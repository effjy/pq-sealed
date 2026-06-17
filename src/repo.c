/* repo.c — PQ-Sealed backup store.
 *
 * A repository is a directory:
 *
 *   <repo>/PQSEALED              marker + format version
 *   <repo>/keyring               hybrid-KEM key-ring (see repocrypto.c)
 *   <repo>/keys/snapshot.pub     ML-DSA-65 public key (armored)
 *   <repo>/keys/snapshot.key     ML-DSA-65 secret key (passphrase-encrypted)
 *   <repo>/objects/<ab>/<hex>    sealed file contents, named by plaintext hash
 *   <repo>/snapshots/<stamp>.manifest{,.sig}
 *
 * Backups are content-addressed: a file becomes an object named by the
 * SHA-256 of its plaintext. If that object already exists — stored by an
 * earlier snapshot, or an identical file elsewhere in this run — it is not
 * re-sealed. That is what makes successive backups incremental and
 * deduplicating: only new or changed content is written.
 *
 * Each snapshot's manifest lists every file and directory with its mode,
 * size, mtime and content hash. The (encrypted) manifest is signed with
 * ML-DSA-65, so a snapshot is tamper-evident: altering the manifest or
 * substituting objects is detected at verify/restore time.
 */
#define _GNU_SOURCE
#include "sealed.h"
#include "pqsign.h"
#include "keyfile_internal.h"

#include <sodium.h>
#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SIG_ALG       "ML-DSA-65"
/* Domain-separation prefix mixed into every signed manifest digest. */
static const char DS_CONTEXT[] = "pq-sealed/v1";

#define MARKER_TEXT   "PQSEALED-REPO v1\n"
#define MANIFEST_HDR  "PQSEALED-MANIFEST v1"

/* Set the caller's error buffer and return -1. */
static int fail(char *err, size_t errlen, const char *fmt, ...) {
    if (err && errlen) {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(err, errlen, fmt, ap);
        va_end(ap);
    }
    return -1;
}

/* Emit a line through the optional log callback. Returns the callback's
 * value (non-zero requests cancellation), or 0 when there is no callback. */
static int logf_cb(sealed_log_cb cb, void *user, const char *fmt, ...) {
    if (!cb) return 0;
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    return cb(line, user);
}

/* ----- small path / fs helpers ----------------------------------------- */

/* snprintf wrapper that reports truncation: returns 0 on success, -1 if the
 * formatted string did not fit (output is always NUL-terminated). Checking
 * the result here keeps every path-building call site explicit about
 * truncation. */
__attribute__((format(printf, 3, 4)))
static int sfmt(char *buf, size_t cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, cap, fmt, ap);
    va_end(ap);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Build "<repo>/<sub>". Repo-relative names are short and fixed, so a
 * truncated result here would be a programming error; clamp defensively. */
static void rp(char *buf, size_t cap, const char *repo, const char *sub) {
    if (sfmt(buf, cap, "%s/%s", repo, sub) != 0 && cap) buf[cap - 1] = '\0';
}

static int file_exists(const char *p) { return access(p, F_OK) == 0; }

static int is_dir(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 && S_ISDIR(st.st_mode);
}

/* mkdir -p. Returns 0 on success (existing directory is fine). */
static int mkdir_p(const char *path, mode_t mode) {
    char tmp[4096];
    size_t len = (size_t)snprintf(tmp, sizeof tmp, "%s", path);
    if (len >= sizeof tmp) return -1;
    if (len && tmp[len - 1] == '/') tmp[--len] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

/* Create every parent directory of a file path. */
static int ensure_parent_dirs(const char *path, mode_t mode) {
    char tmp[4096];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s", path) >= sizeof tmp) return -1;
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return 0;
    *slash = '\0';
    return mkdir_p(tmp, mode);
}

/* Read an entire file without aborting. Returns malloc'd buffer (caller
 * frees) with *out_len set, or NULL on any error. */
static uint8_t *slurp(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

/* ----- growable text buffer (the manifest) ------------------------------ */

typedef struct { char *buf; size_t len, cap; } sb_t;

static int sb_reserve(sb_t *s, size_t extra) {
    if (s->len + extra + 1 <= s->cap) return 0;
    size_t nc = s->cap ? s->cap : 8192;
    while (nc < s->len + extra + 1) nc *= 2;
    char *nb = realloc(s->buf, nc);
    if (!nb) return -1;
    s->buf = nb; s->cap = nc;
    return 0;
}
static int sb_addf(sb_t *s, const char *fmt, ...) {
    char line[8192];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= sizeof line) return -1;
    if (sb_reserve(s, (size_t)n) != 0) return -1;
    memcpy(s->buf + s->len, line, (size_t)n);
    s->len += (size_t)n;
    s->buf[s->len] = '\0';
    return 0;
}

/* ----- repository path accessors ---------------------------------------- */

static void repo_object_path(char *buf, size_t cap, const char *repo,
                             const char *hex) {
    /* hex is 64 chars; bucket by the first two. */
    if (sfmt(buf, cap, "%s/objects/%.2s/%s", repo, hex, hex) != 0 && cap)
        buf[cap - 1] = '\0';
}

/* ----- ML-DSA signing over a file --------------------------------------- */

/* Build the message actually signed: SHA256( ctx || sha256(file) ). */
static void signed_message(const char *path, uint8_t out[32]) {
    uint8_t fdigest[32];
    sha256_file(path, fdigest);
    uint8_t buf[sizeof(DS_CONTEXT) - 1 + 32];
    memcpy(buf, DS_CONTEXT, sizeof(DS_CONTEXT) - 1);
    memcpy(buf + sizeof(DS_CONTEXT) - 1, fdigest, 32);
    sha256(buf, sizeof buf, out);
}

/* Load an armored key with an explicit passphrase (no terminal prompt).
 * Returns 0 on success; -1 on missing/invalid file or wrong passphrase. */
static int load_key(const char *path, const char *pw, pqsign_key *out) {
    memset(out, 0, sizeof *out);
    size_t len;
    uint8_t *raw = slurp(path, &len);
    if (!raw) return -1;

    pqsign_armor a;
    if (!key_armor_parse(raw, len, &a)) { free(raw); return -1; }
    snprintf(out->alg, sizeof out->alg, "%s", a.alg);
    out->is_secret = a.is_secret;

    /* Decrypt first: key_decrypt feeds the embedded public key in as AEAD
     * associated data, so a.pub must still be present here. Only afterwards
     * do we transfer ownership of pub to the loaded key. */
    int ok = key_decrypt(&a, (pw && *pw) ? pw : NULL, &out->key, &out->key_len);
    if (ok) { out->pub = a.pub; out->pub_len = a.pub_len; a.pub = NULL; }

    armor_free(&a);
    secure_wipe(raw, len);
    free(raw);
    if (!ok) { memset(out, 0, sizeof *out); return -1; }
    return 0;
}

/* Sign `file` with the repository secret key, writing a detached blob to
 * `sigpath`. Returns 0 on success. */
static int sign_file(const char *seckey_path, const char *key_pw,
                     const char *file, const char *sigpath,
                     char *err, size_t errlen) {
    pqsign_key sk;
    if (load_key(seckey_path, key_pw, &sk) != 0)
        return fail(err, errlen,
                    "cannot load signing key (wrong passphrase, or corrupt key)");
    if (!sk.is_secret) { key_free(&sk);
        return fail(err, errlen, "backup signing key is not a secret key"); }

    OQS_SIG *sig = OQS_SIG_new(sk.alg);
    int rc = -1;
    if (!sig) { fail(err, errlen, "signature algorithm '%s' unavailable", sk.alg);
                goto out; }
    if (sk.key_len != sig->length_secret_key ||
        !sk.pub || sk.pub_len != sig->length_public_key) {
        fail(err, errlen, "backup signing key is malformed"); goto out; }

    uint8_t msg[32];
    signed_message(file, msg);
    uint8_t *signature = xmalloc(sig->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_sign(sig, signature, &siglen, msg, sizeof msg, sk.key)
        != OQS_SUCCESS) {
        free(signature); fail(err, errlen, "signing the manifest failed"); goto out;
    }
    size_t blob_len = 0;
    uint8_t *blob = sigfile_build(sk.alg, sk.pub, sk.pub_len, signature, siglen,
                                  &blob_len);
    write_file(sigpath, blob, blob_len, 0644);
    free(blob);
    secure_wipe(signature, sig->length_signature);
    free(signature);
    rc = 0;
out:
    if (sig) OQS_SIG_free(sig);
    key_free(&sk);
    return rc;
}

/* Verify the detached signature `sigpath` over `file` with `pk`.
 * Returns 0 if valid, 1 if invalid/missing/mismatched. */
static int verify_file(const pqsign_key *pk, const char *file,
                       const char *sigpath) {
    size_t blob_len;
    uint8_t *blob = slurp(sigpath, &blob_len);
    if (!blob) return 1;
    pqsign_sigfile sf;
    if (!sigfile_parse(blob, blob_len, &sf)) { free(blob); return 1; }
    sf.raw = blob;

    int bad = 1;
    if (strcmp(sf.alg, pk->alg) == 0) {
        uint8_t fpr[32];
        sha256(pk->key, pk->key_len, fpr);
        if (ct_equal(fpr, sf.pub_fpr, 32)) {
            OQS_SIG *sig = OQS_SIG_new(pk->alg);
            if (sig && pk->key_len == sig->length_public_key) {
                uint8_t msg[32];
                signed_message(file, msg);
                if (OQS_SIG_verify(sig, msg, sizeof msg, sf.sig, sf.sig_len,
                                   pk->key) == OQS_SUCCESS)
                    bad = 0;
            }
            if (sig) OQS_SIG_free(sig);
        }
    }
    sigfile_free(&sf);
    return bad;
}

/* ----- directory walk + object store ------------------------------------ */

typedef struct {
    const char *repo;
    const uint8_t *dk;
    char repo_real[4096];   /* canonical repo path, to skip backing it up */
    sb_t *mani;
    sealed_log_cb log;
    void *user;
    uint64_t files, files_new, dirs;
    uint64_t bytes, bytes_new;
    int aborted;            /* set on cancellation or fatal seal error */
    char err[256];
} walk_ctx;

/* Reject manifest-supplied relative paths that could escape the destination
 * (defence in depth: our own manifests are signed, but never trust on input). */
static int rel_is_safe(const char *rel) {
    if (!*rel || rel[0] == '/') return 0;
    for (const char *p = rel; *p; ) {
        if (p[0] == '.' && p[1] == '.' &&
            (p[2] == '/' || p[2] == '\0') && (p == rel || p[-1] == '/'))
            return 0;
        const char *nx = strchr(p, '/');
        p = nx ? nx + 1 : p + strlen(p);
    }
    return 1;
}

static void store_file(walk_ctx *c, const char *abs, const char *rel,
                       const struct stat *st) {
    uint8_t digest[32];
    char hex[65];
    sha256_file(abs, digest);
    to_hex(digest, 32, hex);

    char objpath[4096];
    repo_object_path(objpath, sizeof objpath, c->repo, hex);

    c->files++;
    c->bytes += (uint64_t)st->st_size;
    if (!file_exists(objpath)) {
        if (ensure_parent_dirs(objpath, 0700) != 0 ||
            rc_seal_file(abs, objpath, c->dk) != 0) {
            sfmt(c->err, sizeof c->err, "failed to seal '%s'", rel);
            c->aborted = 1;
            return;
        }
        c->files_new++;
        c->bytes_new += (uint64_t)st->st_size;
        if (logf_cb(c->log, c->user, "  + %s", rel)) c->aborted = 1;
    } else if (logf_cb(c->log, c->user, "  = %s", rel)) {
        c->aborted = 1;
    }

    char *b64rel = b64_encode((const uint8_t *)rel, strlen(rel));
    if (sb_addf(c->mani, "F %s %o %lld %lld %s\n", hex,
                (unsigned)(st->st_mode & 07777),
                (long long)st->st_size, (long long)st->st_mtime, b64rel) != 0)
        c->aborted = 1;
    free(b64rel);
}

static void walk(walk_ctx *c, const char *dir_abs, const char *rel_prefix) {
    DIR *d = opendir(dir_abs);
    if (!d) { warn("cannot open directory '%s': %s", dir_abs, strerror(errno));
              return; }

    struct dirent *e;
    while (!c->aborted && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;

        char abs[4096], rel[4096];
        if ((size_t)snprintf(abs, sizeof abs, "%s/%s", dir_abs, e->d_name)
                >= sizeof abs ||
            (size_t)snprintf(rel, sizeof rel, "%s%s%s", rel_prefix,
                             *rel_prefix ? "/" : "", e->d_name) >= sizeof rel) {
            warn("path too long under '%s', skipping '%s'", dir_abs, e->d_name);
            continue;
        }

        struct stat st;
        if (lstat(abs, &st) != 0) {
            warn("cannot stat '%s': %s", abs, strerror(errno));
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            warn("skipping symlink '%s'", rel);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            char real[4096];
            if (realpath(abs, real) && strcmp(real, c->repo_real) == 0)
                continue;   /* never recurse into the repository itself */
            char *b64rel = b64_encode((const uint8_t *)rel, strlen(rel));
            if (sb_addf(c->mani, "D %o %s\n",
                        (unsigned)(st.st_mode & 07777), b64rel) != 0)
                c->aborted = 1;
            free(b64rel);
            c->dirs++;
            walk(c, abs, rel);
        } else if (S_ISREG(st.st_mode)) {
            store_file(c, abs, rel, &st);
        } else {
            warn("skipping special file '%s'", rel);
        }
    }
    closedir(d);
}

/* ----- commands --------------------------------------------------------- */

static int require_repo(const char *repo, char *err, size_t errlen) {
    char marker[4096];
    rp(marker, sizeof marker, repo, "PQSEALED");
    if (!file_exists(marker))
        return fail(err, errlen,
            "'%s' is not a PQ-Sealed backup directory (initialise it first)", repo);
    return 0;
}

int sealed_init(const char *repo, const char *repo_pw, const char *key_pw,
                char *err, size_t errlen) {
    char marker[4096], kr[4096], pub[4096], sec[4096], sub[4096];
    rp(marker, sizeof marker, repo, "PQSEALED");
    if (file_exists(marker))
        return fail(err, errlen, "'%s' is already a PQ-Sealed backup directory", repo);
    if (!repo_pw || !*repo_pw)
        return fail(err, errlen, "a backup password is required");

    if (mkdir_p(repo, 0700) != 0)
        return fail(err, errlen, "cannot create '%s': %s", repo, strerror(errno));
    rp(sub, sizeof sub, repo, "objects");   mkdir_p(sub, 0700);
    rp(sub, sizeof sub, repo, "snapshots"); mkdir_p(sub, 0700);
    rp(sub, sizeof sub, repo, "keys");      mkdir_p(sub, 0700);

    /* Repository encryption password -> hybrid KEM key-ring. */
    uint8_t dk[RC_DK_LEN];
    sodium_mlock(dk, sizeof dk);
    rp(kr, sizeof kr, repo, "keyring");
    int rc = rc_keyring_create(kr, repo_pw, dk);
    sodium_munlock(dk, sizeof dk);
    if (rc != 0) return fail(err, errlen, "failed to create the backup key-ring");

    /* ML-DSA-65 snapshot-signing keypair. */
    OQS_SIG *sig = OQS_SIG_new(SIG_ALG);
    if (!sig) return fail(err, errlen,
                          "signature algorithm '%s' unavailable in liboqs", SIG_ALG);
    uint8_t *pk = xmalloc(sig->length_public_key);
    uint8_t *sk = secure_alloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        secure_free(sk, sig->length_secret_key); free(pk); OQS_SIG_free(sig);
        return fail(err, errlen, "signing key generation failed");
    }

    rp(pub, sizeof pub, repo, "keys/snapshot.pub");
    rp(sec, sizeof sec, repo, "keys/snapshot.key");
    key_write_public(pub, SIG_ALG, pk, sig->length_public_key);
    key_write_secret(sec, SIG_ALG, sk, sig->length_secret_key,
                     pk, sig->length_public_key, (key_pw && *key_pw) ? key_pw : NULL);

    write_file(marker, (const uint8_t *)MARKER_TEXT, strlen(MARKER_TEXT), 0644);

    secure_free(sk, sig->length_secret_key);
    free(pk);
    OQS_SIG_free(sig);
    return 0;
}

int sealed_backup(const char *repo, const char *source,
                  const char *repo_pw, const char *key_pw,
                  sealed_log_cb log, void *user, char *err, size_t errlen) {
    if (require_repo(repo, err, errlen) != 0) return -1;

    char src_real[4096];
    if (!realpath(source, src_real))
        return fail(err, errlen, "cannot resolve source '%s': %s",
                    source, strerror(errno));
    if (!is_dir(src_real))
        return fail(err, errlen, "source '%s' is not a directory", src_real);

    uint8_t dk[RC_DK_LEN];
    sodium_mlock(dk, sizeof dk);
    char kr[4096];
    rp(kr, sizeof kr, repo, "keyring");
    if (rc_keyring_open(kr, repo_pw ? repo_pw : "", dk) != 0) {
        sodium_munlock(dk, sizeof dk);
        return fail(err, errlen, "wrong backup password, or key-ring corrupted");
    }

    sb_t mani = {0};
    char *b64src = b64_encode((const uint8_t *)src_real, strlen(src_real));
    int hdrok = sb_addf(&mani, "%s\n", MANIFEST_HDR) == 0 &&
                sb_addf(&mani, "source %s\n", b64src) == 0 &&
                sb_addf(&mani, "created %lld\n", (long long)time(NULL)) == 0;
    free(b64src);
    if (!hdrok) { sodium_munlock(dk, sizeof dk); free(mani.buf);
        return fail(err, errlen, "out of memory"); }

    walk_ctx c = {0};
    c.repo = repo; c.dk = dk; c.mani = &mani; c.log = log; c.user = user;
    if (!realpath(repo, c.repo_real))
        sfmt(c.repo_real, sizeof c.repo_real, "%s", repo);

    logf_cb(log, user, "Backing up %s", src_real);
    walk(&c, src_real, "");
    if (c.aborted) {
        sodium_munlock(dk, sizeof dk); secure_wipe(mani.buf, mani.len); free(mani.buf);
        return fail(err, errlen, "%s", c.err[0] ? c.err : "backup cancelled");
    }

    /* Unique, sortable snapshot name. */
    char stamp[64];
    time_t now = time(NULL);
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tmv);

    char mdir[4096], spath[4096];
    int trunc = 0;
    rp(mdir, sizeof mdir, repo, "snapshots");
    for (int n = 0; ; n++) {
        trunc = (n == 0)
            ? sfmt(spath, sizeof spath, "%s/%s.manifest", mdir, stamp)
            : sfmt(spath, sizeof spath, "%s/%s-%d.manifest", mdir, stamp, n);
        if (trunc || !file_exists(spath)) break;
    }
    if (trunc) {
        sodium_munlock(dk, sizeof dk); secure_wipe(mani.buf, mani.len); free(mani.buf);
        return fail(err, errlen, "snapshot path is too long");
    }

    int wr = rc_seal_buf((const uint8_t *)mani.buf, mani.len, spath, dk);
    sodium_munlock(dk, sizeof dk);
    secure_wipe(mani.buf, mani.len);
    free(mani.buf);
    if (wr != 0) return fail(err, errlen, "failed to write the snapshot manifest");

    /* Sign the (encrypted) manifest for tamper-evidence. */
    char sigpath[4096], seckey[4096];
    if (sfmt(sigpath, sizeof sigpath, "%s.sig", spath) != 0)
        return fail(err, errlen, "snapshot path is too long");
    rp(seckey, sizeof seckey, repo, "keys/snapshot.key");
    if (sign_file(seckey, key_pw, spath, sigpath, err, errlen) != 0) {
        remove(spath);   /* don't leave an unsigned snapshot behind */
        return -1;
    }

    const char *base = strrchr(spath, '/');
    base = base ? base + 1 : spath;
    logf_cb(log, user, "");
    logf_cb(log, user, "Snapshot %s", base);
    logf_cb(log, user, "  files: %llu (%llu new)   dirs: %llu",
            (unsigned long long)c.files, (unsigned long long)c.files_new,
            (unsigned long long)c.dirs);
    logf_cb(log, user, "  new data this snapshot: %llu of %llu bytes",
            (unsigned long long)c.bytes_new, (unsigned long long)c.bytes);
    logf_cb(log, user, "  manifest signed with %s", SIG_ALG);
    return 0;
}

/* Compare for qsort over char* names. */
static int cmp_str(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Collect snapshot manifest base names (sorted). Caller frees each + array.
 * Returns NULL with *out_n==0 if the directory cannot be read. */
static char **list_snapshots(const char *repo, size_t *out_n) {
    *out_n = 0;
    char dirp[4096];
    rp(dirp, sizeof dirp, repo, "snapshots");
    DIR *d = opendir(dirp);
    if (!d) return NULL;

    char **names = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 9 || strcmp(e->d_name + len - 9, ".manifest") != 0)
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            char **nn = realloc(names, cap * sizeof *names);
            if (!nn) break;
            names = nn;
        }
        names[n++] = strdup(e->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof *names, cmp_str);
    *out_n = n;
    return names;
}

int sealed_list(const char *repo, sealed_log_cb log, void *user,
                char *err, size_t errlen) {
    if (require_repo(repo, err, errlen) != 0) return -1;

    char pubpath[4096];
    rp(pubpath, sizeof pubpath, repo, "keys/snapshot.pub");
    pqsign_key pk = {0};
    int have_pub = (load_key(pubpath, NULL, &pk) == 0);

    size_t n;
    char **names = list_snapshots(repo, &n);
    if (n == 0) logf_cb(log, user, "No snapshots in %s", repo);
    else logf_cb(log, user, "%-28s %-10s %s", "SNAPSHOT", "SIZE", "SIGNATURE");

    for (size_t i = 0; i < n; i++) {
        char mpath[4096], sigpath[4096];
        if (sfmt(mpath, sizeof mpath, "%s/snapshots/%s", repo, names[i]) != 0 ||
            sfmt(sigpath, sizeof sigpath, "%s.sig", mpath) != 0) {
            logf_cb(log, user, "%-28s (path too long)", names[i]);
            free(names[i]);
            continue;
        }
        struct stat st;
        long long sz = (stat(mpath, &st) == 0) ? (long long)st.st_size : -1;
        const char *status = !have_pub ? "?"
            : (verify_file(&pk, mpath, sigpath) == 0 ? "OK" : "BAD/UNSIGNED");
        logf_cb(log, user, "%-28s %-10lld %s", names[i], sz, status);
        free(names[i]);
    }
    free(names);
    if (have_pub) key_free(&pk);
    return 0;
}

int sealed_verify(const char *repo, int *out_failures,
                  sealed_log_cb log, void *user, char *err, size_t errlen) {
    if (require_repo(repo, err, errlen) != 0) return -1;

    char pubpath[4096];
    rp(pubpath, sizeof pubpath, repo, "keys/snapshot.pub");
    pqsign_key pk = {0};
    if (load_key(pubpath, NULL, &pk) != 0)
        return fail(err, errlen, "backup directory has no usable public key");

    size_t n;
    char **names = list_snapshots(repo, &n);
    int failures = 0;
    for (size_t i = 0; i < n; i++) {
        char mpath[4096], sigpath[4096];
        int bad;
        if (sfmt(mpath, sizeof mpath, "%s/snapshots/%s", repo, names[i]) != 0 ||
            sfmt(sigpath, sizeof sigpath, "%s.sig", mpath) != 0)
            bad = 1;   /* unreachable name counts as a failure */
        else
            bad = verify_file(&pk, mpath, sigpath);
        logf_cb(log, user, "%-28s %s", names[i], bad ? "FAILED" : "OK");
        if (bad) failures++;
        free(names[i]);
    }
    free(names);
    key_free(&pk);

    if (n == 0) logf_cb(log, user, "No snapshots to verify.");
    else logf_cb(log, user, "%zu snapshot(s), %d failure(s)", n, failures);
    if (out_failures) *out_failures = failures;
    return 0;
}

/* Apply one manifest line during restore. Returns 0 on success, -1 on a
 * fatal error (message written to err). */
static int restore_line(const char *repo, const uint8_t *dk, const char *dest,
                        char *line, uint64_t *files, uint64_t *dirs,
                        sealed_log_cb log, void *user, char *err, size_t errlen) {
    char *save = NULL;
    char *kind = strtok_r(line, " ", &save);
    if (!kind) return 0;

    if (strcmp(kind, "D") == 0) {
        char *mode = strtok_r(NULL, " ", &save);
        char *b64  = strtok_r(NULL, " ", &save);
        if (!mode || !b64) return fail(err, errlen, "malformed manifest (D)");
        size_t rl; uint8_t *rel = b64_decode(b64, strlen(b64), &rl);
        if (!rel) return fail(err, errlen, "malformed manifest path");
        char rels[4096];
        if (rl >= sizeof rels) { free(rel); return fail(err, errlen, "path too long"); }
        memcpy(rels, rel, rl); rels[rl] = '\0'; free(rel);
        if (!rel_is_safe(rels)) return fail(err, errlen, "unsafe path: %s", rels);

        char target[4096];
        if (sfmt(target, sizeof target, "%s/%s", dest, rels) != 0)
            return fail(err, errlen, "restore path too long");
        if (mkdir_p(target, 0700) != 0)
            return fail(err, errlen, "cannot create directory '%s'", target);
        chmod(target, (mode_t)strtoul(mode, NULL, 8));
        (*dirs)++;
    } else if (strcmp(kind, "F") == 0) {
        char *hex   = strtok_r(NULL, " ", &save);
        char *mode  = strtok_r(NULL, " ", &save);
        char *size  = strtok_r(NULL, " ", &save);
        char *mtime = strtok_r(NULL, " ", &save);
        char *b64   = strtok_r(NULL, " ", &save);
        (void)size;
        if (!hex || !mode || !size || !mtime || !b64 || strlen(hex) != 64)
            return fail(err, errlen, "malformed manifest (F)");
        size_t rl; uint8_t *rel = b64_decode(b64, strlen(b64), &rl);
        if (!rel) return fail(err, errlen, "malformed manifest path");
        char rels[4096];
        if (rl >= sizeof rels) { free(rel); return fail(err, errlen, "path too long"); }
        memcpy(rels, rel, rl); rels[rl] = '\0'; free(rel);
        if (!rel_is_safe(rels)) return fail(err, errlen, "unsafe path: %s", rels);

        char target[4096], objpath[4096];
        if (sfmt(target, sizeof target, "%s/%s", dest, rels) != 0)
            return fail(err, errlen, "restore path too long");
        repo_object_path(objpath, sizeof objpath, repo, hex);
        if (!file_exists(objpath))
            return fail(err, errlen, "missing object for '%s'", rels);
        if (ensure_parent_dirs(target, 0700) != 0)
            return fail(err, errlen, "cannot create parents of '%s'", target);
        if (rc_open_file(objpath, target, dk) != 0)
            return fail(err, errlen, "failed to restore '%s' (corrupt/wrong password)", rels);

        uint8_t digest[32]; char got[65];
        sha256_file(target, digest);
        to_hex(digest, 32, got);
        if (strcmp(got, hex) != 0)
            return fail(err, errlen, "content hash mismatch for '%s' (tampered)", rels);

        chmod(target, (mode_t)strtoul(mode, NULL, 8));
        struct timespec ts[2];
        ts[0].tv_sec = ts[1].tv_sec = (time_t)strtoll(mtime, NULL, 10);
        ts[0].tv_nsec = ts[1].tv_nsec = 0;
        utimensat(AT_FDCWD, target, ts, 0);
        if (logf_cb(log, user, "  %s", rels)) return fail(err, errlen, "cancelled");
        (*files)++;
    }
    /* Unknown line kinds are ignored for forward compatibility. */
    return 0;
}

int sealed_restore(const char *repo, const char *snapshot, const char *dest,
                   const char *repo_pw, sealed_log_cb log, void *user,
                   char *err, size_t errlen) {
    if (require_repo(repo, err, errlen) != 0) return -1;

    /* Resolve the snapshot manifest path. */
    char mpath[4096];
    int trunc;
    if (!snapshot || !*snapshot || strcmp(snapshot, "latest") == 0) {
        size_t n;
        char **names = list_snapshots(repo, &n);
        if (n == 0) { free(names); return fail(err, errlen, "no snapshots to restore"); }
        trunc = sfmt(mpath, sizeof mpath, "%s/snapshots/%s", repo, names[n - 1]);
        for (size_t i = 0; i < n; i++) free(names[i]);
        free(names);
    } else {
        const char *suffix = (strlen(snapshot) >= 9 &&
            strcmp(snapshot + strlen(snapshot) - 9, ".manifest") == 0)
            ? "" : ".manifest";
        trunc = sfmt(mpath, sizeof mpath, "%s/snapshots/%s%s", repo, snapshot, suffix);
    }
    if (trunc) return fail(err, errlen, "snapshot path is too long");
    if (!file_exists(mpath))
        return fail(err, errlen, "snapshot '%s' not found", snapshot ? snapshot : "latest");

    /* Verify the manifest signature before trusting its contents. */
    char pubpath[4096], sigpath[4096];
    rp(pubpath, sizeof pubpath, repo, "keys/snapshot.pub");
    if (sfmt(sigpath, sizeof sigpath, "%s.sig", mpath) != 0)
        return fail(err, errlen, "snapshot path is too long");
    pqsign_key pk = {0};
    if (load_key(pubpath, NULL, &pk) == 0) {
        int bad = verify_file(&pk, mpath, sigpath);
        key_free(&pk);
        if (bad) return fail(err, errlen,
            "snapshot signature is INVALID — refusing to restore");
    } else {
        logf_cb(log, user, "warning: no public key; skipping signature check");
    }

    uint8_t dk[RC_DK_LEN];
    sodium_mlock(dk, sizeof dk);
    char kr[4096];
    rp(kr, sizeof kr, repo, "keyring");
    if (rc_keyring_open(kr, repo_pw ? repo_pw : "", dk) != 0) {
        sodium_munlock(dk, sizeof dk);
        return fail(err, errlen, "wrong backup password, or key-ring corrupted");
    }

    size_t mlen;
    uint8_t *mbuf = rc_open_buf(mpath, dk, &mlen);
    if (!mbuf) { sodium_munlock(dk, sizeof dk);
        return fail(err, errlen, "failed to decrypt the manifest (wrong password?)"); }

    if (mkdir_p(dest, 0700) != 0) {
        sodium_munlock(dk, sizeof dk); free(mbuf);
        return fail(err, errlen, "cannot create destination '%s': %s",
                    dest, strerror(errno));
    }

    char *save = NULL;
    char *line = strtok_r((char *)mbuf, "\n", &save);
    if (!line || strcmp(line, MANIFEST_HDR) != 0) {
        sodium_munlock(dk, sizeof dk); free(mbuf);
        return fail(err, errlen, "not a PQ-Sealed manifest");
    }

    const char *base = strrchr(mpath, '/');
    logf_cb(log, user, "Restoring %s -> %s", base ? base + 1 : mpath, dest);

    uint64_t files = 0, dirs = 0;
    int rc = 0;
    while ((line = strtok_r(NULL, "\n", &save)) != NULL) {
        if (strncmp(line, "source ", 7) == 0 ||
            strncmp(line, "created ", 8) == 0) continue;
        if ((rc = restore_line(repo, dk, dest, line, &files, &dirs,
                               log, user, err, errlen)) != 0)
            break;
    }

    sodium_munlock(dk, sizeof dk);
    free(mbuf);
    if (rc != 0) return -1;
    logf_cb(log, user, "Restored %llu files, %llu directories",
            (unsigned long long)files, (unsigned long long)dirs);
    return 0;
}
