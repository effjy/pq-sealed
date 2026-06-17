/* repocrypto.c — PQ-Sealed repository key-ring and object sealing.
 *
 * Key-ring file layout (all integers little-endian):
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------------------
 *   0       16    magic  "PQSEALED-KRING\0\0"
 *   16      1     format_version (1)
 *   17      4     argon2 t_cost
 *   21      4     argon2 m_cost (KiB)
 *   25      4     argon2 parallelism
 *   29      16    salt
 *   45      24    wrap nonce
 *   69      WS    wrapped hybrid secret key  (HK_SK_LEN + 16-byte tag)
 *   ...     CT    KEM ciphertext             (HK_KEM_CT_LEN)
 *
 * A single Argon2id pass over the password yields the master key. That key
 * unwraps the Kyber-1024 + X448 hybrid secret key (XChaCha20-Poly1305), which
 * decapsulates the stored KEM ciphertext back to the 32-byte data key. The
 * data key seals every object and manifest, so the costly KDF and the
 * post-quantum KEM run once per repository open rather than per file. This
 * mirrors the per-file hybrid design of Ciphers, lifted to repository scope.
 */
#define _GNU_SOURCE
#include "sealed.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <argon2.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#define KR_MAGIC      "PQSEALED-KRING\0\0"
#define KR_MAGIC_LEN  16
#define KR_VERSION    1
#define KR_SALT_LEN   16

/* Argon2id: 1 GiB / t=3 / 4 lanes — the Ciphers "medium" preset, run once. */
#define KR_T_COST     3u
#define KR_M_COST     (1u * 1024u * 1024u)
#define KR_PARALLEL   4u

/* Sanity ceilings for parameters read back from an (untrusted) ring header. */
#define MAX_T_COST    16u
#define MAX_M_COST    (4u * 1024u * 1024u)
#define MAX_PARALLEL  16u

#define MASTERKEY_LEN   crypto_aead_xchacha20poly1305_ietf_KEYBYTES   /* 32 */
#define WRAP_NONCE_LEN  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  /* 24 */
#define WRAP_ABYTES     crypto_aead_xchacha20poly1305_ietf_ABYTES     /* 16 */
#define WRAPPED_SK_LEN  (HK_SK_LEN + WRAP_ABYTES)

#define WRAP_AD     ((const unsigned char *)"PQSEALED-KRING-WRAP")
#define WRAP_AD_LEN 19

#define KR_HDR_LEN  (KR_MAGIC_LEN + 1 + 12 + KR_SALT_LEN)   /* 45 */
#define KR_BODY_LEN (WRAP_NONCE_LEN + WRAPPED_SK_LEN + HK_KEM_CT_LEN)
#define KR_FILE_LEN (KR_HDR_LEN + KR_BODY_LEN)

#define SEAL_CHUNK  65536u

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int derive_master(const char *password, const uint8_t *salt,
                         uint32_t t, uint32_t m, uint32_t p, uint8_t *key) {
    int rc = argon2id_hash_raw(t, m, p, password, strlen(password),
                               salt, KR_SALT_LEN, key, MASTERKEY_LEN);
    return rc == ARGON2_OK ? 0 : -1;
}

/* Best-effort durable write of a fully built buffer to `path`: stage to a
 * sibling temp, fsync, rename, fsync dir. Returns 0 on success. */
static int write_atomic(const char *path, const uint8_t *buf, size_t len) {
    char tmp[4096];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", path) >= sizeof tmp) return -1;
    FILE *f = fopen(tmp, "wb");
    if (!f) return -1;
    int ok = (fwrite(buf, 1, len, f) == len) && fflush(f) == 0 &&
             fsync(fileno(f)) == 0;
    if (fclose(f) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) { remove(tmp); return -1; }
    return 0;
}

int rc_keyring_create(const char *path, const char *password,
                      uint8_t dk[RC_DK_LEN]) {
    uint8_t master[MASTERKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];          /* kyber_sk || x448_sk */
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t file[KR_FILE_LEN];
    int ret = -1;

    sodium_mlock(master, sizeof master);
    sodium_mlock(hybrid_sk, sizeof hybrid_sk);

    uint8_t salt[KR_SALT_LEN];
    randombytes_buf(salt, sizeof salt);
    if (derive_master(password, salt, KR_T_COST, KR_M_COST, KR_PARALLEL,
                      master) != 0) goto out;
    if (hk_generate_keypair(kyber_pk, hybrid_sk, x448_pk,
                            hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;

    /* Header. */
    uint8_t *p = file;
    memcpy(p, KR_MAGIC, KR_MAGIC_LEN);     p += KR_MAGIC_LEN;
    *p++ = KR_VERSION;
    put_u32(p, KR_T_COST);    p += 4;
    put_u32(p, KR_M_COST);    p += 4;
    put_u32(p, KR_PARALLEL);  p += 4;
    memcpy(p, salt, KR_SALT_LEN);          p += KR_SALT_LEN;

    /* Body: wrap nonce || wrapped secret key || KEM ciphertext. */
    uint8_t *wrap_nonce = p;               p += WRAP_NONCE_LEN;
    uint8_t *wrapped_sk = p;               p += WRAPPED_SK_LEN;
    uint8_t *kem_ct     = p;               /* HK_KEM_CT_LEN */

    randombytes_buf(wrap_nonce, WRAP_NONCE_LEN);
    crypto_aead_xchacha20poly1305_ietf_encrypt(wrapped_sk, NULL,
        hybrid_sk, HK_SK_LEN, WRAP_AD, WRAP_AD_LEN, NULL, wrap_nonce, master);
    if (hk_encapsulate(dk, kem_ct, kyber_pk, x448_pk) != 0) goto out;

    if (write_atomic(path, file, KR_FILE_LEN) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof master);
    sodium_munlock(hybrid_sk, sizeof hybrid_sk);
    return ret;
}

int rc_keyring_open(const char *path, const char *password,
                    uint8_t dk[RC_DK_LEN]) {
    uint8_t file[KR_FILE_LEN];
    uint8_t master[MASTERKEY_LEN];
    uint8_t hybrid_sk[HK_SK_LEN];
    int ret = -1;

    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t got = fread(file, 1, sizeof file, f);
    int extra = fgetc(f) != EOF;
    fclose(f);
    if (got != KR_FILE_LEN || extra) return -1;
    if (memcmp(file, KR_MAGIC, KR_MAGIC_LEN) != 0) return -1;
    if (file[KR_MAGIC_LEN] != KR_VERSION) return -1;

    const uint8_t *hp = file + KR_MAGIC_LEN + 1;
    uint32_t t = get_u32(hp), m = get_u32(hp + 4), pl = get_u32(hp + 8);
    if (t == 0 || t > MAX_T_COST || pl == 0 || pl > MAX_PARALLEL ||
        m < 8u * pl || m > MAX_M_COST) return -1;
    const uint8_t *salt = hp + 12;

    const uint8_t *body = file + KR_HDR_LEN;
    const uint8_t *wrap_nonce = body;
    const uint8_t *wrapped_sk = wrap_nonce + WRAP_NONCE_LEN;
    const uint8_t *kem_ct     = wrapped_sk + WRAPPED_SK_LEN;

    sodium_mlock(master, sizeof master);
    sodium_mlock(hybrid_sk, sizeof hybrid_sk);

    if (derive_master(password, salt, t, m, pl, master) != 0) goto out;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(hybrid_sk, NULL, NULL,
            wrapped_sk, WRAPPED_SK_LEN, WRAP_AD, WRAP_AD_LEN,
            wrap_nonce, master) != 0)
        goto out;   /* wrong password or tampered ring */
    if (hk_decapsulate(dk, kem_ct, hybrid_sk,
                       hybrid_sk + HK_KYBER_SECRETKEYBYTES) != 0) goto out;
    ret = 0;
out:
    sodium_munlock(master, sizeof master);
    sodium_munlock(hybrid_sk, sizeof hybrid_sk);
    return ret;
}

/* ----- object sealing (secretstream) ----------------------------------- */

/* Seal an open stream `in` to the open stream `out`. Frames are
 * [u32 clen][clen bytes]; the secretstream tags carry ordering and a FINAL
 * marker so truncation is detected on open. Returns 0 on success. */
static int seal_stream(FILE *in, FILE *out, const uint8_t dk[RC_DK_LEN]) {
    crypto_secretstream_xchacha20poly1305_state st;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    uint8_t plain[SEAL_CHUNK];
    uint8_t ct[SEAL_CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES];
    uint8_t lenbuf[4];
    int ret = -1;

    sodium_mlock(plain, sizeof plain);
    if (crypto_secretstream_xchacha20poly1305_init_push(&st, header, dk) != 0)
        goto out;
    if (fwrite(header, 1, sizeof header, out) != sizeof header) goto out;

    for (;;) {
        size_t n = fread(plain, 1, SEAL_CHUNK, in);
        if (n == 0 && ferror(in)) goto out;
        int final = feof(in) ? 1 : 0;
        unsigned char tag = final
            ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        unsigned long long clen = 0;
        if (crypto_secretstream_xchacha20poly1305_push(&st, ct, &clen,
                plain, n, NULL, 0, tag) != 0) goto out;
        put_u32(lenbuf, (uint32_t)clen);
        if (fwrite(lenbuf, 1, 4, out) != 4 ||
            fwrite(ct, 1, (size_t)clen, out) != (size_t)clen) goto out;
        if (final) break;
    }
    ret = 0;
out:
    sodium_munlock(plain, sizeof plain);
    return ret;
}

/* Open a sealed stream `in`, writing plaintext to `out`. Returns 0 on
 * success, -1 on any failure including a missing FINAL frame (truncation). */
static int open_stream(FILE *in, FILE *out, const uint8_t dk[RC_DK_LEN]) {
    crypto_secretstream_xchacha20poly1305_state st;
    uint8_t header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    uint8_t ct[SEAL_CHUNK + crypto_secretstream_xchacha20poly1305_ABYTES];
    uint8_t plain[SEAL_CHUNK];
    uint8_t lenbuf[4];
    int ret = -1, saw_final = 0;

    sodium_mlock(plain, sizeof plain);
    if (fread(header, 1, sizeof header, in) != sizeof header) goto out;
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, dk) != 0)
        goto out;

    for (;;) {
        size_t r = fread(lenbuf, 1, 4, in);
        if (r == 0 && feof(in)) break;
        if (r != 4) goto out;
        uint32_t clen = get_u32(lenbuf);
        if (clen < crypto_secretstream_xchacha20poly1305_ABYTES ||
            clen > sizeof ct) goto out;
        if (fread(ct, 1, clen, in) != clen) goto out;

        unsigned long long mlen = 0;
        unsigned char tag = 0;
        if (crypto_secretstream_xchacha20poly1305_pull(&st, plain, &mlen, &tag,
                ct, clen, NULL, 0) != 0) goto out;   /* corrupt / wrong key */
        if (mlen && fwrite(plain, 1, (size_t)mlen, out) != (size_t)mlen) goto out;
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            saw_final = 1;
            break;
        }
    }
    ret = saw_final ? 0 : -1;
out:
    sodium_munlock(plain, sizeof plain);
    return ret;
}

int rc_seal_file(const char *in_path, const char *out_path,
                 const uint8_t dk[RC_DK_LEN]) {
    char tmp[4096];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", out_path) >= sizeof tmp)
        return -1;
    FILE *in = fopen(in_path, "rb");
    if (!in) return -1;
    FILE *out = fopen(tmp, "wb");
    if (!out) { fclose(in); return -1; }

    int rc = seal_stream(in, out, dk);
    fclose(in);
    if (rc == 0 && (fflush(out) != 0 || fsync(fileno(out)) != 0)) rc = -1;
    fclose(out);
    if (rc == 0 && rename(tmp, out_path) != 0) rc = -1;
    if (rc != 0) remove(tmp);
    return rc;
}

int rc_open_file(const char *in_path, const char *out_path,
                 const uint8_t dk[RC_DK_LEN]) {
    char tmp[4096];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", out_path) >= sizeof tmp)
        return -1;
    FILE *in = fopen(in_path, "rb");
    if (!in) return -1;
    FILE *out = fopen(tmp, "wb");
    if (!out) { fclose(in); return -1; }

    int rc = open_stream(in, out, dk);
    fclose(in);
    if (rc == 0 && (fflush(out) != 0 || fsync(fileno(out)) != 0)) rc = -1;
    fclose(out);
    if (rc == 0 && rename(tmp, out_path) != 0) rc = -1;
    if (rc != 0) remove(tmp);
    return rc;
}

int rc_seal_buf(const uint8_t *buf, size_t len, const char *out_path,
                const uint8_t dk[RC_DK_LEN]) {
    char tmp[4096];
    if ((size_t)snprintf(tmp, sizeof tmp, "%s.tmp", out_path) >= sizeof tmp)
        return -1;
    FILE *mem = fmemopen((void *)buf, len, "rb");
    if (!mem) return -1;
    FILE *out = fopen(tmp, "wb");
    if (!out) { fclose(mem); return -1; }

    int rc = seal_stream(mem, out, dk);
    fclose(mem);
    if (rc == 0 && (fflush(out) != 0 || fsync(fileno(out)) != 0)) rc = -1;
    fclose(out);
    if (rc == 0 && rename(tmp, out_path) != 0) rc = -1;
    if (rc != 0) remove(tmp);
    return rc;
}

uint8_t *rc_open_buf(const char *in_path, const uint8_t dk[RC_DK_LEN],
                     size_t *out_len) {
    FILE *in = fopen(in_path, "rb");
    if (!in) return NULL;
    char *mem = NULL;
    size_t memlen = 0;
    FILE *out = open_memstream(&mem, &memlen);
    if (!out) { fclose(in); return NULL; }

    int rc = open_stream(in, out, dk);
    fclose(in);
    if (fclose(out) != 0) rc = -1;
    if (rc != 0) { free(mem); return NULL; }

    /* NUL-terminate for text parsing; open_memstream already keeps a byte
     * past memlen, but make the terminator explicit in a sized copy. */
    uint8_t *buf = malloc(memlen + 1);
    if (!buf) { free(mem); return NULL; }
    memcpy(buf, mem, memlen);
    buf[memlen] = '\0';
    free(mem);
    *out_len = memlen;
    return buf;
}
