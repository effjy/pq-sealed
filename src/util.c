/* util.c — fatal errors, secure memory, encodings, file I/O.
 * Symmetric primitives (SHA-256, RNG) come from OpenSSL. */
#define _GNU_SOURCE
#include "pqsign.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <libgen.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

_Noreturn void die(const char *fmt, ...)
{
    va_list ap;
    fputs("pq-sealed: error: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

void warn(const char *fmt, ...)
{
    va_list ap;
    fputs("pq-sealed: warning: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

void secure_wipe(void *p, size_t n)
{
    if (p)
        OPENSSL_cleanse(p, n);
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        die("out of memory (%zu bytes)", n);
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        die("out of memory");
    return p;
}

void *secure_alloc(size_t n)
{
    static bool warned = false;
    size_t len = n ? n : 1;
    void *p = xmalloc(len);   /* never returns NULL */
    /* Keep secret material out of swap. A low RLIMIT_MEMLOCK is not fatal —
     * we still wipe — but the user should know the guarantee is weaker.
     *
     * GCC >= 12 at -O2 emits a spurious -Wmaybe-uninitialized for `p` here:
     * it fails to propagate xmalloc's noreturn-on-failure across the inline
     * (clang, -O1, and -fno-inline are all clean). Suppress only that. */
#if defined(__GNUC__) && !defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
    if (mlock(p, len) != 0 && !warned) {
        warn("could not mlock secret memory (%s); secrets may reach swap",
             strerror(errno));
        warned = true;
    }
#if defined(__GNUC__) && !defined(__clang__)
#  pragma GCC diagnostic pop
#endif
    return p;
}

void secure_free(void *p, size_t n)
{
    if (!p)
        return;
    OPENSSL_cleanse(p, n);
    munlock(p, n ? n : 1);   /* harmless if the earlier mlock failed */
    free(p);
}

void random_bytes(uint8_t *buf, size_t n)
{
    if (RAND_bytes(buf, (int)n) != 1)
        die("CSPRNG failure");
}

bool ct_equal(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n) == 0;
}

uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open '%s': %s", path, strerror(errno));
    if (fseek(f, 0, SEEK_END) != 0)
        die("cannot seek '%s'", path);
    long sz = ftell(f);
    if (sz < 0)
        die("cannot size '%s'", path);
    rewind(f);

    uint8_t *buf = xmalloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, f);
    if (got != (size_t)sz)
        die("short read on '%s'", path);
    buf[sz] = '\0';
    fclose(f);
    *out_len = (size_t)sz;
    return buf;
}

void write_file(const char *path, const uint8_t *buf, size_t len, int mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
        die("cannot create '%s': %s", path, strerror(errno));
    /* Tighten perms even if the file pre-existed with a looser umask. */
    if (fchmod(fd, mode) != 0)
        warn("could not set mode on '%s'", path);

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            die("write to '%s' failed: %s", path, strerror(errno));
        }
        off += (size_t)w;
    }
    if (close(fd) != 0)
        die("close '%s' failed: %s", path, strerror(errno));
}

void write_file_atomic(const char *path, const uint8_t *buf, size_t len,
                       int mode)
{
    /* Stage in the same directory so the final rename(2) is atomic (rename
     * across filesystems is not). Template: "<path>.tmpXXXXXX". */
    char tmp[4096];
    int n = snprintf(tmp, sizeof tmp, "%s.tmpXXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof tmp)
        die("path too long: '%s'", path);

    int fd = mkstemp(tmp);
    if (fd < 0)
        die("cannot create temp file for '%s': %s", path, strerror(errno));

    /* mkstemp creates 0600; widen/narrow to the caller's requested mode. */
    if (fchmod(fd, mode) != 0) {
        int e = errno;
        unlink(tmp);
        close(fd);
        die("could not set mode on temp for '%s': %s", path, strerror(e));
    }

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            int e = errno;
            unlink(tmp);
            close(fd);
            die("write to temp for '%s' failed: %s", path, strerror(e));
        }
        off += (size_t)w;
    }

    if (fsync(fd) != 0) {
        int e = errno;
        unlink(tmp);
        close(fd);
        die("fsync temp for '%s' failed: %s", path, strerror(e));
    }
    if (close(fd) != 0) {
        int e = errno;
        unlink(tmp);
        die("close temp for '%s' failed: %s", path, strerror(e));
    }

    if (rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        die("rename to '%s' failed: %s", path, strerror(e));
    }

    /* fsync the directory so the rename itself is durable. Best-effort. */
    char dirbuf[4096];
    snprintf(dirbuf, sizeof dirbuf, "%s", path);
    int dfd = open(dirname(dirbuf), O_RDONLY | O_DIRECTORY);
    if (dfd >= 0) {
        if (fsync(dfd) != 0)
            warn("could not fsync directory of '%s'", path);
        close(dfd);
    }
}

void sha256(const uint8_t *buf, size_t len, uint8_t out[32])
{
    unsigned int olen = 32;
    if (EVP_Digest(buf, len, out, &olen, EVP_sha256(), NULL) != 1)
        die("SHA-256 failed");
}

void sha256_file(const char *path, uint8_t out[32])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        die("cannot open '%s': %s", path, strerror(errno));

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        die("SHA-256 init failed");

    uint8_t chunk[64 * 1024];
    size_t got;
    while ((got = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (EVP_DigestUpdate(ctx, chunk, got) != 1)
            die("SHA-256 update failed");
    }
    if (ferror(f))
        die("read error on '%s'", path);

    unsigned int olen = 32;
    if (EVP_DigestFinal_ex(ctx, out, &olen) != 1)
        die("SHA-256 final failed");

    EVP_MD_CTX_free(ctx);
    secure_wipe(chunk, sizeof chunk);
    fclose(f);
}

void to_hex(const uint8_t *src, size_t n, char *dst)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[2 * i]     = hx[src[i] >> 4];
        dst[2 * i + 1] = hx[src[i] & 0x0f];
    }
    dst[2 * n] = '\0';
}

char *b64_encode(const uint8_t *src, size_t n)
{
    /* 4 chars per 3 bytes, plus NUL. */
    size_t outcap = 4 * ((n + 2) / 3) + 1;
    char *out = xmalloc(outcap);
    int w = EVP_EncodeBlock((unsigned char *)out, src, (int)n);
    if (w < 0)
        die("base64 encode failed");
    out[w] = '\0';
    return out;
}

/* Reverse of the standard base64 alphabet: value 0-63, or -1 if not a
 * base64 symbol. '=' is handled separately as padding. */
static int b64_val(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

uint8_t *b64_decode(const char *src, size_t srclen, size_t *out_len)
{
    /* Strip ASCII whitespace first so wrapped armor bodies decode cleanly,
     * then validate strictly: every remaining byte must be an alphabet
     * symbol, padding may only be the final one or two '=' on a 4-char
     * boundary, and the total length must be a multiple of 4. */
    char *clean = xmalloc(srclen + 1);
    size_t c = 0;
    for (size_t i = 0; i < srclen; i++) {
        char ch = src[i];
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t' || ch == '\f'
            || ch == '\v')
            continue;
        clean[c++] = ch;
    }
    if (c == 0 || c % 4 != 0) {
        free(clean);
        return NULL;
    }

    size_t pad = 0;
    if (clean[c - 1] == '=') pad++;
    if (clean[c - 2] == '=') pad++;

    /* '=' must appear only in the final quantum, contiguously at the end. */
    for (size_t i = 0; i < c - pad; i++) {
        if (b64_val((unsigned char)clean[i]) < 0) {
            free(clean);
            return NULL;
        }
    }

    size_t outcap = c / 4 * 3;
    uint8_t *out = xmalloc(outcap ? outcap : 1);
    size_t o = 0;
    for (size_t i = 0; i < c; i += 4) {
        int a = b64_val((unsigned char)clean[i]);
        int b = b64_val((unsigned char)clean[i + 1]);
        bool last = (i + 4 == c);
        int cc = (last && pad >= 2) ? 0 : b64_val((unsigned char)clean[i + 2]);
        int d  = (last && pad >= 1) ? 0 : b64_val((unsigned char)clean[i + 3]);
        if (a < 0 || b < 0 || cc < 0 || d < 0) {
            free(clean);
            free(out);
            return NULL;
        }
        uint32_t q = (uint32_t)a << 18 | (uint32_t)b << 12 |
                     (uint32_t)cc << 6 | (uint32_t)d;
        out[o++] = (uint8_t)(q >> 16);
        if (!(last && pad >= 2)) out[o++] = (uint8_t)(q >> 8);
        if (!(last && pad >= 1)) out[o++] = (uint8_t)q;
    }

    free(clean);
    *out_len = o;
    return out;
}

char *prompt_passphrase(const char *prompt, bool confirm)
{
    struct termios old, raw;
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty)
        die("no controlling terminal for passphrase entry");

    int fd = fileno(tty);
    if (tcgetattr(fd, &old) != 0)
        die("tcgetattr failed");
    raw = old;
    raw.c_lflag &= ~(tcflag_t)ECHO;
    if (tcsetattr(fd, TCSAFLUSH, &raw) != 0)
        die("tcsetattr failed");

    fputs(prompt, tty);
    fflush(tty);

    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, tty);
    fputc('\n', tty);
    if (n < 0)
        die("failed to read passphrase");
    if (n > 0 && line[n - 1] == '\n')
        line[--n] = '\0';

    if (confirm) {
        fputs("Confirm passphrase: ", tty);
        fflush(tty);
        char *line2 = NULL;
        size_t cap2 = 0;
        ssize_t n2 = getline(&line2, &cap2, tty);
        fputc('\n', tty);
        if (n2 < 0)
            die("failed to read passphrase confirmation");
        if (n2 > 0 && line2[n2 - 1] == '\n')
            line2[--n2] = '\0';
        if (strcmp(line, line2) != 0) {
            secure_wipe(line, (size_t)n);
            secure_wipe(line2, (size_t)n2);
            free(line);
            free(line2);
            tcsetattr(fd, TCSAFLUSH, &old);
            fclose(tty);
            die("passphrases do not match");
        }
        secure_wipe(line2, (size_t)n2);
        free(line2);
    }

    tcsetattr(fd, TCSAFLUSH, &old);
    fclose(tty);
    return line;
}
