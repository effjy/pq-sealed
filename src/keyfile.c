/* keyfile.c — armored (PEM-like) key containers.
 *
 * Public keys are stored as plain armored base64. Secret keys may be
 * encrypted at rest with Argon2id (key derivation) + AES-256-GCM (AEAD),
 * mirroring the symmetric stack used across the wider toolset.
 *
 * A secret key embeds its matching public key in a `Pub:` header so signing
 * can always bind the signer fingerprint without hunting for a companion
 * file. For encrypted secret keys the algorithm string *and* that public key
 * are fed in as AEAD, so neither can be swapped without failing the GCM tag.
 *
 * Parsing is split into a pure, never-aborting `key_armor_parse` over raw
 * (untrusted, not necessarily NUL-terminated) bytes plus a `key_decrypt`
 * step that takes the passphrase as an argument; `key_load` is the thin
 * file-I/O + prompt wrapper over the two. See keyfile_internal.h.
 *
 * Armor layout:
 *   -----BEGIN PQSIGN <PUBLIC|SECRET> KEY-----
 *   Alg: ML-DSA-65
 *   Pub: <base64>                (secret keys only — the public key)
 *   Cipher: AES-256-GCM          (secret + encrypted only)
 *   KDF: Argon2id t=3 m=65536 p=1 (secret + encrypted only)
 *   Salt: <base64>               (secret + encrypted only)
 *   Nonce: <base64>              (secret + encrypted only)
 *   Tag: <base64>                (secret + encrypted only)
 *   <blank line>
 *   <base64 body>
 *   -----END PQSIGN <PUBLIC|SECRET> KEY-----
 */
#define _GNU_SOURCE
#include "pqsign.h"
#include "keyfile_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <argon2.h>

/* Argon2id parameters — interactive but firm. */
#define ARGON2_T   3u            /* iterations           */
#define ARGON2_M   65536u        /* memory in KiB (64MiB) */
#define ARGON2_P   1u            /* lanes/threads        */

static const char PUB_BEGIN[] = "-----BEGIN PQSIGN PUBLIC KEY-----";
static const char PUB_END[]   = "-----END PQSIGN PUBLIC KEY-----";
static const char SEC_BEGIN[] = "-----BEGIN PQSIGN SECRET KEY-----";
static const char SEC_END[]   = "-----END PQSIGN SECRET KEY-----";

/* Derive a 32-byte DEK from passphrase + salt via the reference Argon2id. */
static void derive_key(const char *pass, const uint8_t salt[PQS_SALT_LEN],
                       uint8_t dek[PQS_DEK_LEN])
{
    int rc = argon2id_hash_raw(ARGON2_T, ARGON2_M, ARGON2_P,
                               pass, strlen(pass),
                               salt, PQS_SALT_LEN,
                               dek, PQS_DEK_LEN);
    if (rc != ARGON2_OK)
        die("Argon2id derivation failed: %s", argon2_error_message(rc));
}

/* AES-256-GCM. The AAD binds the algorithm string and the public key to the
 * ciphertext, so a tamperer cannot repurpose an encrypted key under a
 * different identity without failing the tag. */
static uint8_t *gcm_encrypt(const uint8_t dek[PQS_DEK_LEN],
                            const uint8_t nonce[PQS_NONCE_LEN],
                            const char *alg,
                            const uint8_t *pub, size_t pub_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t tag[PQS_TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        die("cipher context allocation failed");
    uint8_t *ct = xmalloc(pt_len);
    int len = 0, tmp = 0;

    if (EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, PQS_NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(c, NULL, NULL, dek, nonce) != 1)
        die("AES-GCM init failed");

    if (EVP_EncryptUpdate(c, NULL, &tmp, (const uint8_t *)alg,
                          (int)strlen(alg)) != 1 ||
        (pub_len && EVP_EncryptUpdate(c, NULL, &tmp, pub, (int)pub_len) != 1))
        die("AES-GCM AAD failed");
    if (EVP_EncryptUpdate(c, ct, &len, pt, (int)pt_len) != 1)
        die("AES-GCM encrypt failed");
    int final = 0;
    if (EVP_EncryptFinal_ex(c, ct + len, &final) != 1)
        die("AES-GCM finalize failed");
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, PQS_TAG_LEN, tag) != 1)
        die("AES-GCM tag failed");

    EVP_CIPHER_CTX_free(c);
    return ct;
}

/* Returns NULL on auth failure (wrong passphrase or tampered key). The
 * plaintext is allocated with secure_alloc so it is mlock'd. */
static uint8_t *gcm_decrypt(const uint8_t dek[PQS_DEK_LEN],
                            const uint8_t nonce[PQS_NONCE_LEN],
                            const char *alg,
                            const uint8_t *pub, size_t pub_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[PQS_TAG_LEN])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        die("cipher context allocation failed");
    uint8_t *pt = secure_alloc(ct_len);
    int len = 0, tmp = 0;

    if (EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, PQS_NONCE_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(c, NULL, NULL, dek, nonce) != 1)
        die("AES-GCM init failed");

    if (EVP_DecryptUpdate(c, NULL, &tmp, (const uint8_t *)alg,
                          (int)strlen(alg)) != 1 ||
        (pub_len && EVP_DecryptUpdate(c, NULL, &tmp, pub, (int)pub_len) != 1))
        die("AES-GCM AAD failed");
    if (EVP_DecryptUpdate(c, pt, &len, ct, (int)ct_len) != 1)
        die("AES-GCM decrypt failed");
    uint8_t tagcopy[PQS_TAG_LEN];   /* EVP_CTRL takes a non-const pointer */
    memcpy(tagcopy, tag, PQS_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, PQS_TAG_LEN, tagcopy) != 1)
        die("AES-GCM set tag failed");

    int final = 0;
    int ok = EVP_DecryptFinal_ex(c, pt + len, &final);
    EVP_CIPHER_CTX_free(c);
    if (ok != 1) {
        secure_free(pt, ct_len);
        return NULL;
    }
    return pt;
}

/* --- armor writers --------------------------------------------------- */

static void write_armored(const char *path, const char *begin,
                          const char *end, const char *headers,
                          const uint8_t *body, size_t body_len, int mode)
{
    char *b64 = b64_encode(body, body_len);

    size_t cap = strlen(begin) + strlen(end) + strlen(headers) +
                 strlen(b64) + 64;
    char *out = xmalloc(cap);
    /* Explicit blank line separates the (newline-free) header block from the
     * base64 body, matching the "\n\n" the parser scans for. */
    int n = snprintf(out, cap, "%s\n%s\n\n%s\n%s\n", begin, headers, b64, end);
    if (n < 0 || (size_t)n >= cap)
        die("armor formatting overflow");

    /* Key files are written crash-safely; secrets must never be left half
     * on disk. (Callers pass the secret-or-public mode.) */
    write_file_atomic(path, (const uint8_t *)out, (size_t)n, mode);
    free(b64);
    free(out);
}

void key_write_public(const char *path, const char *alg,
                      const uint8_t *pub, size_t pub_len)
{
    char headers[128];
    snprintf(headers, sizeof headers, "Alg: %s", alg);
    write_armored(path, PUB_BEGIN, PUB_END, headers, pub, pub_len, 0644);
}

void key_write_secret(const char *path, const char *alg,
                      const uint8_t *sec, size_t sec_len,
                      const uint8_t *pub, size_t pub_len,
                      const char *passphrase)
{
    char *b_pub = b64_encode(pub, pub_len);

    if (!passphrase) {
        /* Pub is a full public key in base64, so size the buffer to it. */
        size_t hcap = strlen(alg) + strlen(b_pub) + 32;
        char *headers = xmalloc(hcap);
        snprintf(headers, hcap, "Alg: %s\nPub: %s", alg, b_pub);
        write_armored(path, SEC_BEGIN, SEC_END, headers, sec, sec_len, 0600);
        free(headers);
        free(b_pub);
        return;
    }

    uint8_t salt[PQS_SALT_LEN], nonce[PQS_NONCE_LEN], tag[PQS_TAG_LEN];
    uint8_t dek[PQS_DEK_LEN];
    random_bytes(salt, sizeof salt);
    random_bytes(nonce, sizeof nonce);
    derive_key(passphrase, salt, dek);

    uint8_t *ct = gcm_encrypt(dek, nonce, alg, pub, pub_len, sec, sec_len, tag);
    secure_wipe(dek, sizeof dek);

    char *b_salt  = b64_encode(salt, sizeof salt);
    char *b_nonce = b64_encode(nonce, sizeof nonce);
    char *b_tag   = b64_encode(tag, sizeof tag);

    /* Header block can be large (Pub is a full public key in base64). */
    size_t hcap = strlen(alg) + strlen(b_pub) + strlen(b_salt) +
                  strlen(b_nonce) + strlen(b_tag) + 128;
    char *headers = xmalloc(hcap);
    snprintf(headers, hcap,
             "Alg: %s\n"
             "Pub: %s\n"
             "Cipher: AES-256-GCM\n"
             "KDF: Argon2id t=%u m=%u p=%u\n"
             "Salt: %s\n"
             "Nonce: %s\n"
             "Tag: %s",
             alg, b_pub, ARGON2_T, ARGON2_M, ARGON2_P, b_salt, b_nonce, b_tag);

    write_armored(path, SEC_BEGIN, SEC_END, headers, ct, sec_len, 0600);

    free(headers);
    free(b_pub); free(b_salt); free(b_nonce); free(b_tag);
    secure_wipe(ct, sec_len);
    free(ct);
}

/* --- armor parsing (pure, raw-byte safe) ----------------------------- */

static const uint8_t *find_mem(const uint8_t *hay, size_t haylen,
                               const char *needle)
{
    return memmem(hay, haylen, needle, strlen(needle));
}

/* Find a "Key: value" header in the byte range [text, end). Returns a
 * malloc'd, trimmed, NUL-terminated copy of the value, or NULL if absent. */
static char *find_header(const uint8_t *text, const uint8_t *end,
                         const char *key)
{
    size_t klen = strlen(key);
    const uint8_t *p = text;
    while (p < end) {
        const uint8_t *eol = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
        if (linelen > klen + 1 &&
            memcmp(p, key, klen) == 0 && p[klen] == ':') {
            const uint8_t *v = p + klen + 1;
            while (v < p + linelen && (*v == ' ' || *v == '\t'))
                v++;
            size_t vlen = (size_t)(p + linelen - v);
            char *out = xmalloc(vlen + 1);
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return out;
        }
        if (!eol)
            break;
        p = eol + 1;
    }
    return NULL;
}

/* Decode a base64 header value, requiring an exact decoded length. */
static uint8_t *decode_fixed(const char *b64v, size_t want)
{
    if (!b64v)
        return NULL;
    size_t got = 0;
    uint8_t *raw = b64_decode(b64v, strlen(b64v), &got);
    if (!raw || got != want) {
        free(raw);
        return NULL;
    }
    return raw;
}

bool key_armor_parse(const uint8_t *buf, size_t len, pqsign_armor *out)
{
    memset(out, 0, sizeof *out);

    const uint8_t *bp = find_mem(buf, len, SEC_BEGIN);
    bool secret = bp != NULL;
    const char *endm;
    if (secret) {
        endm = SEC_END;
    } else {
        bp = find_mem(buf, len, PUB_BEGIN);
        if (!bp)
            return false;                 /* not a PQSIGN key file */
        endm = PUB_END;
    }
    out->is_secret = secret;

    const uint8_t *ep = find_mem(bp, (size_t)(buf + len - bp), endm);
    if (!ep || ep < bp)
        return false;                     /* missing/!ordered END marker */

    /* Algorithm. */
    char *alg = find_header(bp, ep, "Alg");
    if (!alg || strlen(alg) >= sizeof out->alg) {
        free(alg);
        return false;
    }
    snprintf(out->alg, sizeof out->alg, "%s", alg);
    free(alg);

    out->encrypted = secret && find_header(bp, ep, "Cipher") != NULL;

    /* Optional embedded public key (secret keys carry it). */
    char *b_pub = find_header(bp, ep, "Pub");
    if (b_pub) {
        out->pub = b64_decode(b_pub, strlen(b_pub), &out->pub_len);
        free(b_pub);
        if (!out->pub) { armor_free(out); return false; }
    }

    /* Body: from the first blank line up to the END marker. */
    const uint8_t *body = find_mem(bp, (size_t)(ep - bp), "\n\n");
    if (!body) { armor_free(out); return false; }
    body += 2;
    out->body = b64_decode((const char *)body, (size_t)(ep - body),
                           &out->body_len);
    if (!out->body) { armor_free(out); return false; }

    if (out->encrypted) {
        char *b_salt  = find_header(bp, ep, "Salt");
        char *b_nonce = find_header(bp, ep, "Nonce");
        char *b_tag   = find_header(bp, ep, "Tag");
        uint8_t *salt  = decode_fixed(b_salt,  PQS_SALT_LEN);
        uint8_t *nonce = decode_fixed(b_nonce, PQS_NONCE_LEN);
        uint8_t *tag   = decode_fixed(b_tag,   PQS_TAG_LEN);
        free(b_salt); free(b_nonce); free(b_tag);
        if (!salt || !nonce || !tag) {
            free(salt); free(nonce); free(tag);
            armor_free(out);
            return false;
        }
        memcpy(out->salt,  salt,  PQS_SALT_LEN);
        memcpy(out->nonce, nonce, PQS_NONCE_LEN);
        memcpy(out->tag,   tag,   PQS_TAG_LEN);
        free(salt); free(nonce); free(tag);
    }

    return true;
}

bool key_decrypt(const pqsign_armor *a, const char *passphrase,
                 uint8_t **out_key, size_t *out_len)
{
    if (!a->encrypted) {
        /* Plaintext body is the key material; copy into owned storage. */
        uint8_t *k = a->is_secret ? secure_alloc(a->body_len)
                                  : xmalloc(a->body_len ? a->body_len : 1);
        memcpy(k, a->body, a->body_len);
        *out_key = k;
        *out_len = a->body_len;
        return true;
    }

    if (!passphrase)
        return false;                     /* encrypted but no passphrase */

    uint8_t dek[PQS_DEK_LEN];
    derive_key(passphrase, a->salt, dek);
    uint8_t *pt = gcm_decrypt(dek, a->nonce, a->alg, a->pub, a->pub_len,
                              a->body, a->body_len, a->tag);
    secure_wipe(dek, sizeof dek);
    if (!pt)
        return false;                     /* wrong passphrase / tampered */
    *out_key = pt;
    *out_len = a->body_len;
    return true;
}

void armor_free(pqsign_armor *a)
{
    if (!a)
        return;
    if (a->body) {
        secure_wipe(a->body, a->body_len);   /* may be plaintext secret */
        free(a->body);
    }
    free(a->pub);
    a->body = a->pub = NULL;
    a->body_len = a->pub_len = 0;
}

/* --- public entry point --------------------------------------------- */

void key_load(const char *path, pqsign_key *out)
{
    memset(out, 0, sizeof *out);
    size_t len;
    uint8_t *raw = read_file(path, &len);

    pqsign_armor a;
    if (!key_armor_parse(raw, len, &a)) {
        secure_wipe(raw, len);
        free(raw);
        die("'%s' is not a valid PQSIGN key file", path);
    }

    snprintf(out->alg, sizeof out->alg, "%s", a.alg);
    out->is_secret = a.is_secret;

    /* Transfer ownership of the embedded public key to the loaded key. */
    out->pub = a.pub;
    out->pub_len = a.pub_len;
    a.pub = NULL;

    char *pass = NULL;
    if (a.encrypted)
        pass = prompt_passphrase("Passphrase: ", false);

    bool ok = key_decrypt(&a, pass, &out->key, &out->key_len);
    if (pass) {
        secure_wipe(pass, strlen(pass));
        free(pass);
    }
    armor_free(&a);
    secure_wipe(raw, len);
    free(raw);

    if (!ok)
        die("wrong passphrase or corrupted secret key");
}

void key_free(pqsign_key *k)
{
    if (!k)
        return;
    if (k->key) {
        if (k->is_secret)
            secure_free(k->key, k->key_len);
        else
            free(k->key);
    }
    free(k->pub);
    k->key = k->pub = NULL;
    k->key_len = k->pub_len = 0;
}
