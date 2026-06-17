/* keyfile_internal.h — internal seams of the key-armor codec.
 *
 * These split the armored-key handling into a *pure* parse step (no file I/O,
 * no passphrase prompt, never aborts) and a separate decrypt step that takes
 * the passphrase as an argument. That makes the untrusted-input parser
 * fuzzable and lets tests exercise the encrypted round-trip non-interactively.
 *
 * Not part of the stable CLI surface; included by keyfile.c, the KAT harness,
 * and the fuzz targets.
 */
#ifndef PQSIGN_KEYFILE_INTERNAL_H
#define PQSIGN_KEYFILE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PQS_SALT_LEN   16
#define PQS_NONCE_LEN  12
#define PQS_TAG_LEN    16
#define PQS_DEK_LEN    32            /* AES-256 */

/* Structural view of an armored key, owning its decoded byte buffers. */
typedef struct {
    char     alg[64];
    bool     is_secret;
    bool     encrypted;

    uint8_t *body;                  /* base64 body: secret/public bytes, or  */
    size_t   body_len;              /* the ciphertext when `encrypted`        */

    uint8_t *pub;                   /* decoded `Pub:` header (NULL if absent) */
    size_t   pub_len;

    uint8_t  salt[PQS_SALT_LEN];    /* valid only when `encrypted`            */
    uint8_t  nonce[PQS_NONCE_LEN];
    uint8_t  tag[PQS_TAG_LEN];
} pqsign_armor;

/* Pure parse of armored key text. Returns false on any malformed input.
 * Never prompts, never reads files, never aborts. */
bool key_armor_parse(const uint8_t *buf, size_t len, pqsign_armor *out);

/* Recover the plaintext key bytes from a parsed armor. For an encrypted
 * secret key this derives the DEK from `passphrase` and AEAD-decrypts;
 * otherwise it just copies the body. Returns false on a wrong passphrase,
 * a failed tag, or a missing passphrase for an encrypted key.
 * *out_key is malloc'd (secure_alloc for secrets); caller frees. */
bool key_decrypt(const pqsign_armor *a, const char *passphrase,
                 uint8_t **out_key, size_t *out_len);

/* Free the decoded buffers owned by a parsed armor (wipes the body). */
void armor_free(pqsign_armor *a);

#endif /* PQSIGN_KEYFILE_INTERNAL_H */
