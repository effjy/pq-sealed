/* sealed.h — PQ-Sealed incremental encrypted backup engine.
 *
 * Two layers sit on top of the reused primitives:
 *
 *   repocrypto.c  the repository key-ring: a single Argon2id pass over the
 *                 password unwraps a Kyber-1024 + X448 hybrid secret key,
 *                 which decapsulates to one 32-byte repository data key.
 *                 Every object and manifest is then sealed with that data
 *                 key via libsodium's secretstream AEAD — so the expensive
 *                 KDF and the post-quantum KEM run once per repository open,
 *                 not once per file.
 *
 *   repo.c        the backup store: content-addressed, deduplicating objects
 *                 plus per-snapshot manifests signed with ML-DSA (pq-sign's
 *                 signature container), giving tamper-evident snapshots.
 */
#ifndef PQSEALED_H
#define PQSEALED_H

#include <stddef.h>
#include <stdint.h>

#define PQSEALED_VERSION "1.0.1"

/* Length of the repository data key (a secretstream key). */
#define RC_DK_LEN 32

/* ------------------------------------------------------------------ *
 *  repocrypto.c — repository key-ring and object sealing
 * ------------------------------------------------------------------ */

/* Create a new key-ring at `path`: derive a master key from `password`
 * (Argon2id), generate a fresh hybrid keypair, wrap its secret key under the
 * master key, encapsulate to its public key, and persist the result. The
 * resulting 32-byte data key is returned in `dk`. Returns 0 on success. */
int rc_keyring_create(const char *path, const char *password,
                      uint8_t dk[RC_DK_LEN]);

/* Open an existing key-ring with `password`, recovering the data key.
 * Returns 0 on success, -1 on a wrong password / tampered ring. */
int rc_keyring_open(const char *path, const char *password,
                    uint8_t dk[RC_DK_LEN]);

/* Seal `in_path` -> `out_path` under the data key (streaming secretstream,
 * written atomically). Returns 0 on success, -1 on failure. */
int rc_seal_file(const char *in_path, const char *out_path,
                 const uint8_t dk[RC_DK_LEN]);

/* Open a sealed file `in_path` -> plaintext `out_path` (atomic write).
 * Returns 0 on success, -1 on failure (corruption / wrong key / truncation). */
int rc_open_file(const char *in_path, const char *out_path,
                 const uint8_t dk[RC_DK_LEN]);

/* Seal an in-memory buffer to `out_path` (used for the manifest, so its
 * plaintext never touches disk). Returns 0 on success, -1 on failure. */
int rc_seal_buf(const uint8_t *buf, size_t len, const char *out_path,
                const uint8_t dk[RC_DK_LEN]);

/* Open a sealed file entirely into a freshly malloc'd buffer (NUL-terminated
 * for convenient text parsing). Returns the buffer with *out_len set, or NULL
 * on failure. Caller frees. */
uint8_t *rc_open_buf(const char *in_path, const uint8_t dk[RC_DK_LEN],
                     size_t *out_len);

/* ------------------------------------------------------------------ *
 *  repo.c — commands
 * ------------------------------------------------------------------ *
 *
 * Passwords are passed in by the caller (the CLI prompts the terminal; the
 * GUI collects them in dialogs), so the engine never touches /dev/tty. Each
 * command returns 0 on success or -1 on a recoverable error, writing a
 * human-readable message into `err`. Progress and per-item output are
 * delivered through an optional log callback rather than stdout; returning
 * non-zero from it requests cancellation.
 */

/* `key_pw` may be NULL or "" to leave the signing key unencrypted. */
typedef int (*sealed_log_cb)(const char *line, void *user);

int sealed_init(const char *repo, const char *repo_pw, const char *key_pw,
                char *err, size_t errlen);
int sealed_backup(const char *repo, const char *source,
                  const char *repo_pw, const char *key_pw,
                  sealed_log_cb log, void *user, char *err, size_t errlen);
int sealed_restore(const char *repo, const char *snapshot, const char *dest,
                   const char *repo_pw, sealed_log_cb log, void *user,
                   char *err, size_t errlen);
/* repo_pw is optional: when a valid password is supplied the manifests are
 * decrypted to report the snapshot's true data size, file count and creation
 * date; otherwise the listing falls back to showing the manifest file size. */
int sealed_list(const char *repo, const char *repo_pw, sealed_log_cb log,
                void *user, char *err, size_t errlen);
/* On success *out_failures (may be NULL) receives the number of bad/missing
 * signatures; the call still returns 0 unless the repository is unreadable. */
int sealed_verify(const char *repo, int *out_failures,
                  sealed_log_cb log, void *user, char *err, size_t errlen);

#endif /* PQSEALED_H */
