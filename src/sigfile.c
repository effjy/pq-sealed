/* sigfile.c — detached signature container (binary).
 *
 * Layout (all integers little-endian):
 *   magic[6]     = "PQSIGN"
 *   ver_major u8 = 1
 *   ver_minor u8 = 0
 *   alg_len   u16          length of the algorithm identifier
 *   alg[alg_len]           e.g. "ML-DSA-65" (no NUL)
 *   pub_fpr[32]            SHA-256 of the signer's public key
 *   sig_len   u32
 *   sig[sig_len]           raw signature bytes
 *
 * The container is self-describing: verify learns the scheme and the
 * expected signer fingerprint without any side-channel metadata.
 */
#include "pqsign.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t MAGIC[6] = { 'P', 'Q', 'S', 'I', 'G', 'N' };
#define VER_MAJOR 1
#define VER_MINOR 0

static void put_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)(v >> 8);
}
static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint8_t *sigfile_build(const char *alg, const uint8_t *pubkey,
                       size_t pubkey_len, const uint8_t *sig, size_t sig_len,
                       size_t *out_len)
{
    size_t alg_len = strlen(alg);
    if (alg_len > 0xffff)
        die("algorithm name too long");

    size_t total = 6 + 1 + 1 + 2 + alg_len + 32 + 4 + sig_len;
    uint8_t *buf = xmalloc(total);
    size_t o = 0;

    memcpy(buf + o, MAGIC, 6);            o += 6;
    buf[o++] = VER_MAJOR;
    buf[o++] = VER_MINOR;
    put_u16(buf + o, (uint16_t)alg_len);  o += 2;
    memcpy(buf + o, alg, alg_len);        o += alg_len;
    sha256(pubkey, pubkey_len, buf + o);  o += 32;
    put_u32(buf + o, (uint32_t)sig_len);  o += 4;
    memcpy(buf + o, sig, sig_len);        o += sig_len;

    *out_len = total;
    return buf;
}

bool sigfile_parse(const uint8_t *buf, size_t len, pqsign_sigfile *out)
{
    /* Input is attacker-controlled: validate every field and never abort.
     * Bounds are written as `field > len - o` (not `o + field > len`) so the
     * arithmetic cannot overflow, since each check keeps `o <= len`. */
    size_t o = 0;
    if (len < 6 + 2 + 2 || memcmp(buf, MAGIC, 6) != 0)
        return false;                     /* not a pq-sign signature file */
    o += 6;

    uint8_t vmaj = buf[o++];
    o++;                                  /* minor version: accepted as-is */
    if (vmaj != VER_MAJOR)
        return false;                     /* unsupported major version    */

    if (len - o < 2)
        return false;                     /* truncated (alg length)       */
    uint16_t alg_len = get_u16(buf + o);
    o += 2;
    if (alg_len == 0 || alg_len >= sizeof out->alg || alg_len > len - o)
        return false;                     /* invalid algorithm field      */
    memcpy(out->alg, buf + o, alg_len);
    out->alg[alg_len] = '\0';
    o += alg_len;

    if (len - o < 32)
        return false;                     /* truncated (fingerprint)      */
    memcpy(out->pub_fpr, buf + o, 32);
    o += 32;

    if (len - o < 4)
        return false;                     /* truncated (sig length)       */
    uint32_t sig_len = get_u32(buf + o);
    o += 4;
    if (sig_len != len - o)
        return false;                     /* trailing or missing bytes    */

    out->sig = buf + o;
    out->sig_len = sig_len;
    out->raw = NULL;   /* set by caller if it owns `buf` */
    return true;
}

void sigfile_free(pqsign_sigfile *s)
{
    if (s && s->raw) {
        free(s->raw);
        s->raw = NULL;
    }
}
