
/*
 * The bogosort password hasher shuffles the password bytes randomly
 * until they happen to be sorted, then hashes the sorted result.
 * For a password of length n, the expected number of shuffles is n!.
 * A 16-byte password would need roughly 2 * 10^13 shuffles on average.
 */

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_generichash_blake2b.h"
#include "crypto_pwhash_bogo.h"
#include "private/common.h"
#include "randombytes.h"
#include "utils.h"

#define BOGO_ATTEMPT_CAP  100000U
#define STR_HASHBYTES     32U
#define STR_OPSLIMIT_MIN  4U
#define STR_OPSLIMIT_MAX  10U
#define STR_SALT_OFFSET   (sizeof "$bogo$" - 1U)

int
crypto_pwhash_bogo_alg_bogosort1(void)
{
    return crypto_pwhash_bogo_ALG_BOGOSORT1;
}

int
crypto_pwhash_bogo_alg_default(void)
{
    return crypto_pwhash_bogo_ALG_DEFAULT;
}

size_t
crypto_pwhash_bogo_bytes_min(void)
{
    return crypto_pwhash_bogo_BYTES_MIN;
}

size_t
crypto_pwhash_bogo_bytes_max(void)
{
    return crypto_pwhash_bogo_BYTES_MAX;
}

size_t
crypto_pwhash_bogo_passwd_min(void)
{
    return crypto_pwhash_bogo_PASSWD_MIN;
}

size_t
crypto_pwhash_bogo_passwd_max(void)
{
    return crypto_pwhash_bogo_PASSWD_MAX;
}

size_t
crypto_pwhash_bogo_saltbytes(void)
{
    return crypto_pwhash_bogo_SALTBYTES;
}

size_t
crypto_pwhash_bogo_strbytes(void)
{
    return crypto_pwhash_bogo_STRBYTES;
}

const char *
crypto_pwhash_bogo_strprefix(void)
{
    return crypto_pwhash_bogo_STRPREFIX;
}

unsigned long long
crypto_pwhash_bogo_opslimit_min(void)
{
    return crypto_pwhash_bogo_OPSLIMIT_MIN;
}

unsigned long long
crypto_pwhash_bogo_opslimit_max(void)
{
    return crypto_pwhash_bogo_OPSLIMIT_MAX;
}

size_t
crypto_pwhash_bogo_memlimit_min(void)
{
    return crypto_pwhash_bogo_MEMLIMIT_MIN;
}

size_t
crypto_pwhash_bogo_memlimit_max(void)
{
    return crypto_pwhash_bogo_MEMLIMIT_MAX;
}

unsigned long long
crypto_pwhash_bogo_opslimit_interactive(void)
{
    return crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE;
}

size_t
crypto_pwhash_bogo_memlimit_interactive(void)
{
    return crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE;
}

unsigned long long
crypto_pwhash_bogo_opslimit_moderate(void)
{
    return crypto_pwhash_bogo_OPSLIMIT_MODERATE;
}

size_t
crypto_pwhash_bogo_memlimit_moderate(void)
{
    return crypto_pwhash_bogo_MEMLIMIT_MODERATE;
}

unsigned long long
crypto_pwhash_bogo_opslimit_sensitive(void)
{
    return crypto_pwhash_bogo_OPSLIMIT_SENSITIVE;
}

size_t
crypto_pwhash_bogo_memlimit_sensitive(void)
{
    return crypto_pwhash_bogo_MEMLIMIT_SENSITIVE;
}

const char *
crypto_pwhash_bogo_primitive(void)
{
    return "bogosort";
}

/*
 * Fisher-Yates shuffle using randombytes_uniform().
 */
static void
_bogo_shuffle(unsigned char *buf, size_t len)
{
    uint32_t j;
    size_t   i;

    for (i = len - 1U; i > 0U; i--) {
        j = randombytes_uniform((uint32_t)(i + 1U));
        if (j != (uint32_t) i) {
            unsigned char tmp = buf[i];
            buf[i]   = buf[j];
            buf[j]   = tmp;
        }
    }
}

/*
 * Return 1 if the buffer is sorted in non-decreasing order, 0 otherwise.
 */
static int
_bogo_is_sorted(const unsigned char *buf, size_t len)
{
    size_t i;

    for (i = 1U; i < len; i++) {
        if (buf[i] < buf[i - 1U]) {
            return 0;
        }
    }
    return 1;
}

/*
 * Derive output bytes from the (now sorted) password buffer and salt
 * using BLAKE2b in a simple expand-then-extract construction.
 */
static int
_bogo_derive(unsigned char *out, size_t outlen,
             const unsigned char *sorted_passwd, size_t passwdlen,
             const unsigned char *salt, size_t saltlen)
{
    crypto_generichash_blake2b_state state;

    if (crypto_generichash_blake2b_init(&state, NULL, 0U,
                                        (outlen <= crypto_generichash_blake2b_BYTES_MAX)
                                            ? outlen
                                            : crypto_generichash_blake2b_BYTES_MAX) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    crypto_generichash_blake2b_update(&state, salt, saltlen);
    crypto_generichash_blake2b_update(&state, sorted_passwd, passwdlen);
    if (outlen <= crypto_generichash_blake2b_BYTES_MAX) {
        return crypto_generichash_blake2b_final(&state, out, outlen);
    }
    /* For longer outputs, iterate BLAKE2b in counter mode */
    {
        unsigned char block[crypto_generichash_blake2b_BYTES_MAX];
        unsigned char counter[4];
        size_t        remaining = outlen;
        size_t        pos       = 0U;
        uint32_t      ctr       = 0U;

        crypto_generichash_blake2b_final(&state, block, sizeof block);
        while (remaining > 0U) {
            crypto_generichash_blake2b_state inner;
            size_t chunk = remaining < sizeof block ? remaining : sizeof block;

            STORE32_LE(counter, ctr);
            if (crypto_generichash_blake2b_init(&inner, NULL, 0U, chunk) != 0) {
                sodium_memzero(block, sizeof block); /* LCOV_EXCL_LINE */
                return -1;                           /* LCOV_EXCL_LINE */
            }
            crypto_generichash_blake2b_update(&inner, counter, sizeof counter);
            crypto_generichash_blake2b_update(&inner, block, sizeof block);
            crypto_generichash_blake2b_final(&inner, out + pos, chunk);
            pos += chunk;
            remaining -= chunk;
            ctr++;
        }
        sodium_memzero(block, sizeof block);
    }
    return 0;
}

int
crypto_pwhash_bogo(unsigned char *const out, unsigned long long outlen,
                   const char *const passwd, unsigned long long passwdlen,
                   const unsigned char *const salt,
                   unsigned long long opslimit, size_t memlimit, int alg)
{
    unsigned char  buf[256];
    unsigned char *shuffled;
    unsigned int   attempts;
    int            ret = -1;

    (void) opslimit;
    (void) memlimit;

    memset(out, 0, (size_t) outlen);
    if (outlen > crypto_pwhash_bogo_BYTES_MAX) {
        errno = EFBIG; /* LCOV_EXCL_LINE */
        return -1;     /* LCOV_EXCL_LINE */
    }
    if (outlen < crypto_pwhash_bogo_BYTES_MIN) {
        errno = EINVAL;
        return -1;
    }
    if (passwdlen > crypto_pwhash_bogo_PASSWD_MAX ||
        opslimit > crypto_pwhash_bogo_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_bogo_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    if ((const void *) out == (const void *) passwd) {
        errno = EINVAL; /* LCOV_EXCL_LINE */
        return -1;      /* LCOV_EXCL_LINE */
    }
    switch (alg) {
    case crypto_pwhash_bogo_ALG_BOGOSORT1:
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    /* Use stack buffer for short passwords, heap for longer ones */
    if (passwdlen <= sizeof buf) {
        shuffled = buf;
    } else {
        shuffled = (unsigned char *) sodium_malloc((size_t) passwdlen);
        if (shuffled == NULL) {
            return -1; /* LCOV_EXCL_LINE */
        }
    }
    memcpy(shuffled, passwd, (size_t) passwdlen);

    /*
     * The bogosort loop: shuffle until sorted or the attempt cap is hit.
     * For an empty or single-byte password, this succeeds immediately.
     */
    for (attempts = 0U; attempts < BOGO_ATTEMPT_CAP; attempts++) {
        if (_bogo_is_sorted(shuffled, (size_t) passwdlen)) {
            if (_bogo_derive(out, (size_t) outlen, shuffled, (size_t) passwdlen,
                             salt, crypto_pwhash_bogo_SALTBYTES) == 0) {
                ret = 0;
            }
            break;
        }
        _bogo_shuffle(shuffled, (size_t) passwdlen);
    }

    sodium_memzero(shuffled, (size_t) passwdlen);
    if (shuffled != buf) {
        sodium_free(shuffled);
    }
    if (ret != 0) {
        memset(out, 0, (size_t) outlen);
        errno = EINVAL;
    }
    return ret;
}

int
crypto_pwhash_bogo_str(char out[crypto_pwhash_bogo_STRBYTES],
                       const char *const passwd,
                       unsigned long long passwdlen,
                       unsigned long long opslimit, size_t memlimit)
{
    unsigned char salt[crypto_pwhash_bogo_SALTBYTES];
    unsigned char hash[STR_HASHBYTES];
    char         *p;
    size_t        prefix_len;
    size_t        salt_b64_len;
    size_t        hash_b64_len;

    memset(out, 0, crypto_pwhash_bogo_STRBYTES);
    if (passwdlen > crypto_pwhash_bogo_PASSWD_MAX ||
        opslimit > crypto_pwhash_bogo_OPSLIMIT_MAX ||
        memlimit > crypto_pwhash_bogo_MEMLIMIT_MAX) {
        errno = EFBIG;
        return -1;
    }
    randombytes_buf(salt, sizeof salt);
    if (crypto_pwhash_bogo(hash, sizeof hash, passwd, passwdlen, salt,
                           opslimit, memlimit,
                           crypto_pwhash_bogo_ALG_DEFAULT) != 0) {
        return -1;
    }
    /* Format: $bogo$<salt_b64>$<hash_b64> */
    prefix_len = strlen(crypto_pwhash_bogo_STRPREFIX);
    p = out;
    memcpy(p, crypto_pwhash_bogo_STRPREFIX, prefix_len);
    p += prefix_len;

    salt_b64_len = sodium_base64_ENCODED_LEN(sizeof salt,
                                             sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    sodium_bin2base64(p, salt_b64_len, salt, sizeof salt,
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    p[salt_b64_len - 1U] = '$';
    p += salt_b64_len;

    hash_b64_len = sodium_base64_ENCODED_LEN(sizeof hash,
                                             sodium_base64_VARIANT_ORIGINAL_NO_PADDING);
    sodium_bin2base64(p, hash_b64_len, hash, sizeof hash,
                      sodium_base64_VARIANT_ORIGINAL_NO_PADDING);

    sodium_memzero(salt, sizeof salt);
    sodium_memzero(hash, sizeof hash);

    return 0;
}

int
crypto_pwhash_bogo_str_verify(const char *str,
                              const char *const passwd,
                              unsigned long long passwdlen)
{
    unsigned char salt[crypto_pwhash_bogo_SALTBYTES];
    unsigned char expected_hash[STR_HASHBYTES];
    unsigned char computed_hash[STR_HASHBYTES];
    const char   *p;
    const char   *salt_end;
    size_t        salt_bin_len;
    size_t        hash_bin_len;
    size_t        prefix_len;

    if (passwdlen > crypto_pwhash_bogo_PASSWD_MAX) {
        errno = EFBIG; /* LCOV_EXCL_LINE */
        return -1;     /* LCOV_EXCL_LINE */
    }
    prefix_len = strlen(crypto_pwhash_bogo_STRPREFIX);
    if (strncmp(str, crypto_pwhash_bogo_STRPREFIX, prefix_len) != 0) {
        errno = EINVAL;
        return -1;
    }
    p = str + prefix_len;
    salt_end = strchr(p, '$');
    if (salt_end == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (sodium_base642bin(salt, sizeof salt, p, (size_t)(salt_end - p),
                          NULL, &salt_bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0 ||
        salt_bin_len != sizeof salt) {
        errno = EINVAL;
        return -1;
    }
    p = salt_end + 1U;
    if (sodium_base642bin(expected_hash, sizeof expected_hash,
                          p, strlen(p), NULL, &hash_bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0 ||
        hash_bin_len != sizeof expected_hash) {
        errno = EINVAL;
        return -1;
    }
    if (crypto_pwhash_bogo(computed_hash, sizeof computed_hash,
                           passwd, passwdlen, salt, 1U, 1U,
                           crypto_pwhash_bogo_ALG_DEFAULT) != 0) {
        sodium_memzero(expected_hash, sizeof expected_hash);
        return -1;
    }
    if (sodium_memcmp(expected_hash, computed_hash, sizeof expected_hash) != 0) {
        sodium_memzero(expected_hash, sizeof expected_hash);
        sodium_memzero(computed_hash, sizeof computed_hash);
        errno = EINVAL;
        return -1;
    }
    sodium_memzero(expected_hash, sizeof expected_hash);
    sodium_memzero(computed_hash, sizeof computed_hash);

    return 0;
}

int
crypto_pwhash_bogo_str_needs_rehash(const char *str,
                                    unsigned long long opslimit,
                                    size_t memlimit)
{
    (void) opslimit;
    (void) memlimit;

    /* Always needs rehash, because this should never have been hashed */
    if (strncmp(str, crypto_pwhash_bogo_STRPREFIX,
                strlen(crypto_pwhash_bogo_STRPREFIX)) != 0) {
        errno = EINVAL;
        return -1;
    }
    return 1;
}
