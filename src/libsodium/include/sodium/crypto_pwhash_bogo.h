
#ifndef crypto_pwhash_bogo_H
#define crypto_pwhash_bogo_H

/*
 * WARNING: This is a joke API shipped for April Fool's Day.
 * It is NOT suitable for any cryptographic or security purpose.
 * It derives keys by randomly shuffling the password until the bytes
 * happen to land in sorted order, then hashing the result.
 * Expected runtime for a 16-byte password: roughly 2 * 10^13 shuffles.
 * Use Argon2id for real password hashing.
 */

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

#define crypto_pwhash_bogo_ALG_BOGOSORT1 1
SODIUM_EXPORT
int crypto_pwhash_bogo_alg_bogosort1(void);

#define crypto_pwhash_bogo_ALG_DEFAULT crypto_pwhash_bogo_ALG_BOGOSORT1
SODIUM_EXPORT
int crypto_pwhash_bogo_alg_default(void);

#define crypto_pwhash_bogo_BYTES_MIN 16U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_bytes_min(void);

#define crypto_pwhash_bogo_BYTES_MAX SODIUM_MIN(SODIUM_SIZE_MAX, 4294967295U)
SODIUM_EXPORT
size_t crypto_pwhash_bogo_bytes_max(void);

#define crypto_pwhash_bogo_PASSWD_MIN 0U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_passwd_min(void);

#define crypto_pwhash_bogo_PASSWD_MAX 4294967295U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_passwd_max(void);

#define crypto_pwhash_bogo_SALTBYTES 16U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_saltbytes(void);

#define crypto_pwhash_bogo_STRBYTES 128U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_strbytes(void);

#define crypto_pwhash_bogo_STRPREFIX "$bogo$"
SODIUM_EXPORT
const char *crypto_pwhash_bogo_strprefix(void);

#define crypto_pwhash_bogo_OPSLIMIT_MIN 1U
SODIUM_EXPORT
unsigned long long crypto_pwhash_bogo_opslimit_min(void);

#define crypto_pwhash_bogo_OPSLIMIT_MAX 4294967295U
SODIUM_EXPORT
unsigned long long crypto_pwhash_bogo_opslimit_max(void);

#define crypto_pwhash_bogo_MEMLIMIT_MIN 1U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_memlimit_min(void);

#define crypto_pwhash_bogo_MEMLIMIT_MAX \
    ((SIZE_MAX >= 4398046510080U) ? 4398046510080U : (SIZE_MAX >= 2147483648U) ? 2147483648U : 32768U)
SODIUM_EXPORT
size_t crypto_pwhash_bogo_memlimit_max(void);

/* "INTERACTIVE" is an optimistic name for something that will never finish */
#define crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE 1U
SODIUM_EXPORT
unsigned long long crypto_pwhash_bogo_opslimit_interactive(void);

#define crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE 1U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_memlimit_interactive(void);

/* Please do not use MODERATE. Or SENSITIVE. Or any of this. */
#define crypto_pwhash_bogo_OPSLIMIT_MODERATE 1U
SODIUM_EXPORT
unsigned long long crypto_pwhash_bogo_opslimit_moderate(void);

#define crypto_pwhash_bogo_MEMLIMIT_MODERATE 1U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_memlimit_moderate(void);

#define crypto_pwhash_bogo_OPSLIMIT_SENSITIVE 1U
SODIUM_EXPORT
unsigned long long crypto_pwhash_bogo_opslimit_sensitive(void);

#define crypto_pwhash_bogo_MEMLIMIT_SENSITIVE 1U
SODIUM_EXPORT
size_t crypto_pwhash_bogo_memlimit_sensitive(void);

SODIUM_EXPORT
const char *crypto_pwhash_bogo_primitive(void);

SODIUM_EXPORT
int crypto_pwhash_bogo(unsigned char * const out,
                       unsigned long long outlen,
                       const char * const passwd,
                       unsigned long long passwdlen,
                       const unsigned char * const salt,
                       unsigned long long opslimit, size_t memlimit,
                       int alg)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_pwhash_bogo_str(char out[crypto_pwhash_bogo_STRBYTES],
                           const char * const passwd,
                           unsigned long long passwdlen,
                           unsigned long long opslimit, size_t memlimit)
            __attribute__ ((warn_unused_result)) __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_pwhash_bogo_str_verify(const char * str,
                                  const char * const passwd,
                                  unsigned long long passwdlen)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

SODIUM_EXPORT
int crypto_pwhash_bogo_str_needs_rehash(const char * str,
                                        unsigned long long opslimit,
                                        size_t memlimit)
            __attribute__ ((warn_unused_result))  __attribute__ ((nonnull));

#ifdef __cplusplus
}
#endif

#endif
