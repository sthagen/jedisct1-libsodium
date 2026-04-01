
#define TEST_NAME "pwhash_bogo"
#include "cmptest.h"

/* WARNING: This tests a joke API. Do not use crypto_pwhash_bogo for anything. */

int
main(void)
{
    unsigned char  out[32];
    unsigned char  salt[crypto_pwhash_bogo_SALTBYTES];
    char           str_out[crypto_pwhash_bogo_STRBYTES];
    const char    *sorted_passwd = "abcdef";
    const char    *unsorted_passwd = "fedcba";
    size_t         i;
    int            ret;

    memset(salt, 0x42, sizeof salt);

    /* Test 1: accessor functions return expected values */
    printf("alg_default: %d\n", crypto_pwhash_bogo_alg_default());
    printf("bytes_min: %u\n", (unsigned int) crypto_pwhash_bogo_bytes_min());
    printf("saltbytes: %u\n", (unsigned int) crypto_pwhash_bogo_saltbytes());
    printf("strbytes: %u\n", (unsigned int) crypto_pwhash_bogo_strbytes());
    printf("strprefix: %s\n", crypto_pwhash_bogo_strprefix());
    printf("primitive: %s\n", crypto_pwhash_bogo_primitive());

    /* Test 2: pre-sorted password succeeds immediately */
    ret = crypto_pwhash_bogo(out, sizeof out, sorted_passwd,
                             strlen(sorted_passwd), salt,
                             crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_ALG_DEFAULT);
    printf("sorted password: %d\n", ret);
    if (ret == 0) {
        for (i = 0; i < sizeof out; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");
    }

    /* Test 3: empty password succeeds (trivially sorted) */
    ret = crypto_pwhash_bogo(out, sizeof out, "", 0U, salt,
                             crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_ALG_DEFAULT);
    printf("empty password: %d\n", ret);
    if (ret == 0) {
        for (i = 0; i < sizeof out; i++) {
            printf("%02x", out[i]);
        }
        printf("\n");
    }

    /* Test 4: single-byte password succeeds (trivially sorted) */
    ret = crypto_pwhash_bogo(out, sizeof out, "x", 1U, salt,
                             crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_ALG_DEFAULT);
    printf("single byte: %d\n", ret);

    /* Test 5: repeated-byte password succeeds (always sorted) */
    ret = crypto_pwhash_bogo(out, sizeof out, "aaaa", 4U, salt,
                             crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE,
                             crypto_pwhash_bogo_ALG_DEFAULT);
    printf("repeated bytes: %d\n", ret);

    /* Test 6: reverse-sorted long password fails (6! = 720, but cap is 10000 -
     * however this is random, so we test with a much longer password to ensure failure) */
    {
        const char *long_unsorted = "zyxwvutsrqponmlkjihgfedcba";
        ret = crypto_pwhash_bogo(out, sizeof out, long_unsorted,
                                 strlen(long_unsorted), salt,
                                 crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                                 crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE,
                                 crypto_pwhash_bogo_ALG_DEFAULT);
        printf("long unsorted password: %d\n", ret);
    }

    /* Test 7: invalid algorithm */
    ret = crypto_pwhash_bogo(out, sizeof out, sorted_passwd,
                             strlen(sorted_passwd), salt, 1U, 1U, 42);
    printf("invalid alg: %d\n", ret);

    /* Test 8: output too short */
    ret = crypto_pwhash_bogo(out, crypto_pwhash_bogo_BYTES_MIN - 1U,
                             sorted_passwd, strlen(sorted_passwd), salt,
                             1U, 1U, crypto_pwhash_bogo_ALG_DEFAULT);
    printf("output too short: %d\n", ret);

    /* Test 9: str and str_verify with pre-sorted password */
    ret = crypto_pwhash_bogo_str(str_out, sorted_passwd,
                                 strlen(sorted_passwd),
                                 crypto_pwhash_bogo_OPSLIMIT_INTERACTIVE,
                                 crypto_pwhash_bogo_MEMLIMIT_INTERACTIVE);
    printf("str: %d\n", ret);
    if (ret == 0) {
        printf("str starts with prefix: %d\n",
               strncmp(str_out, crypto_pwhash_bogo_STRPREFIX,
                       strlen(crypto_pwhash_bogo_STRPREFIX)) == 0);
        ret = crypto_pwhash_bogo_str_verify(str_out, sorted_passwd,
                                            strlen(sorted_passwd));
        printf("str_verify correct: %d\n", ret);
        ret = crypto_pwhash_bogo_str_verify(str_out, "wrong",
                                            strlen("wrong"));
        printf("str_verify wrong: %d\n", ret);
    }

    /* Test 10: str_needs_rehash always returns 1 */
    if (str_out[0] == '$') {
        ret = crypto_pwhash_bogo_str_needs_rehash(str_out, 1U, 1U);
        printf("needs_rehash: %d\n", ret);
    }

    /* Test 11: str_needs_rehash with wrong prefix */
    ret = crypto_pwhash_bogo_str_needs_rehash("$argon2id$garbage", 1U, 1U);
    printf("needs_rehash wrong prefix: %d\n", ret);

    return 0;
}
