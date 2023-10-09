/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/


#ifndef SECP256K1_ECDSA_IMPL_H
#define SECP256K1_ECDSA_IMPL_H

#include "scalar.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "ecdsa.h"

/** Group order for secp256k1 defined as 'n' in "Standards for Efficient Cryptography" (SEC2) 2.7.1
 *  $ sage -c 'load("secp256k1_params.sage"); print(hex(N))'
 *  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
 */
static const secp256k1_fe secp256k1_ecdsa_const_order_as_fe = SECP256K1_FE_CONST(
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
    0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL
);

/** Difference between field and order, values 'p' and 'n' values defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 *  $ sage -c 'load("secp256k1_params.sage"); print(hex(P-N))'
 *  0x14551231950b75fc4402da1722fc9baee
 */
static const secp256k1_fe secp256k1_ecdsa_const_p_minus_order = SECP256K1_FE_CONST(
    0, 0, 0, 1, 0x45512319UL, 0x50B75FC4UL, 0x402DA172UL, 0x2FC9BAEEUL
);

static int secp256k1_der_read_len(size_t *len, const unsigned char **sigp, const unsigned char *sigend) {
    size_t lenleft;
    unsigned char b1;
    VERIFY_CHECK(len != NULL);
    *len = 0;
    if (*sigp >= sigend) {
        return 0;
    }
    b1 = *((*sigp)++);
    if (b1 == 0xFF) {
        /* X.690-0207 8.1.3.5.c the value 0xFF shall not be used. */
        return 0;
    }
    if ((b1 & 0x80) == 0) {
        /* X.690-0207 8.1.3.4 short form length octets */
        *len = b1;
        return 1;
    }
    if (b1 == 0x80) {
        /* Indefinite length is not allowed in DER. */
        return 0;
    }
    /* X.690-207 8.1.3.5 long form length octets */
    lenleft = b1 & 0x7F; /* lenleft is at least 1 */
    if (lenleft > (size_t)(sigend - *sigp)) {
        return 0;
    }
    if (**sigp == 0) {
        /* Not the shortest possible length encoding. */
        return 0;
    }
    if (lenleft > sizeof(size_t)) {
        /* The resulting length would exceed the range of a size_t, so
         * certainly longer than the passed array size.
         */
        return 0;
    }
    while (lenleft > 0) {
        *len = (*len << 8) | **sigp;
        (*sigp)++;
        lenleft--;
    }
    if (*len > (size_t)(sigend - *sigp)) {
        /* Result exceeds the length of the passed array. */
        return 0;
    }
    if (*len < 128) {
        /* Not the shortest possible length encoding. */
        return 0;
    }
    return 1;
}

static int secp256k1_der_parse_integer(secp256k1_scalar *r, const unsigned char **sig, const unsigned char *sigend) {
    int overflow = 0;
    unsigned char ra[32] = {0};
    size_t rlen;

    if (*sig == sigend || **sig != 0x02) {
        /* Not a primitive integer (X.690-0207 8.3.1). */
        return 0;
    }
    (*sig)++;
    if (secp256k1_der_read_len(&rlen, sig, sigend) == 0) {
        return 0;
    }
    if (rlen == 0 || rlen > (size_t)(sigend - *sig)) {
        /* Exceeds bounds or not at least length 1 (X.690-0207 8.3.1).  */
        return 0;
    }
    if (**sig == 0x00 && rlen > 1 && (((*sig)[1]) & 0x80) == 0x00) {
        /* Excessive 0x00 padding. */
        return 0;
    }
    if (**sig == 0xFF && rlen > 1 && (((*sig)[1]) & 0x80) == 0x80) {
        /* Excessive 0xFF padding. */
        return 0;
    }
    if ((**sig & 0x80) == 0x80) {
        /* Negative. */
        overflow = 1;
    }
    /* There is at most one leading zero byte:
     * if there were two leading zero bytes, we would have failed and returned 0
     * because of excessive 0x00 padding already. */
    if (rlen > 0 && **sig == 0) {
        /* Skip leading zero byte */
        rlen--;
        (*sig)++;
    }
    if (rlen > 32) {
        overflow = 1;
    }
    if (!overflow) {
        if (rlen) memcpy(ra + 32 - rlen, *sig, rlen);
        secp256k1_scalar_set_b32(r, ra, &overflow);
    }
    if (overflow) {
        secp256k1_scalar_set_int(r, 0);
    }
    (*sig) += rlen;
    return 1;
}

static int secp256k1_ecdsa_sig_parse(secp256k1_scalar *rr, secp256k1_scalar *rs, const unsigned char *sig, size_t size) {
    const unsigned char *sigend = sig + size;
    size_t rlen;
    if (sig == sigend || *(sig++) != 0x30) {
        /* The encoding doesn't start with a constructed sequence (X.690-0207 8.9.1). */
        return 0;
    }
    if (secp256k1_der_read_len(&rlen, &sig, sigend) == 0) {
        return 0;
    }
    if (rlen != (size_t)(sigend - sig)) {
        /* Tuple exceeds bounds or garage after tuple. */
        return 0;
    }

    if (!secp256k1_der_parse_integer(rr, &sig, sigend)) {
        return 0;
    }
    if (!secp256k1_der_parse_integer(rs, &sig, sigend)) {
        return 0;
    }

    if (sig != sigend) {
        /* Trailing garbage inside tuple. */
        return 0;
    }

    return 1;
}

static int secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const secp256k1_scalar* ar, const secp256k1_scalar* as) {
    unsigned char r[33] = {0}, s[33] = {0};
    unsigned char *rp = r, *sp = s;
    size_t lenR = 33, lenS = 33;
    secp256k1_scalar_get_b32(&r[1], ar);
    secp256k1_scalar_get_b32(&s[1], as);
    while (lenR > 1 && rp[0] == 0 && rp[1] < 0x80) { lenR--; rp++; }
    while (lenS > 1 && sp[0] == 0 && sp[1] < 0x80) { lenS--; sp++; }
    if (*size < 6+lenS+lenR) {
        *size = 6 + lenS + lenR;
        return 0;
    }
    *size = 6 + lenS + lenR;
    sig[0] = 0x30;
    sig[1] = 4 + lenS + lenR;
    sig[2] = 0x02;
    sig[3] = lenR;
    memcpy(sig+4, rp, lenR);
    sig[4+lenR] = 0x02;
    sig[5+lenR] = lenS;
    memcpy(sig+lenR+6, sp, lenS);
    return 1;
}

static int secp256k1_ecdsa_sig_verify(const secp256k1_scalar *sigr, const secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
    unsigned char c[32];
    secp256k1_scalar sn, u1, u2;
#if !defined(EXHAUSTIVE_TEST_ORDER)
    secp256k1_fe xr;
#endif
    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    secp256k1_scalar_inverse_var(&sn, sigs);
    secp256k1_scalar_mul(&u1, &sn, message);
    secp256k1_scalar_mul(&u2, &sn, sigr);
    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&pr, &pubkeyj, &u2, &u1);
    if (secp256k1_gej_is_infinity(&pr)) {
        return 0;
    }

#if defined(EXHAUSTIVE_TEST_ORDER)
{
    secp256k1_scalar computed_r;
    secp256k1_ge pr_ge;
    secp256k1_ge_set_gej(&pr_ge, &pr);
    secp256k1_fe_normalize(&pr_ge.x);

    secp256k1_fe_get_b32(c, &pr_ge.x);
    secp256k1_scalar_set_b32(&computed_r, c, NULL);
    return secp256k1_scalar_eq(sigr, &computed_r);
}
#else
    secp256k1_scalar_get_b32(c, sigr);
    /* we can ignore the fe_set_b32_limit return value, because we know the input is in range */
    (void)secp256k1_fe_set_b32_limit(&xr, c);

    /** We now have the recomputed R point in pr, and its claimed x coordinate (modulo n)
     *  in xr. Naively, we would extract the x coordinate from pr (requiring a inversion modulo p),
     *  compute the remainder modulo n, and compare it to xr. However:
     *
     *        xr == X(pr) mod n
     *    <=> exists h. (xr + h * n < p && xr + h * n == X(pr))
     *    [Since 2 * n > p, h can only be 0 or 1]
     *    <=> (xr == X(pr)) || (xr + n < p && xr + n == X(pr))
     *    [In Jacobian coordinates, X(pr) is pr.x / pr.z^2 mod p]
     *    <=> (xr == pr.x / pr.z^2 mod p) || (xr + n < p && xr + n == pr.x / pr.z^2 mod p)
     *    [Multiplying both sides of the equations by pr.z^2 mod p]
     *    <=> (xr * pr.z^2 mod p == pr.x) || (xr + n < p && (xr + n) * pr.z^2 mod p == pr.x)
     *
     *  Thus, we can avoid the inversion, but we have to check both cases separately.
     *  secp256k1_gej_eq_x implements the (xr * pr.z^2 mod p == pr.x) test.
     */
    if (secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* xr * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    if (secp256k1_fe_cmp_var(&xr, &secp256k1_ecdsa_const_p_minus_order) >= 0) {
        /* xr + n >= p, so we can skip testing the second case. */
        return 0;
    }
    secp256k1_fe_add(&xr, &secp256k1_ecdsa_const_order_as_fe);
    if (secp256k1_gej_eq_x_var(&xr, &pr)) {
        /* (xr + n) * pr.z^2 mod p == pr.x, so the signature is valid. */
        return 1;
    }
    return 0;
#endif
}

static int secp256k1_generate_stealth_J(const secp256k1_ecmult_gen_context* ctx, const unsigned char* stealthFactor, unsigned char* stealthResult) {
    secp256k1_gej rp;
    secp256k1_ge stealthPoint;
    secp256k1_scalar stealthResultScalar;
    int overflow = 0;
    secp256k1_scalar_set_b32(&stealthResultScalar, stealthFactor, &overflow);
    secp256k1_ecmult_gen(ctx, &rp, &stealthResultScalar);
    secp256k1_ge_set_gej(&stealthPoint, &rp);
    secp256k1_fe_normalize(&stealthPoint.x);
    secp256k1_fe_normalize(&stealthPoint.y);
    secp256k1_fe_get_b32(stealthResult, &stealthPoint.x);
    return 1;
}

static int secp256k1_ecdsa_verify_timestamped_r(const secp256k1_ecmult_gen_context* ctx, const unsigned char* dataHashPointer, const unsigned char* stealthFactor,
                                                const secp256k1_scalar* expectedR) {
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    sha.s[0] = 0x9cecba11ul;
    sha.s[1] = 0x23925381ul;
    sha.s[2] = 0x11679112ul;
    sha.s[3] = 0xd1627e0ful;
    sha.s[4] = 0x97c87550ul;
    sha.s[5] = 0x003cc765ul;
    sha.s[6] = 0x90f61164ul;
    sha.s[7] = 0x33e9b66aul;
    sha.bytes = 64;
    secp256k1_sha256_write(&sha, stealthFactor, 32);
    secp256k1_sha256_write(&sha, dataHashPointer, 32);
    unsigned char hash[32];
    secp256k1_sha256_finalize(&sha, hash);
    secp256k1_scalar hashResult;

    unsigned char bytes[32];
    secp256k1_gej rp;
    secp256k1_ge resultPoint;
    secp256k1_scalar visibleResult, sigr, stealthFactorScalar;
    int overflow = 0;

    secp256k1_scalar_set_b32(&hashResult, hash, &overflow);
    secp256k1_ecmult_gen(ctx, &rp, &hashResult);
    secp256k1_ge_set_gej(&resultPoint, &rp);
    secp256k1_fe_normalize(&resultPoint.x);
    secp256k1_fe_normalize(&resultPoint.y);
    secp256k1_fe_get_b32(bytes, &resultPoint.x);
    secp256k1_scalar_set_b32(&visibleResult, bytes, &overflow);
    secp256k1_scalar_set_b32(&stealthFactorScalar, stealthFactor, &overflow);
    secp256k1_scalar_add(&sigr, &stealthFactorScalar, &visibleResult);
    return secp256k1_scalar_eq(&sigr, expectedR);
}

static int secp256k1_generate_secure_k(const secp256k1_ecmult_gen_context* ctx, const unsigned char* j, unsigned char* stealthFactor, const unsigned char* dataHashPointer, unsigned char* k) {
    secp256k1_gej rp;
    secp256k1_ge stealthPoint;
    secp256k1_scalar jScalar;
    int overflow = 0;
    secp256k1_scalar_set_b32(&jScalar, j, &overflow);
    secp256k1_ecmult_gen(ctx, &rp, &jScalar);
    secp256k1_ge_set_gej(&stealthPoint, &rp);
    secp256k1_fe_normalize(&stealthPoint.x);
    secp256k1_fe_normalize(&stealthPoint.y);
    secp256k1_fe_get_b32(stealthFactor, &stealthPoint.x);
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    sha.s[0] = 0x9cecba11ul;
    sha.s[1] = 0x23925381ul;
    sha.s[2] = 0x11679112ul;
    sha.s[3] = 0xd1627e0ful;
    sha.s[4] = 0x97c87550ul;
    sha.s[5] = 0x003cc765ul;
    sha.s[6] = 0x90f61164ul;
    sha.s[7] = 0x33e9b66aul;
    sha.bytes = 64;
    secp256k1_sha256_write(&sha, stealthFactor, 32);
    secp256k1_sha256_write(&sha, dataHashPointer, 32);
    unsigned char hash[32];
    secp256k1_sha256_finalize(&sha, hash);
    secp256k1_scalar hashResult;
    secp256k1_scalar_set_b32(&hashResult, hash, &overflow);
    secp256k1_scalar secureK;
    secp256k1_scalar_add(&secureK, &jScalar, &hashResult);
    secp256k1_scalar_get_b32(k, &secureK);
    return 1;
}

static int secp256k1_ecdsa_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {
    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar n;
    int overflow = 0;
    int high;

    secp256k1_ecmult_gen(ctx, &rp, nonce);
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_normalize(&r.y);
    secp256k1_fe_get_b32(b, &r.x);
    secp256k1_scalar_set_b32(sigr, b, &overflow);
    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow << 1) | secp256k1_fe_is_odd(&r.y);
    }
    secp256k1_scalar_mul(&n, sigr, seckey);
    secp256k1_scalar_add(&n, &n, message);
    secp256k1_scalar_inverse(sigs, nonce);
    secp256k1_scalar_mul(sigs, sigs, &n);
    secp256k1_scalar_clear(&n);
    secp256k1_gej_clear(&rp);
    secp256k1_ge_clear(&r);
    high = secp256k1_scalar_is_high(sigs);
    secp256k1_scalar_cond_negate(sigs, high);
    if (recid) {
        *recid ^= high;
    }
    /* P.x = order is on the curve, so technically sig->r could end up being zero, which would be an invalid signature.
     * This is cryptographically unreachable as hitting it requires finding the discrete log of P.x = N.
     */
    return (int)(!secp256k1_scalar_is_zero(sigr)) & (int)(!secp256k1_scalar_is_zero(sigs));
}

#endif /* SECP256K1_ECDSA_IMPL_H */
