/**
 * @file libcomp/src/CryptSupport.h
 * @ingroup libcomp
 *
 * @author COMP Omega <compomega@tutanota.com>
 *
 * @brief Support functions for older versions of OpenSSL.
 *
 * This file is part of the COMP_hack Library (libcomp).
 *
 * Copyright (C) 2012-2019 COMP_hack Team <compomega@tutanota.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIBCOMP_SRC_CRYPTSUPPORT_H
#define LIBCOMP_SRC_CRYPTSUPPORT_H

// OpenSSL Includes
#include <openssl/dh.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static inline void DH_get0_pqg(const DH *dh, const BIGNUM **p,
                               const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

static inline const BIGNUM* DH_get0_p(const DH *dh)
{
    return dh->p;
}

static inline const BIGNUM* DH_get0_q(const DH *dh)
{
    return dh->q;
}

static inline const BIGNUM* DH_get0_g(const DH *dh)
{
    return dh->g;
}

static inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

static inline void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
                               const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

static inline const BIGNUM* DH_get0_pub_key(const DH *dh)
{
    return dh->pub_key;
}

static inline const BIGNUM* DH_get0_priv_key(const DH *dh)
{
    return dh->priv_key;
}

static inline int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}

static inline int DH_set_length(DH *dh, long length)
{
    dh->length = length;
    return 1;
}

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L

#endif // LIBCOMP_SRC_CRYPTSUPPORT_H
