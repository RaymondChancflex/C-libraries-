/*
Copyright 2014-2015 Coinfloor LTD.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "libecp.h"

#include "ecp.h"


#ifdef _WIN32
#include <malloc.h>
#define ALLOCA _alloca
#else
#include <alloca.h>
#define ALLOCA alloca
#endif

#pragma GCC visibility push(default)

void ecp_pubkey_u8(uint8_t Q[], const uint8_t p[], const uint8_t a[], const uint8_t G[], const uint8_t d[], size_t l) {
    mp_limb_t* p_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* a_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* G_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l) * 3);
    mp_limb_t* d_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    bytes_to_mpn(p_, p, l);
    bytes_to_mpn(a_, a, l);
    bytes_to_mpn(&G_[MP_NLIMBS(l) * 0], &G[0], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 1], &G[l], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 2], &G[l * 2], l);
    bytes_to_mpn(d_, d, l);
    mp_limb_t* Q_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l) * 3);
    ecp_pubkey(Q_, p_, a_, G_, d_, MP_NLIMBS(l));
    mpn_to_bytes(&Q[0], &Q_[0 * MP_NLIMBS(l)], l), mpn_to_bytes(&Q[l], &Q_[1 * MP_NLIMBS(l)], l), mpn_to_bytes(&Q[l * 2], &Q_[2 * MP_NLIMBS(l)], l);
}

void ecp_sign_u8(uint8_t r[], uint8_t s[], const uint8_t p[], const uint8_t a[], const uint8_t G[], const uint8_t n[], const uint8_t d[], const uint8_t z[], size_t l) {
    mp_limb_t* p_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* a_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* G_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l) * 3);
    mp_limb_t* n_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* d_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* z_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    bytes_to_mpn(p_, p, l);
    bytes_to_mpn(a_, a, l);
    bytes_to_mpn(&G_[MP_NLIMBS(l) * 0], &G[0], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 1], &G[l], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 2], &G[l * 2], l);
    bytes_to_mpn(n_, n, l);
    bytes_to_mpn(d_, d, l);
    bytes_to_mpn(z_, z, l);
    mp_limb_t* r_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* s_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    ecp_sign(r_, s_, p_, a_, G_, n_, d_, z_, MP_NLIMBS(l));
    mpn_to_bytes(r, r_, l);
    mpn_to_bytes(s, s_, l);
}

bool ecp_verify_u8(const uint8_t p[], const uint8_t a[], const uint8_t G[], const uint8_t n[], const uint8_t Q[], const uint8_t z[], const uint8_t r[], const uint8_t s[], size_t l) {
    mp_limb_t* p_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* a_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* G_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l) * 3);
    mp_limb_t* n_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* Q_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l) * 3);
    mp_limb_t* z_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* r_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    mp_limb_t* s_ = (mp_limb_t*)ALLOCA(sizeof(mp_limb_t) * MP_NLIMBS(l));
    bytes_to_mpn(p_, p, l);
    bytes_to_mpn(a_, a, l);
    bytes_to_mpn(&G_[MP_NLIMBS(l) * 0], &G[0], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 1], &G[l], l), bytes_to_mpn(&G_[MP_NLIMBS(l) * 2], &G[l * 2], l);
    bytes_to_mpn(n_, n, l);
    bytes_to_mpn(&Q_[MP_NLIMBS(l) * 0], &Q[0], l), bytes_to_mpn(&Q_[MP_NLIMBS(l) * 1], &Q[l], l), bytes_to_mpn(&Q_[MP_NLIMBS(l) * 2], &Q[l * 2], l);
    bytes_to_mpn(z_, z, l);
    bytes_to_mpn(r_, r, l);
    bytes_to_mpn(s_, s, l);
    return ecp_verify(p_, a_, G_, n_, Q_, z_, r_, s_, MP_NLIMBS(l));
}

#pragma GCC visibility pop
