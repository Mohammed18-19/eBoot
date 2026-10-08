// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EoS Project

/**
 * @file eos_production_key.h
 * @brief The compiled-in production trust anchor.
 *
 * Defined by a translation unit that cmake/ProductionKey.cmake generates from
 * EBLDR_PRODUCTION_KEY, and compiled into eboot_core only when that option is
 * set. core/keystore.c uses it in place of the RFC 8032 development key for a
 * board that has no OTP to read a key from.
 */

#ifndef EOS_PRODUCTION_KEY_H
#define EOS_PRODUCTION_KEY_H

#include <stdint.h>
#include "eos_keystore.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const uint8_t ebldr_production_key[EOS_ED25519_PUB_KEY_SIZE];

#ifdef __cplusplus
}
#endif

#endif /* EOS_PRODUCTION_KEY_H */
