/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2021 Google LLC. */

#ifndef LFSR_H
#define LFSR_H

#include <inttypes.h>

/* Linear Feedback shift register for number generation, up to 64 bits.
 *
 * x = lfsr(x, N) generates a sequence of (2^N - 1) different non-zero values.
 * x is the previous value. Valid N are 1..32 and 64.
 *
 * Constants are taken from
 * https://www.xilinx.com/support/documentation/application_notes/xapp052.pdf
 */

static inline uint64_t lfsr(uint64_t x, uint16_t order)
{
#define LFSR_ORDER_MASK 0x7f
        static const uint64_t lfsr_poly[] = {
                [1] = 1,
                [2] = 3,
                [3] = 6,
                [4] = 0xc,
                [5] = 0x14,
                [6] = 0x30,
                [7] = 0x60,
                [8] = 0xb4,
                [9] = 0x110,
                [10] = 0x240,
                [11] = 0x500,
                [12] = 0x829,
                [13] = 0x100d,
                [14] = 0x2015,
                [15] = 0x6000,
                [16] = 0xd008,
                [17] = 0x12000,
                [18] = 0x20400,
                [19] = 0x40023,
                [20] = 0x90000,
                [21] = 0x140000,
                [22] = 0x300000,
                [23] = 0x420000,
                [24] = 0xe1ULL << 16,
                [25] = 0x12ULL << 20,
                [26] = (0x1ULL << 25) | 0x23,
                [27] = (0x1ULL << 26) | 0x13,
                [28] = 0x9ULL << 24,
                [29] = 0x5ULL << 26,
                [30] = (0x1ULL << 29) | 0x29,
                [31] = 0x9ULL << 27,
                [32] = 0x80200003ULL,
                [64] = 0xd8ULL << 56,
                [LFSR_ORDER_MASK] = 0,
        };

        uint64_t lsb = x & 1, d1 = x >> 1;

        return d1 ^ ((-lsb) & lfsr_poly[order & LFSR_ORDER_MASK]);
#undef LFSR_ORDER_MASK
}
#endif /* LFSR_H */
