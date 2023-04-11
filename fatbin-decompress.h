/** Decompress nvcc fatbin files
 *
 * Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************************/

#ifndef __FATBIN_DECOMPRESS_H__
#define __FATBIN_DECOMPRESS_H__

#include <stdint.h>

size_t decompress(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size);

#endif // __FATBIN_DECOMPRESS_H__