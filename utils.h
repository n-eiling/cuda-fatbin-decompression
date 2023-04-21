/** Helper functions
 *
 * Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************************/

#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void hexdump(const uint8_t* data, size_t size);

#endif // UTILS_H