/** Decompress nvcc fatbin files
 *
 * Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************************/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "fatbin-decompress.h"
#include "utils.h"

//#define FATBIN_DECOMPRESS_DEBUG 1

#define FATBIN_TEXT_MAGIC     0xBA55ED50
#define FATBIN_FLAG_DEBUG     0x0000000000000002LL
#define FATBIN_FLAG_COMPRESS  0x0000000000002000LL

/** Check the header of a fatbin
 * Performs some integrity checks, returns the size of the decompressed data and a pointer to the compressed data
 * @param fatbin_data Pointer to the fatbin data
 * @param fatbin_size Size of the fatbin data
 * @param decompressed_size Pointer to a variable that will be set to the size of the decompressed data
 * @param compressed_data Pointer to a variable that will be set to point to the compressed data
*/
int get_header(const uint8_t* fatbin_data, size_t fatbin_size, struct fat_elf_header **elf_header,
                 struct fat_text_header **text_header)
{
    struct fat_elf_header *eh = NULL;
    struct fat_text_header *th = NULL;

    if (fatbin_data == NULL || elf_header == NULL || text_header == NULL) {
        fprintf(stderr, "Error: fatbin_data is NULL\n");
        return 1;
    }

    if (fatbin_size < sizeof(struct fat_elf_header) + sizeof(struct fat_text_header)) {
        fprintf(stderr, "Error: fatbin_size is too small\n");
        return 1;
    }

    eh = (struct fat_elf_header*) fatbin_data;
    if (eh->magic != FATBIN_TEXT_MAGIC) {
        fprintf(stderr, "Error: Invalid magic  number: expected %#x but got %#x\n", FATBIN_TEXT_MAGIC, eh->magic);
        return 1;
    }

    if (eh->version != 1 || eh->header_size != sizeof(struct fat_elf_header)) {
        fprintf(stderr, "fatbin text version is wrong or header size is inconsistent.\
            This is a sanity check to avoid reading a new fatbinary format\n");
        return 1;
    }

    th = (struct fat_text_header*) (fatbin_data + eh->header_size);

    if (th->flags & FATBIN_FLAG_COMPRESS) {
        printf("note: fatbin is compressed.\n");
    }
    if (th->flags & FATBIN_FLAG_DEBUG) {
        printf("note: fatbin contains debug sybols.\n");
    }
    *elf_header = eh;
    *text_header = th;
    return 0;
}

/** Decompresses a fatbin file
 * @param input Pointer compressed input data
 * @param input_size Size of compressed data
 * @param output preallocated memory where decompressed output should be stored
 * @param output_size size of output buffer. Should be equal to the size of the decompressed data
 */
size_t decompress(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size)
{
    size_t ipos = 0, opos = 0;  
    uint16_t next_nclen;  // length of next non-compressed segment
    uint16_t next_clen;   // length of next compressed segment
    uint16_t back_offset; // negative offset where redudant data is located, relative to current opos

    while (ipos < input_size) {
        next_nclen = (input[ipos] & 0xf0) >> 4;
        next_clen = 4 + (input[ipos] & 0xf);
        if (next_nclen == 0xf) {
            next_nclen += input[++ipos];
        }
        
        if (memcpy(output + opos, input + (++ipos), next_nclen) == NULL) {
            fprintf(stderr, "Error copying data");
            return 0;
        }
#ifdef FATBIN_DECOMPRESS_DEBUG
        printf("%#04zx nocompress (len:%#x):\n", opos, next_nclen);
        hexdump(output + opos, next_nclen);
#endif
        ipos += next_nclen;
        opos += next_nclen;
        if (ipos >= input_size || opos >= output_size) {
            break;
        }
        back_offset = input[ipos] + (input[ipos + 1] << 8);       
        ipos += 2;
        if (next_clen == 0xf+4) {
            do {
                next_clen += input[ipos++];
            } while (input[ipos - 1] == 0xff);
        }
#ifdef FATBIN_DECOMPRESS_DEBUG
        printf("%#04zx compress (decompressed len: %#x, back_offset %#x):\n", opos, next_clen, back_offset);
#endif
        if (next_clen <= back_offset) {
            if (memcpy(output + opos, output + opos - back_offset, next_clen) == NULL) {
                fprintf(stderr, "Error copying data");
                return 0;
            }
        } else {
            if (memcpy(output + opos, output + opos - back_offset, back_offset) == NULL) {
                fprintf(stderr, "Error copying data");
                return 0;
            }
            for (size_t i = back_offset; i < next_clen; i++) {
                output[opos + i] = output[opos + i - back_offset];
            }
        }
#ifdef FATBIN_DECOMPRESS_DEBUG
        hexdump(output + opos, next_clen);
#endif
        opos += next_clen;
    }
    return opos;
}

size_t decompress_fatbin(const uint8_t* fatbin_data, size_t fatbin_size, uint8_t** decompressed_data)
{
    struct fat_elf_header *eh = NULL;
    struct fat_text_header *th = NULL;
    const uint8_t *input_pos = fatbin_data;

    int i = 0;
    uint8_t *output = NULL;
    uint8_t *output_pos = NULL;
    size_t output_size = 0;

    if (fatbin_data == NULL || decompressed_data == NULL) {
        fprintf(stderr, "Error: fatbin_data is NULL\n");
        goto error;
    }

    while (input_pos < fatbin_data + fatbin_size) {
        printf("##### .text section no. %d: #####\n", i++);
        if (get_header(input_pos, fatbin_size - (input_pos - fatbin_data), &eh, &th) != 0) {
            fprintf(stderr, "Something went wrong while checking the header.\n");
            goto error;
        }
        input_pos += eh->header_size + th->header_size;

        if ((output = realloc(output, output_size + th->decompressed_size + eh->header_size + th->header_size)) == NULL) {
            fprintf(stderr, "Error allocating memory for output buffer: %s\n", strerror(errno));
            goto error;
        }
        output_pos = output + output_size;
        output_size += th->decompressed_size + eh->header_size + th->header_size;

        if (memcpy(output_pos, eh, eh->header_size) == NULL) {
            fprintf(stderr, "Error copying data");
            goto error;
        }
        output_pos += eh->header_size;

        if (memcpy(output_pos, th, th->header_size) == NULL) {
            fprintf(stderr, "Error copying data");
            goto error;
        }
        ((struct fat_text_header*)output_pos)->flags &= ~FATBIN_FLAG_COMPRESS;  // clear compressed flag
        ((struct fat_text_header*)output_pos)->compressed_size = 0;             // clear compressed size
        ((struct fat_text_header*)output_pos)->decompressed_size = 0;           // clear decompressed size

        output_pos += th->header_size;

        if (decompress(input_pos, th->compressed_size, output_pos, th->decompressed_size) != th->decompressed_size) {
            fprintf(stderr, "Decompression failed\n");
            goto error;
        }

        printf("##### Decompressed data (size %#zx): #####\n", th->decompressed_size);
        hexdump(output_pos, th->decompressed_size);

        input_pos += eh->size - th->header_size;
    }

    *decompressed_data = output;
    return output_size;
 error:
    if (output != NULL) {
        free(output);
    }
    *decompressed_data = NULL;
    return 0;
}