/** Decompress nvcc fatbin files
 *
 * Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************************/
#define _GNU_SOURCE

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
#define FATBIN_FLAG_64BIT     0x0000000000000001LL
#define FATBIN_FLAG_DEBUG     0x0000000000000002LL
#define FATBIN_FLAG_LINUX     0x0000000000000010LL
#define FATBIN_FLAG_COMPRESS  0x0000000000002000LL

static int flag_to_str(char** str, uint64_t flag)
{
    return asprintf(str, "64Bit: %s, Debug: %s, Linux: %s, Compress: %s",
        (flag & FATBIN_FLAG_64BIT) ? "yes" : "no",
        (flag & FATBIN_FLAG_DEBUG) ? "yes" : "no",
        (flag & FATBIN_FLAG_LINUX) ? "yes" : "no",
        (flag & FATBIN_FLAG_COMPRESS) ? "yes" : "no");
}

static void print_header(struct fat_text_header *th)
{
    char* flagstr = NULL;
    flag_to_str(&flagstr, th->flags);

    printf("text_header: fatbin_kind: %#x, header_size %#x, size %#zx, compressed_size %#x,\
 minor %#x, major %#x, arch %d, decompressed_size %#zx\n\tflags: %s\n",
        th->kind,
        th->header_size,
        th->size,
        th->compressed_size,
        th->minor,
        th->major,
        th->arch,
        th->decompressed_size,
        flagstr);
    printf("\tunknown fields: unknown1: %#x, unknown2: %#x, zeros: %#zx\n",
        th->unknown1,
        th->unknown2,
        th->zero);
}

/** Check the header of a fatbin
 * Performs some integrity checks and returns the elf header
 * @param fatbin_data Pointer to the fatbin data
 * @param fatbin_size Size of the fatbin data
 * @param decompressed_size Pointer to a variable that will be set to the size of the decompressed data
 * @param compressed_data Pointer to a variable that will be set to point to the compressed data
*/
static int get_elf_header(const uint8_t* fatbin_data, size_t fatbin_size, struct fat_elf_header **elf_header)
{
    struct fat_elf_header *eh = NULL;

    if (fatbin_data == NULL || elf_header == NULL) {
        fprintf(stderr, "Error: fatbin_data is NULL\n");
        return 1;
    }

    if (fatbin_size < sizeof(struct fat_elf_header)) {
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
    *elf_header = eh;
    return 0;
}

/** Check the text header of a fatbin
 * Performs some integrity checks and returns the text header
 * @param fatbin_data Pointer to the fatbin data
 * @param fatbin_size Size of the fatbin data
 * @param decompressed_size Pointer to a variable that will be set to the size of the decompressed data
 * @param compressed_data Pointer to a variable that will be set to point to the compressed data
*/
static int get_text_header(const uint8_t* fatbin_data, size_t fatbin_size, struct fat_text_header **text_header)
{
    struct fat_text_header *th = NULL;

    if (fatbin_data == NULL || text_header == NULL) {
        fprintf(stderr, "Error: fatbin_data is NULL\n");
        return 1;
    }

    if (fatbin_size < sizeof(struct fat_text_header)) {
        fprintf(stderr, "Error: fatbin_size is too small\n");
        return 1;
    }

    th = (struct fat_text_header*)fatbin_data;

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
    size_t eh_out_offset = 0;
    struct fat_elf_header *eh_out = NULL;
    struct fat_text_header *th = NULL;
    struct fat_text_header *th_out = NULL;
    const uint8_t *input_pos = fatbin_data;
    uint8_t zeroes[6] = {0};

    int i = 0;
    uint8_t *output = NULL;
    uint8_t *output_pos = NULL;
    size_t output_size = 0;
    size_t padding;

    if (fatbin_data == NULL || decompressed_data == NULL) {
        fprintf(stderr, "Error: fatbin_data is NULL\n");
        goto error;
    }

    while (input_pos < fatbin_data + fatbin_size) {
        if (get_elf_header(input_pos, fatbin_size - (input_pos - fatbin_data), &eh) != 0) {
            fprintf(stderr, "Something went wrong while checking the header.\n");
            goto error;
        }
        printf("elf header no. %d: magic: %#x, version: %#x, header_size: %#x, size: %#zx\n",
               i++, eh->magic, eh->version, eh->header_size, eh->size);
        input_pos += eh->header_size;
        eh_out = NULL;
        do {
            if (get_text_header(input_pos, fatbin_size - (input_pos - fatbin_data) - eh->header_size, &th) != 0) {
                fprintf(stderr, "Something went wrong while checking the header.\n");
                goto error;
            }
            print_header(th);
            input_pos += th->header_size;

            if ((output = realloc(output, output_size + th->decompressed_size + eh->header_size + th->header_size)) == NULL) {
                fprintf(stderr, "Error allocating memory of size %#zx for output buffer: %s\n", 
                        output_size + th->decompressed_size + eh->header_size + th->header_size, strerror(errno));
                goto error;
            }
            output_pos = output + output_size;
            output_size += th->decompressed_size + th->header_size;

            if (eh_out == NULL) {
                if (memcpy(output_pos, eh, eh->header_size) == NULL) {
                    fprintf(stderr, "Error copying data");
                    goto error;
                }
                eh_out = ((struct fat_elf_header*)output_pos);
                eh_out_offset = output_pos - output;
                eh_out->size = 0;
                output_pos += eh->header_size;
                output_size += eh->header_size;
            }
            eh_out = ((struct fat_elf_header*)(output + eh_out_offset));   // repair pointer in case realloc moved the buffer
            eh_out->size += th->decompressed_size + th->header_size;       // set size

            if (memcpy(output_pos, th, th->header_size) == NULL) {
                fprintf(stderr, "Error copying data");
                goto error;
            }
            th_out = ((struct fat_text_header*)output_pos);
            th_out->flags &= ~FATBIN_FLAG_COMPRESS;  // clear compressed flag
            th_out->compressed_size = 0;             // clear compressed size
            th_out->decompressed_size = 0;           // clear decompressed size
            th_out->size = th->decompressed_size;    // set size

            output_pos += th->header_size;

            if (decompress(input_pos, th->compressed_size, output_pos, th->decompressed_size) != th->decompressed_size) {
                fprintf(stderr, "Decompression failed\n");
                goto error;
            }

            input_pos += th->compressed_size;
            output_pos += th->decompressed_size;

            // if (input_pos != (uint8_t*)th + eh->size) {
            //     printf("There is %#zx bytes of data remaining\n", (uint8_t*)th + eh->size - input_pos);
            // }
         
            padding = ((8 -(size_t)input_pos) % 8);
            if (memcmp(input_pos, zeroes, padding) != 0) {
                printf("Error: expected %#zx zero bytes, got:\n", padding);
                hexdump(input_pos, 0x60);
                goto error;
            }
            input_pos += padding;

            padding = ((8 - (size_t)th->decompressed_size) % 8);
            // Because we always allocated enough memory for one more elf_header and this is smaller than
            // the maximal padding of 7, we do not have to reallocate here.
            memset(output_pos, 0, padding);
            output_size += padding;
            eh_out->size += padding;
            th_out->size += padding;

        } while (input_pos < (uint8_t*)eh + eh->header_size + eh->size);

        //printf("##### Decompressed data (size %#zx): #####\n", th->decompressed_size);
        //hexdump(output_pos, th->decompressed_size);
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
