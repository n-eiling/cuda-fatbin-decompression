/** Test and demo decompression of nvcc fatbin files
 *
 * Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
 * SPDX-License-Identifier: Apache-2.0
 *********************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <sys/mman.h>
#include <sys/stat.h> 
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "fatbin-decompress.h"


void hexdump(uint8_t* data, size_t size)
{
    size_t pos = 0;
    while (pos < size) {
        printf("%#05zx: ", pos);
        for (int i = 0; i < 16; i++) {
            if (pos + i < size) {
                printf("%02x", data[pos + i]);
            } else {
                printf("  ");
            }
            if (i % 4 == 3) {
                printf(" ");
            }
        }
        printf(" | ");
        for (int i = 0; i < 16; i++) {
            if (pos + i < size) {
                if (data[pos + i] >= 0x20 && data[pos + i] <= 0x7e) {
                    printf("%c", data[pos + i]);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");
            }
        }
        printf("\n");
        pos += 16;
    }
}

int compare_to_file(const char* filename, const uint8_t* data, size_t size)
{
    FILE *fp;
    size_t i;
    uint8_t c;

    if ((fp = fopen(filename, "rb")) == NULL) {
        fprintf(stderr, "Error opening file: %s", strerror(errno));
        return 1;
    }

    for (i = 0; i < size; i++) {
        if ((c = fgetc(fp)) == EOF) {
            printf("EOF reached\n");
            break;
        }
        if (c != data[i]) {
            fprintf(stderr, "Data mismatch at offset %#0zx: %#0x != %#0x\n", i, c, data[i]);
            return 1;
        }
    }

    fclose(fp);

    return 0;
}

int main(int argc, char *argv[])
{
    int fd;
    struct stat st;
    uint8_t *data;
    uint8_t output[0x10000];
    size_t outsize;
    size_t size;
    int compare = 0;

    if (argc < 2 || argc > 3) {
        printf("Usage: %s <file>", argv[0]);
        return 1;
    }

    if (argc == 3) {
        compare = 1;
    }

    if ((fd = open(argv[1], O_RDONLY)) == -1) {
        printf("Error opening file: %s", strerror(errno));
        return 1;
    }

    if (fstat(fd, &st) == -1) {
        printf("Error getting file size: %s", strerror(errno));
        return 1;
    }

    printf("File size: %#0zx\n", st.st_size);

    if ((data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
        printf("Error mapping file: %s", strerror(errno));
        return 1;
    }

    size = st.st_size;

    hexdump(data, size);

    if ((outsize = decompress(data, size, output, sizeof(output))) == 0) {
        printf("Decompression failed");
        return 1;
    }

    hexdump(output, outsize);

    if (compare) {
        if (compare_to_file(argv[2], output, outsize) != 0) {
            printf("Data mismatch");
            return 1;
        }
    }

    return 0;
}