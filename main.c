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
#include <unistd.h>

#include "fatbin-decompress.h"
#include "utils.h"


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

struct mapped_file {
    int fd;
    uint8_t *data;
    size_t size;
};

int mf_open_file(const char *filename, struct mapped_file *mf)
{
    struct stat st;

    if (filename == NULL || mf == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        return 1;
    }

    if ((mf->fd = open(filename, O_RDONLY)) == -1) {
        fprintf(stderr, "Error opening file: %s\n", strerror(errno));
        return 1;
    }

    if (fstat(mf->fd, &st) == -1) {
        fprintf(stderr, "Error getting file size: %s\n", strerror(errno));
        return 1;
    }

    printf("File size: %#0zx\n", st.st_size);
    mf->size = st.st_size;

    if ((mf->data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, mf->fd, 0)) == MAP_FAILED) {
        fprintf(stderr, "Error mapping file: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

void mf_close(struct mapped_file *mf)
{
    if (mf == NULL) {
        return;
    }

    if (mf->data != NULL) {
        munmap(mf->data, mf->size);
    }
    mf->data = NULL;
    mf->size = 0;

    if (mf->fd != -1) {
        close(mf->fd);
    }
}

int main(int argc, char *argv[])
{
    struct mapped_file mf;
    const uint8_t *cur_file_pos;
    int i = 0;
    uint8_t *output = NULL;
    size_t output_size = 0;
    struct fat_elf_header *eh;
    struct fat_text_header *th;

    int compare = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    if (argc == 3) {
        compare = 1;
    }

    if (mf_open_file(argv[1], &mf) != 0) {
        fprintf(stderr, "Error opening mapped file: %s\n", strerror(errno));
        return 1;
    }

    printf("File size: %#0zx\n", mf.size);

    hexdump(mf.data, mf.size);

    cur_file_pos = mf.data;
    while (cur_file_pos < mf.data + mf.size) {
        printf("##### .text section no. %d: #####\n", i++);
        if (get_header(cur_file_pos, mf.size - (cur_file_pos - mf.data), &eh, &th) != 0) {
            fprintf(stderr, "Something went wrong while checking the header.\n");
            return 1;
        }

        if ((output = realloc(output, output_size + th->decompressed_size)) == NULL) {
            fprintf(stderr, "Error allocating memory for output buffer: %s\n", strerror(errno));
            return 1;
        }

        if (decompress(cur_file_pos + eh->header_size + th->header_size,
                       th->compressed_size, output + output_size, th->decompressed_size) != th->decompressed_size) {
            fprintf(stderr, "Decompression failed\n");
            return 1;
        }

        printf("##### Decompressed data (size %#zx): #####\n", th->decompressed_size);
        hexdump(output + output_size, th->decompressed_size);

        output_size += th->decompressed_size;
        cur_file_pos += eh->size + eh->header_size;
    }

    if (compare) {
        if (compare_to_file(argv[2], output, output_size) != 0) {
            fprintf(stderr, "Data mismatch\n");
            return 1;
        }
    }

    mf_close(&mf);

    return 0;
}