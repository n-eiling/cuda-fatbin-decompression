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

int compare_data(const uint8_t* data1, const uint8_t* data2, size_t size)
{
    int mismatch = 0;
    if (data1 == NULL || data2 == NULL) {
        fprintf(stderr, "Invalid arguments\n");
        return 1;
    }

    for (size_t i = 0; i < size; i++) {
        if (data1[i] != data2[i]) {
            fprintf(stderr, "Data mismatch at offset %#0zx: %#0x != %#0x\n", i, data1[i], data2[i]);
            mismatch++;
        }
    }
    if (mismatch > 0) {
        fprintf(stderr, "%d total mismatches\n", mismatch-30);
    }
    return (mismatch == 0 ? 0 : 1);
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
    uint8_t *output = NULL;
    size_t output_size = 0;

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

    printf("Compressed file size: %#0zx\n", mf.size);

    //hexdump(mf.data, mf.size);

    if ((output_size = decompress_fatbin(mf.data, mf.size, &output)) == 0) {
        fprintf(stderr, "Error decompressing fatbin\n");
        //return 1;
    }

    printf("Decompressed data size: %#0zx\n", output_size);
    //hexdump(output, output_size);

    if (compare) {
        struct mapped_file compare_file;
        if (mf_open_file(argv[2], &compare_file) != 0) {
            fprintf(stderr, "Error opening mapped file: %s\n", strerror(errno));
            return 1;
        }

        printf("Compare file size: %#0zx\n", compare_file.size);

        if (compare_file.size != output_size) {
            fprintf(stderr, "Data size mismatch: %#0zx != %#0zx\n", compare_file.size, output_size);
        }

        if (compare_data(compare_file.data, output, output_size) != 0) {
            fprintf(stderr, "Output data mismatches\n");
            return 1;
        }
        mf_close(&compare_file);
        printf("Data matches.\n");
    }

    mf_close(&mf);
    free(output);
    printf("success.\n");
    return 0;
}