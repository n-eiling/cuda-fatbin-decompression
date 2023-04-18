# Makefile
#
# Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
# SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
# SPDX-License-Identifier: Apache-2.0
################################################################################


CC = gcc
LD = gcc
CFLAGS = -Wall -std=gnu99

BINARY = decompress

FILES := main.o fatbin-decompress.o utils.o

CUDA_PATH = /opt/cuda
NVCC = ${CUDA_PATH}/bin/nvcc
ARCH = sm_75
CUDA_SAMPLES_RELEASE = 12.1
CUDA_SAMPLES_URL = https://github.com/NVIDIA/cuda-samples/archive/refs/tags/v${CUDA_SAMPLES_RELEASE}.tar.gz


.PHONY: all clean 
all : $(BINARY)


%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY) : $(FILES)
	$(LD) $(LDFLAGS) -o $@ $^

samples:
	mkdir -p $@
	wget ${CUDA_SAMPLES_URL} -O - | tar -xz --strip-components=1 -C $@

matrixMul.compressed : samples
	make -C samples/Samples/0_Introduction/matrixMul \
		clean
	make -C samples/Samples/0_Introduction/matrixMul \
		NVCCFLAGS="-Xfatbin --compress-all" \
		GENCODE_FLAGS="-arch=$(ARCH)" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/0_Introduction/matrixMul/matrixMul ./matrixMul.compressed

matrixMul.uncompressed : samples
	make -C samples/Samples/0_Introduction/matrixMul \
		clean
	make -C samples/Samples/0_Introduction/matrixMul \
		NVCCFLAGS="--no-compress" \
		GENCODE_FLAGS="-arch=$(ARCH)" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/0_Introduction/matrixMul/matrixMul ./matrixMul.uncompressed

matrixMul.compressed.fatbin : matrixMul.compressed
	objcopy -O binary --only-section=.nv_fatbin $< $@

matrixMul.uncompressed.fatbin : matrixMul.uncompressed
	objcopy -O binary --only-section=.nv_fatbin $< $@

clean :
	rm -f *.o *.d .depend *~ $(BINARY) matrixMul matrixMul.fatbin *.compressed *.uncompressed