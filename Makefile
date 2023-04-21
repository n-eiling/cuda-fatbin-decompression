# Makefile
#
# Author: Niklas Eiling <niklas.eiling@rwth-aachen.de>
# SPDX-FileCopyrightText: 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
# SPDX-License-Identifier: Apache-2.0
################################################################################


CC = gcc
LD = gcc
CFLAGS = -Wall -std=gnu99 -g -ggdb

BINARY = decompress
SAMPLES = samples-bin/matrixMul.compressed.fatbin \
		  samples-bin/matrixMul.uncompressed.fatbin \
		  samples-bin/nbody.uncompressed.fatbin \
		  samples-bin/nbody.compressed.fatbin



FILES := main.o fatbin-decompress.o utils.o

CUDA_PATH = /opt/cuda
NVCC = ${CUDA_PATH}/bin/nvcc
SMS = 75 60
CUDA_SAMPLES_RELEASE = 12.1
CUDA_SAMPLES_URL = https://github.com/NVIDIA/cuda-samples/archive/refs/tags/v${CUDA_SAMPLES_RELEASE}.tar.gz


.PHONY: all clean tests
all : $(BINARY)

%.o : %.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(BINARY) : $(FILES)
	$(LD) $(LDFLAGS) -o $@ $^

tests: $(SAMPLES)

samples:
	mkdir -p $@
	wget ${CUDA_SAMPLES_URL} -O - | tar -xz --strip-components=1 -C $@

samples-bin:
	mkdir -p $@

samples-bin/nbody.uncompressed.sample : samples samples-bin
	make -C samples/Samples/5_Domain_Specific/nbody \
		clean
	make -C samples/Samples/5_Domain_Specific/nbody \
		NVCCFLAGS="--no-compress" \
		SMS="${SMS}" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/5_Domain_Specific/nbody/nbody $@

samples-bin/nbody.compressed.sample : samples samples-bin
	make -C samples/Samples/5_Domain_Specific/nbody \
		clean
	make -C samples/Samples/5_Domain_Specific/nbody \
		NVCCFLAGS="-Xfatbin --compress-all" \
		SMS="${SMS}" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/5_Domain_Specific/nbody/nbody $@

samples-bin/matrixMul.compressed.sample : samples samples-bin
	make -C samples/Samples/0_Introduction/matrixMul \
		clean
	make -C samples/Samples/0_Introduction/matrixMul \
		NVCCFLAGS="-Xfatbin --compress-all" \
		SMS="${SMS}" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/0_Introduction/matrixMul/matrixMul $@

samples-bin/matrixMul.uncompressed.sample : samples samples-bin
	make -C samples/Samples/0_Introduction/matrixMul \
		clean
	make -C samples/Samples/0_Introduction/matrixMul \
		NVCCFLAGS="--no-compress" \
		SMS="${SMS}" \
		CPATH="samples/Common" \
		CUDA_PATH=${CUDA_PATH}
	cp samples/Samples/0_Introduction/matrixMul/matrixMul $@

samples-bin/%.fatbin : samples-bin/%.sample
	objcopy -O binary --only-section=.nv_fatbin $< $@

clean :
	rm -f *.o *.d .depend *~ $(BINARY) matrixMul matrixMul.fatbin samples-bin/*