# CUDA Fatbin Decompression

This projects decompressed CUDA fatbins that were compressed by `nvcc`, e.g., by using the `-Xfatbin --compress-all` flag.

Usage:
```
decompress <compressed fatbin file> [<uncompressed fatbin compare file>]
```

The first parameter should reference a file containing a compressed CUDA fatbin. This can be exported from a binary containing CUDA code using:
```
objcopy -O binary --only-section=.nv_fatbin <input> <output>
```
The program optionally uses the second paramter to compare the decompressed file to an uncompressed version of the first file to check if the output
matches that of nvcc. To obtain an uncompressed CUDA fatbin use the nvcc flag `-no-compress`.

The project is licensed under Apache License 2.0

Copyright 2023 Niklas Eiling <niklas.eiling@rwth-aachen.de>
