# fatbin 
## functions
- Read .nv_fatbin section, and split it to elf file and decompressed PTX files.
- Assume that there is CUDA file-- add.cu, you should run following steps:
```
nvcc add.cu
objcopy -O binary -j .nv_fatbin a.out a.fatbin
./fatbinary a.fatbin
```
- Then you will get all the ELF files and PTX files embedded in the .nv_fatbin section.

## notice
- Learn from https://github.com/n-eiling/cuda-fatbin-decompression
- This project works well with NVCC compiling result and works well with CLANG compiling result when the input is one CUDA file.
- PTX section header is 0x48 bytes long. But I don't know what the last byte works for.


