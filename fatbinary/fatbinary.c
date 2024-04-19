#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

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

typedef  struct  __attribute__((__packed__)) 
{
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint64_t size;
} fat_elf_header;
typedef struct  __attribute__((__packed__)) 
{
    uint16_t kind;
    uint16_t unknown1;
    uint32_t header_size;
    uint64_t size;
    uint32_t compressed_size;       // Size of compressed data
    uint32_t unknown2;              // Address size for PTX?
    uint16_t minor;
    uint16_t major;
    uint32_t arch;
    uint32_t obj_name_offset;
    uint32_t obj_name_len;
    uint64_t flags;
    uint64_t zero;                  // Alignment for compression?
    uint64_t decompressed_size;     // Length of compressed data in decompressed representation.
                                    // There is an uncompressed footer so this is generally smaller
                                    // than size.
} fat_text_header;

static void print_header(fat_text_header *th)
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
void hexdump(const uint8_t* data, size_t size)
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

/** Decompresses a fatbin file
 * @param input Pointer compressed input data
 * @param input_size Size of compressed data
 * @param output preallocated memory where decompressed output should be stored
 * @param output_size size of output buffer. Should be equal to the size of the decompressed data
 */
size_t decompress(const uint8_t* input, size_t input_size, uint8_t* output, size_t output_size)
{
    size_t ipos = 0, opos = 0;  
    uint64_t next_nclen;  // length of next non-compressed segment
    uint64_t next_clen;   // length of next compressed segment
    uint64_t back_offset; // negative offset where redudant data is located, relative to current opos

    while (ipos < input_size) {
        next_nclen = (input[ipos] & 0xf0) >> 4;
        next_clen = 4 + (input[ipos] & 0xf);
        if (next_nclen == 0xf) {
            do {
                next_nclen += input[++ipos];
            } while (input[ipos] == 0xff);
        }
        
        if (memcpy(output + opos, input + (++ipos), next_nclen) == NULL) {
            fprintf(stderr, "Error copying data");
            return 0;
        }
#ifdef FATBIN_DECOMPRESS_DEBUG
        printf("%#04zx/%#04zx nocompress (len:%#zx):\n", opos, ipos, next_nclen);
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
        printf("%#04zx/%#04zx compress (decompressed len: %#zx, back_offset %#zx):\n", opos, ipos, next_clen, back_offset);
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




int main(int argc, char *argv[]){
    if (argc!=2){
        printf("uasge: ./fatbinary $input_fatbin\n");
        return -3;
    }
    FILE *fp=fopen(argv[1],"r");
    if (fp==NULL){
        printf("cant open file %s\n", argv[1]);
        return 1;
    }
    fat_elf_header fatheader;
    fat_text_header  fatTextHeader;
    int re;
    char filename[32];
    int seq=0;
    uint8_t buf[128];
    while (!feof(fp))
    {
        ++seq;
        re = fread(&fatheader, 1, sizeof(fat_elf_header), fp);
        if (!re){
            printf("FINISH!\n");
            return 0;
        } else if (re!=sizeof(fat_elf_header)){
            printf("read FATHeader error, only %d byte left\n", re);
            return -2;
        }
        printf("\n%d: fatbin is 0x%lx, header is 0x%x\n", seq, fatheader.size, fatheader.header_size);

        int acclen=0;
        while (acclen<fatheader.size)
        {
            re = fread(&fatTextHeader, sizeof(fat_text_header), 1, fp);
            if (re!=1){
                printf("read fat_text_header error\n");
                return -2;
            }
            if (sizeof(fat_text_header) < fatTextHeader.header_size){
                printf("Seg header 0x%x, read more\n", fatTextHeader.header_size);
                re = fread(buf, fatTextHeader.header_size-sizeof(fat_text_header), 1, fp);
                if (re!=1){
                    printf("read more header error\n");
                    return -2;
                }
            }
            if (fatTextHeader.kind==2){
                printf("ELF file, header len 0x%x, file len 0x%lx\n",fatTextHeader.header_size, 
                    fatTextHeader.size );
                sprintf(filename,"fat%d.elf",seq);
                FILE *fout=fopen(filename,"wb");
                if (fout==NULL){
                    printf("cant open %s\n",filename);
                    return -2;
                }
                void * buf ;
                buf = malloc(fatTextHeader.size );
                re = fread(buf,fatTextHeader.size ,1,fp);
                if (re!=1){
                    printf("read content error for seq%d\n",seq);
                    return -3;
                }
                re = fwrite(buf,fatTextHeader.size,1,fout);
                if (re!=1){
                    printf("write content error for seq%d\n",seq);
                    return -4;
                }
                free(buf);
                fclose(fout);

            } else if (fatTextHeader.kind==1) {
                printf("PTX file, header len 0x%x, file len 0x%lx\n",fatTextHeader.header_size, 
                    fatTextHeader.size );
                sprintf(filename,"PTX%d.txt",seq);
                FILE *fout=fopen(filename,"wb");
                if (fout==NULL){
                    printf("cant open %s\n",filename);
                    return -2;
                }

                void * inbuf ;
                void * outbuf ;
                inbuf = malloc(fatTextHeader.size );

                re = fread(inbuf, fatTextHeader.size, 1, fp);
                if (re!=1){
                    printf("read content error for seq%d\n",seq);
                    return -3;
                }

                if (fatTextHeader.flags & FATBIN_FLAG_COMPRESS){
                    outbuf = malloc(fatTextHeader.decompressed_size);
                    printf("compress size is 0x%x, decompress size is 0x%lx\n", 
                        fatTextHeader.compressed_size, fatTextHeader.decompressed_size);
                    decompress(inbuf, fatTextHeader.compressed_size, outbuf, fatTextHeader.decompressed_size);
                    re = fwrite(outbuf, fatTextHeader.decompressed_size, 1, fout);
                    if (re!=1){
                        printf("write PTX error for seq%d\n",seq);
                        return -4;
                    }
                } else {
                    outbuf = malloc(fatTextHeader.size);
                    memcpy(outbuf, inbuf, fatTextHeader.size);
                    re = fwrite(outbuf, fatTextHeader.size, 1, fout);
                    if (re!=1){
                       printf("write original PTX error for seq%d\n",seq);
                    return -4;
                    }
                }
                free(inbuf);
                free(outbuf);
                fclose(fout);
            
            }
            acclen+=fatTextHeader.header_size;
            acclen += fatTextHeader.size;
        }
    }

    fclose(fp);
    return 0;
}

// gcc fatbinary.c -o fatbinary