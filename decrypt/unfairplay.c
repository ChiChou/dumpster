#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define SWAP32(x) (((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24))

extern int mremap_encrypted(void*, size_t, uint32_t, uint32_t, uint32_t);

static int unprotect(int f, uint64_t fileoff, uint8_t *dupe, struct encryption_info_command_64 *info) {
    void *base = mmap(NULL, info->cryptsize, PROT_READ | PROT_EXEC, MAP_PRIVATE, f, fileoff + info->cryptoff);
    if (base == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    int error = mremap_encrypted(base, info->cryptsize, info->cryptid,
        CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL);
    if (error) {
        perror("mremap_encrypted");
        munmap(base, info->cryptsize);
        return 1;
    }

    memcpy(dupe + info->cryptoff, base, info->cryptsize);

    munmap(base, info->cryptsize);
    return 0;
}

static uint8_t* map(const char *path, bool mutable, size_t *size, int *descriptor) {
    int f = open(path, mutable ? O_RDWR : O_RDONLY);
    if (f < 0) {
        perror("open");
        return NULL;
    }

    struct stat s;
    if (fstat(f, &s) < 0) {
        perror("fstat");
        close(f);
        return NULL;
    }

    uint8_t *base = mmap(NULL, s.st_size, mutable ? PROT_READ | PROT_WRITE : PROT_READ,
        mutable ? MAP_SHARED : MAP_PRIVATE, f, 0);
    if (base == MAP_FAILED) {
        perror("mmap");
        close(f);
        return NULL;
    }

    *size = s.st_size;
    if (descriptor) {
        *descriptor = f;
    } else {
        close(f);
    }
    return base;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s src dest\n", argv[0]);
        return 1;
    }

    size_t base_size;
    int f;
    uint8_t *base = map(argv[1], false, &base_size, &f);
    if (base == NULL) {
        return 1;
    }

    if (clonefile(argv[1], argv[2], 0) != 0) {
        perror("clonefile");
        munmap(base, base_size);
        close(f);
        return 1;
    }

    size_t dupe_size;
    uint8_t *dupe = map(argv[2], true, &dupe_size, NULL);
    if (dupe == NULL) {
        munmap(base, base_size);
        return 1;
    }

    // If the files are not of the same size, then they are not duplicates of
    // each other, which is an error.
    //
    if (base_size != dupe_size) {
        munmap(base, base_size);
        munmap(dupe, dupe_size);
        return 1;
    }

    uint8_t *real_base = base;
    size_t real_base_size = base_size;
    uint8_t *real_dupe = dupe;
    size_t real_dupe_size = dupe_size;

    uint64_t fileoff = 0;
    if(*(uint32_t*)base == FAT_CIGAM)
    {
        struct fat_header *fh = (struct fat_header*)base;
        struct fat_arch *arch = (struct fat_arch*)(fh + 1);
        for(size_t i = 0; i < SWAP32(fh->nfat_arch); ++i)
        {
            if(SWAP32(arch[i].cputype) == CPU_TYPE_ARM64 && SWAP32(arch[i].cpusubtype) == CPU_SUBTYPE_ARM64_ALL)
            {
                uint32_t offset = SWAP32(arch[i].offset);
                uint32_t size = SWAP32(arch[i].size);
                assert(offset < base_size);
                assert(size <= base_size - offset);
                base += offset;
                dupe += offset;
                base_size = size;
                dupe_size = size;
                fileoff = offset;
                break;
            }
        }
        if(!fileoff)
        {
            fprintf(stderr, "error: no arm64 slice found\n");
            return 1;
        }
    }

    struct mach_header_64* header = (struct mach_header_64*) base;
    assert(header->magic == MH_MAGIC_64);
    assert(header->cputype == CPU_TYPE_ARM64);
    assert(header->cpusubtype == CPU_SUBTYPE_ARM64_ALL);

    // Warm up
    if (header->filetype == MH_EXECUTE) {
        pid_t pid;
        char *spawn_argv[] = {argv[1], NULL};
        if (posix_spawn(&pid, argv[1], NULL, NULL, spawn_argv, NULL) == 0) {
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
        }
    } else {
        dlopen(argv[1], RTLD_LAZY | RTLD_LOCAL);
    }

    uint32_t offset = sizeof(struct mach_header_64);

    // Enumerate all load commands and check for the encryption header, if found
    // start "unprotect"'ing the contents.
    //
    for (uint32_t i = 0; i < header->ncmds; i++) {
        struct load_command* command = (struct load_command*) (base + offset);

        if (command->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 *encryption_info =
                (struct encryption_info_command_64*) command;
            // If "unprotect"'ing is successful, then change the "cryptid" so that
            // the loader does not attempt to decrypt decrypted pages.
            //
            if (unprotect(f, fileoff, dupe, encryption_info) != 0) {
                fprintf(stderr, "error: failed to decrypt %s\n", argv[1]);
                munmap(real_base, real_base_size);
                munmap(real_dupe, real_dupe_size);
                close(f);
                return 1;
            }
            encryption_info = (struct encryption_info_command_64*) (dupe + offset);
            encryption_info->cryptid = 0;
            break;
        }

        offset += command->cmdsize;
    }

    munmap(real_base, real_base_size);
    munmap(real_dupe, real_dupe_size);
    close(f);

    puts(argv[2]);

    return 0;
}
