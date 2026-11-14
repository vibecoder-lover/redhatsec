// RHSHelper — root helper di RedHatSec (pattern TrollStore: binario nel bundle).
// L'app lo spawna con persona uid 0 (entitlement com.apple.private.persona-mgmt);
// qui uid=0 → execve di /var/jb/usr/bin/sh -c <comando>. Se l'exec viene negata,
// stampa il motivo (EXECFAIL + errno) e esce 126 — diagnostica esplicita.
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

extern char **environ;

int main(int argc, char **argv) {
    fprintf(stderr, "[RHSHelper] uid=%d euid=%d\n", getuid(), geteuid());
    if (argc < 2) {
        fprintf(stderr, "uso: RHSHelper <comando sh>\n");
        return 2;
    }
    size_t n = 0;
    for (int i = 1; i < argc; i++) n += strlen(argv[i]) + 1;
    char *cmd = malloc(n + 1);
    if (!cmd) return 2;
    cmd[0] = 0;
    for (int i = 1; i < argc; i++) {
        strcat(cmd, argv[i]);
        if (i < argc - 1) strcat(cmd, " ");
    }

    char *sh = "/var/jb/usr/bin/sh";
    char *args[] = { sh, "-c", cmd, NULL };
    execve(sh, args, environ);
    fprintf(stderr, "EXECFAIL %s: %s (errno=%d)\n", sh, strerror(errno), errno);
    return 126;
}
