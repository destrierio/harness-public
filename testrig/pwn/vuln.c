/* A deliberately vulnerable ret2win target for the pwn end-to-end proof.
   read() overflows a 64-byte buffer; win() prints the flag. No stack protector,
   no PIE, so the exploit is deterministic. */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    char b[128];
    FILE *f = fopen("/workspace/flag.txt", "r");
    if (f) { if (fgets(b, sizeof b, f)) fputs(b, stdout); fclose(f); }
    else { puts("no flag file"); }
    fflush(stdout);
}

int main(void) {
    char buf[64];
    setvbuf(stdout, 0, 2, 0);
    puts("name?");
    read(0, buf, 256);   /* overflow: 64-byte buffer */
    puts("bye");
    return 0;
}
