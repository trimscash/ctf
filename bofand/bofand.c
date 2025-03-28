#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern char *fgets(char *buf, int n, FILE *fp);

int main() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	char (*f)(char *, int, FILE *) = fgets;
	char buf[0x80];
	printf("# hint! last 3 bytes of the gets addr: %4x\n", (unsigned long long)fgets & 0xffffff);

	for (int i = 0; i < 2; i++) {
		printf("# %d> ", i);
		f(buf, 0x90, stdin);
	}

	printf("# last chance!! >");
	f(buf, 0x90, stdin);

	printf("# bye!\n");
	exit(0);
	return 0;
}
