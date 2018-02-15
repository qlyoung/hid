#include "stdafx.h"

#include "util.h"
#include <stdio.h>

FILE *logfile;

void mwlog(const wchar_t *format, ...)
{
	va_list args;
	va_start(args, format);
	vfwprintf(logfile, format, args);
	va_end(args);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);
}

void mlog(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(logfile, format, args);
	va_end(args);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);
}

void hexdump(const void* data, size_t size)
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		fprintf(logfile, "%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void util_init()
{
	logfile = logfile ? logfile : fopen(logfilename, "w");
}

void util_uninit()
{
	if (logfile) {
		mlog("[!] === Closing log. ===");
		fflush(logfile);
		fclose(logfile);
	}

	logfile = NULL;
}
