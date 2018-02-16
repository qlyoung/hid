#include "stdafx.h"

#include "util.h"
#include <stdio.h>

/* global utility lock */
HANDLE ulock;
FILE *logfile;

void mwlog(const wchar_t *format, ...)
{
	WaitForSingleObject(ulock, INFINITE);

	va_list args;
	va_start(args, format);
	vfwprintf(logfile, format, args);
	va_end(args);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);

	ReleaseMutex(ulock);

}

void mlog(const char *format, ...)
{
	WaitForSingleObject(ulock, INFINITE);

	va_list args;
	va_start(args, format);
	vfprintf(logfile, format, args);
	va_end(args);
	fwrite("\n", 1, 1, logfile);
	fflush(logfile);

	ReleaseMutex(ulock);
}

void hexdump(const void* data, size_t size)
{
	WaitForSingleObject(ulock, INFINITE);

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
			fprintf(logfile, " ");
			if ((i + 1) % 16 == 0) {
				fprintf(logfile, "|  %s \n", ascii);
			}
			else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					fprintf(logfile, " ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					fprintf(logfile, "   ");
				}
				fprintf(logfile, "|  %s \n", ascii);
			}
		}
	}

	ReleaseMutex(ulock);
}

void util_init()
{
	logfile = logfile ? logfile : fopen(logfilename, "w");
	ulock = CreateMutex(NULL, FALSE, NULL);
}

void util_uninit()
{
	if (logfile) {
		mlog("[!] === Closing log. ===");
		fflush(logfile);
		fclose(logfile);
	}

	logfile = NULL;
	CloseHandle(ulock);
}
