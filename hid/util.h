#pragma once
/*
 * Logging and miscellaneous utilities.
 */

#define logfilename "hid.log"

 /* Initialize utilities. */
void util_init();

 /* Deinitializes utilities. */
void util_uninit();

/* Writes a message to the log. */
void mlog(const char *format, ...);

/* Writes a message to the log. Accepts wide character strings. */
void mwlog(const wchar_t *format, ...);

/* Writes a hexdump of the given data to the log file. */
void hexdump(const void* data, size_t size);
