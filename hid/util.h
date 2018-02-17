/*
 * Logging and miscellaneous utilities.
 */
#pragma once
#include <string>

#define LOGFILENAME "hid.log"

#define WIDE1(x) L#x
#define WIDE(x) WIDE1(x)

 /* Initialize utilities. */
void util_init();

 /* Deinitializes utilities. */
void util_uninit();

/* Writes a hexdump of the given data to the log file. */
std::string hexdump(const void* data, size_t size);
