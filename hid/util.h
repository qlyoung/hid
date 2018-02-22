/*
 * Logging and miscellaneous utilities.
 */
#pragma once
#include <string>

#define LOGFILENAME "hid.log"

#define WIDE1(x) L#x
#define WIDE(x) WIDE1(x)

#define GUID2STR(buf, buflen, guid) \
	snprintf(buf, buflen, \
		 "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX", \
		 guid##->Data1, guid##->Data2, guid##->Data3, \
		 guid##->Data4[0], guid##->Data4[1], \
		 guid##->Data4[2], guid##->Data4[3], \
		 guid##->Data4[4], guid##->Data4[5], \
		 guid##->Data4[6], guid##->Data4[7]);

/* Initialize utilities. */
void util_init();

/* Deinitializes utilities. */
void util_uninit();

/* Writes a hexdump of the given data to the log file. */
std::string hexdump(const void *data, size_t size);

/* Converts GUID to string. */
std::string guid2str(const GUID *guid);
