#include "stdafx.h"

#include "util.h"
#include "plog\Log.h"
#include <string>

std::string hexdump(const void *data, size_t size)
{
	std::string dump;
	char ascii[17];
	size_t i, j;
	char hexchar[4];

	ascii[16] = '\0';

	for (i = 0; i < size; ++i) {

		snprintf(hexchar, sizeof(hexchar), "%02X ", ((unsigned char *)data)[i]);
		dump.append(hexchar);

		if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char *)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			dump.append(" ");
			if ((i + 1) % 16 == 0) {
				dump.append("|  ");
				dump.append(ascii);
				dump.append(" \n");
			} else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					dump.append(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					dump.append("   ");
				}
				dump.append("|  ");
				dump.append(ascii);
				dump.append("\n");
			}
		}
	}

	return dump;
}

std::string guid2str(const GUID *guid)
{
	char buf[128];
	if (guid) {
		snprintf(buf, sizeof(buf),
		         "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
		         guid->Data1, guid->Data2, guid->Data3,
		         guid->Data4[0], guid->Data4[1],
		         guid->Data4[2], guid->Data4[3],
		         guid->Data4[4], guid->Data4[5],
		         guid->Data4[6], guid->Data4[7]);
	} else {
		snprintf(buf, sizeof(buf), "(NULL GUID)");
	}
	return std::string(buf);
}

void util_init()
{
	plog::init(plog::debug, LOGFILENAME);
}

void util_uninit()
{
	LOGD << "=== Closing log. ===";
}
