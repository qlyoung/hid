#include "stdafx.h"

#include "util.h"
#include "plog\Log.h"
#include <string>

std::string hexdump(const void* data, size_t size)
{
	std::string dump;
	char ascii[17];
	size_t i, j;
	char hexchar[4];

	ascii[16] = '\0';

	for (i = 0; i < size; ++i) {

		snprintf(hexchar, sizeof(hexchar), "%02X ", ((unsigned char *)data)[i]);
		dump.append(hexchar);

		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		}
		else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			dump.append(" ");
			if ((i + 1) % 16 == 0) {
				dump.append("|  ");
				dump.append(ascii);
				dump.append(" \n");
			}
			else if (i + 1 == size) {
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

void util_init()
{
	plog::init(plog::debug, LOGFILENAME);
}

void util_uninit()
{
	LOGD << "=== Closing log. ===";
}
