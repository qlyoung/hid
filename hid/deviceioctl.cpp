#include "stdafx.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#include "plog\Log.h"
#include "deviceioctl.h"
#include "util.h"
#include "MinHook.h"
#include <sstream>

typedef BOOL(WINAPI *DeviceIoControl_t)(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
);


DeviceIoControl_t orig_DeviceIoControl;

BOOL WINAPI hook_DeviceIoControl(
	_In_        HANDLE       hDevice,
	_In_        DWORD        dwIoControlCode,
	_In_opt_    LPVOID       lpInBuffer,
	_In_        DWORD        nInBufferSize,
	_Out_opt_   LPVOID       lpOutBuffer,
	_In_        DWORD        nOutBufferSize,
	_Out_opt_   LPDWORD      lpBytesReturned,
	_Inout_opt_ LPOVERLAPPED lpOverlapped
)
{
	BOOL ret;
	std::stringstream logmsg;
	static HANDLE sensor;

	if (!sensor && dwIoControlCode == SENSOR_IOCTL_UNKNOWN) {
		logmsg << "Saw probable sensor IOCTL, saving handle";
		sensor = hDevice;
	}
	
	if (sensor && hDevice == sensor) {
		logmsg << std::endl << "===== IOCTL =====" << std::endl;
		logmsg << "ctlcode: " << dwIoControlCode << std::endl;
		logmsg << "overlapped: " << std::hex << lpOverlapped << std::dec << std::endl;
		logmsg << "inbuf[" << nInBufferSize << "]" << std::endl;
		logmsg << hexdump(lpInBuffer, nInBufferSize);
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
								   nInBufferSize, lpOutBuffer,
								   nOutBufferSize, lpBytesReturned,
								   lpOverlapped);
		logmsg << "bytes returned: " << (lpBytesReturned ? *lpBytesReturned : 0);
		logmsg << (lpBytesReturned ? "" : "(dumping whole buffer)") << std::endl;
		if (!lpOutBuffer)
			logmsg << ">>> No output buffer..." << std::endl;
		else {
			logmsg << "obuf[" << nOutBufferSize << "]" << std::endl;
			logmsg << hexdump(lpOutBuffer, lpBytesReturned ? *lpBytesReturned : nOutBufferSize);
		}
		logmsg << "=================" << std::endl;
	}
	else {
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
			nInBufferSize, lpOutBuffer,
			nOutBufferSize, lpBytesReturned,
			lpOverlapped);
	}

	if (logmsg.rdbuf()->in_avail())
		LOGI << logmsg.str();

	return ret;
}

void installhooks()
{
	if (MH_Initialize() != MH_OK)
		LOGE << "Could not initialize MinHook.";

	if (MH_CreateHook(&DeviceIoControl, &hook_DeviceIoControl,
		reinterpret_cast<LPVOID*>(&orig_DeviceIoControl)) != MH_OK)
		LOGE << "Could not create DeviceIoControl hook.";

	if (MH_EnableHook(&DeviceIoControl) != MH_OK)
		LOGE << "Could not enable hook.";

	LOGI << "Installed hooks.";
}
