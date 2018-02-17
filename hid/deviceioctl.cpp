#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#include "stdafx.h"

#include "deviceioctl.h"
#include "util.h"
#include "include\MinHook.h"

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
	static HANDLE sensor;

	if (!sensor && dwIoControlCode == SENSOR_IOCTL_UNKNOWN) {
		mlog("[!] Saw probable sensor IOCTL, saving handle");
		sensor = hDevice;
	}
	
	if (sensor && hDevice == sensor) {
		DebugBreak();
		mlog("===== IOCTL =====");
		mlog("ctlcode: %d", dwIoControlCode);
		mlog("overlapped: %p", lpOverlapped);
		mlog("inbuf[%d]:", nInBufferSize);
		hexdump(lpInBuffer, nInBufferSize);
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
			nInBufferSize, lpOutBuffer,
			nOutBufferSize, lpBytesReturned,
			lpOverlapped);
		mlog("bytes returned: %d%s", (lpBytesReturned ? *lpBytesReturned : 0),
			lpBytesReturned ? "" : " (dumping whole buffer)");
		mlog("obuf[%d]:", nOutBufferSize);
		if (!lpOutBuffer)
			mlog(">>> No output buffer...");
		else
			hexdump(lpOutBuffer, lpBytesReturned ? *lpBytesReturned : nOutBufferSize);
		mlog("=================");
	}
	else {
		ret = orig_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer,
			nInBufferSize, lpOutBuffer,
			nOutBufferSize, lpBytesReturned,
			lpOverlapped);
	}

	return ret;
}

void installhooks()
{
	if (MH_Initialize() != MH_OK)
		mlog("[X] Could not initialize MinHook.");

	if (MH_CreateHook(&DeviceIoControl, &hook_DeviceIoControl,
		reinterpret_cast<LPVOID*>(&orig_DeviceIoControl)) != MH_OK)
		mlog("[X] Could not create DeviceIoControl hook.");

	if (MH_EnableHook(&DeviceIoControl) != MH_OK)
		mlog("[X] Could not enable hook.");

	mlog("[!] Installed hooks.");
}
