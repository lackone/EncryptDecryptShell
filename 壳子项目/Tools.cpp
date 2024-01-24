#include "Tools.h"

/**
 * ��Ȩ
 */
BOOL Tools::AdjustPrivileges(HANDLE hProcess, LPCTSTR lpPrivilegeName)
{
	HANDLE hToken;
	BOOL fOk = FALSE;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, lpPrivilegeName, &tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

/**
 * �������
 */
VOID Tools::OutputDebugStringFormat(const TCHAR* format, ...)
{
	va_list args;
	va_start(args, format);

	int length = _vsctprintf(format, args);

	TCHAR* buffer = new TCHAR[length + 1];

	_vstprintf_s(buffer, length + 1, format, args);

	OutputDebugString(buffer);

	delete[] buffer;
	va_end(args);
}

/**
 * ��ȡ���̵�ImageBase
 */
DWORD Tools::GetProcessImageBase(HANDLE hProcess, CONTEXT ctx)
{
	LPVOID address = (LPVOID)(ctx.Ebx + 8);
	DWORD ImageBase = 0;
	ReadProcessMemory(hProcess, address, &ImageBase, 4, NULL);
	return ImageBase;
}