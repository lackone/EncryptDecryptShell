#pragma once

#include <windows.h>
#include <stdarg.h>
#include <tchar.h>

class Tools
{
public:
	//��Ȩ
	static BOOL AdjustPrivileges(HANDLE hProcess, LPCTSTR lpPrivilegeName);
	//�������
	static VOID OutputDebugStringFormat(const TCHAR* format, ...);
	//��ȡ���̵�imagebase
	static DWORD GetProcessImageBase(HANDLE hProcess, CONTEXT ctx);
};

