#include <windows.h>
#include <tchar.h>
#include "PETools.h"
#include "PETools.cpp"
#include "Tools.h"

typedef DWORD(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID);

/**
 * �ٴγ��������ڴ�
 */
LPVOID AgainTryVirtualAlloc(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID address = NULL;

	DWORD start = (DWORD)lpAddress;
	DWORD end = 0x08000000;

	//ģ���ַ����Ϊ 10000H������������ 100000 Ϊ����
	for (; start < end; start += 0x100000)
	{
		//ע�����ע������п��ܻ᷵�� 487
		address = VirtualAllocEx(hProcess, (LPVOID)start, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (address != NULL)
		{
			Tools::OutputDebugStringFormat(TEXT("�����ڴ�ɹ� 0x%x"), address);
			return address;
		}
		Tools::OutputDebugStringFormat(TEXT("�����ڴ�ʧ�� 0x%x %d"), start, GetLastError());
	}

	return address;
}

//������Թ���Ա���п��ӳ��򣬻ᱨ��Ȩʧ�ܣ������룺1300
//�������Ҽ��Թ���Ա���п��ӳ���ʱ���ֻᱨ 0xc0000005

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	if (!Tools::AdjustPrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
	{
		Tools::OutputDebugStringFormat(TEXT("DEBUG ��Ȩʧ�� %d"), GetLastError());
		MessageBox(NULL, TEXT("��������Ȩʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//��ȡ��ǰ�����·��
	TCHAR shellExePath[MAX_PATH]{ 0 };
	GetModuleFileName(GetModuleHandle(NULL), shellExePath, MAX_PATH);

	//1����ȡ��ģ�������
	PETools pe;
	LPVOID shellFileBuf = NULL;
	LPVOID srcImageBuf = NULL;
	pe.ReadPEFile(shellExePath, &shellFileBuf);

	//��ȡ���һ����
	PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(shellFileBuf);
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
	memcpy(srcData, (LPBYTE)shellFileBuf + last_section->PointerToRawData, srcSize);

	//2����SRC���ݽ��н���
	pe.Decrypt(srcData, srcSize);

	//3���Թ������ʽ��������
	STARTUPINFO si{ 0 };
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi{ 0 };
	if (!CreateProcess(NULL, shellExePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBox(NULL, TEXT("��������ʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	if (!Tools::AdjustPrivileges(pi.hProcess, SE_DEBUG_NAME))
	{
		Tools::OutputDebugStringFormat(TEXT("DEBUG ��Ȩʧ�� %d"), GetLastError());
		MessageBox(NULL, TEXT("�ӽ�����Ȩʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//4����ȡ��ǳ����context������Ҫ��
	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//ע��������ǻ�ȡshell��imagebase
	DWORD shellImageBase = Tools::GetProcessImageBase(pi.hProcess, ctx);

	Tools::OutputDebugStringFormat(TEXT("DEBUG shellImageBase 0x%x"), shellImageBase);

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
	PIMAGE_OPTIONAL_HEADER srcOptHeader = pe.GetOptionHeader(srcData);

	//���������ڴ�
	//������shellImageBase�����룬��ʹ��SRC��ImageBase(srcOptHeader->ImageBase)����ֹASLR
	//ASLRֻ����ԭʼbaseAddress�������, ��������������ݼ�����֤
	//ֻҪ���ǲ���shell�Ļ�ַ��������������ǿ�������
	LPVOID address = AgainTryVirtualAlloc(pi.hProcess, (LPVOID)shellImageBase, srcOptHeader->SizeOfImage);

	Tools::OutputDebugStringFormat(TEXT("DEBUG address 0x%x"), address);

	if (address == NULL)
	{
		MessageBox(NULL, TEXT("�����ڴ�ʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//������뵽�ĵ�ַ����ԭshellImageBase��һ�£�����Ҫ�����ض�λ��
	if ((DWORD)address != shellImageBase)
	{
		DWORD offset = (DWORD)address - shellImageBase;
		pe.ReviseRelocation(srcData, offset);
	}

	//7������ɹ�����SRC��PE�ļ����� ���Ƶ��ÿռ���	
	pe.FileBufferToImageBuffer(srcData, &srcImageBuf);

	if (!WriteProcessMemory(pi.hProcess, address, srcImageBuf, srcOptHeader->SizeOfImage, NULL))
	{
		MessageBox(NULL, TEXT("д��SRCʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//10���޸���ǳ����Context
	//��Context��ImageBase�ĳ�SRC��ImageBase
	DWORD srcImageBase = (DWORD)address;

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &srcImageBase, 4, NULL))
	{
		MessageBox(NULL, TEXT("д��srcImageBaseʧ��"), TEXT("��ʾ"), MB_OK);
		return -1;
	}

	//��Context��OEP�ĳ�SRC��OEP	
	ctx.Eax = srcOptHeader->AddressOfEntryPoint + srcImageBase;

	Tools::OutputDebugStringFormat(TEXT("DEBUG Eax 0x%x"), ctx.Eax);

	//11������Context ���ָ����߳�		
	ctx.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	//�ͷ���Դ
	free(shellFileBuf);
	free(srcImageBuf);
	free(srcData);

	return 0;
}