#include <windows.h>
#include <tchar.h>
#include "PETools.h"
#include "PETools.cpp"

typedef DWORD(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID);

/**
 * 提权
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

	//获取命令行参数
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv) {
		//获取当前运行的EXE的路径
		_tcscpy_s(exePath, MAX_PATH, argv[0]);
		//释放分配的内存
		LocalFree(argv);
	}

	if (!AdjustPrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
	{
		MessageBox(NULL, TEXT("提权失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	_tcscpy_s(exePath, MAX_PATH, TEXT("I:\\cpp_projects\\EncryptDecryptShell\\Debug\\123.exe"));

	//1、读取主模块的数据
	PETools pe;
	LPVOID fileBuf = NULL;
	LPVOID imageBuf = NULL;
	pe.ReadPEFile(exePath, &fileBuf);

	//获取最后一个节
	PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(fileBuf);
	//申请内存，保存原来SRC的数据
	//用SizeOfRawData和Misc.VirtualSize都一样，因为这两个值我们添加节时，就是一样的。
	DWORD srcSize = last_section->SizeOfRawData;
	LPBYTE srcData = (LPBYTE)malloc(srcSize);
	if (srcData == NULL)
	{
		MessageBox(NULL, TEXT("申请内存失败"), TEXT("提示"), MB_OK);
		return -1;
	}
	memset(srcData, 0, srcSize);
	memcpy(srcData, (LPBYTE)fileBuf + last_section->PointerToRawData, srcSize);

	//2、把SRC数据进行解密
	pe.Decrypt(srcData, srcSize);

	//3、以挂起的形式创建进程
	STARTUPINFO si{ 0 };
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi{ 0 };
	if (!CreateProcess(NULL, exePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBox(NULL, TEXT("创建进程失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//4、获取外壳程序的context，后面要用
	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//5、卸载外壳程序
	HMODULE nt = LoadLibrary(TEXT("ntdll.dll"));
	pZwUnmapViewOfSection ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(nt, "ZwUnmapViewOfSection");
	if (ZwUnmapViewOfSection == NULL)
	{
		MessageBox(NULL, TEXT("获取ZwUnmapViewOfSection失败"), TEXT("提示"), MB_OK);
		return -1;
	}
	ZwUnmapViewOfSection(pi.hProcess, GetModuleHandle(NULL));

	//6、在指定的位置分配空间：位置就是SRC的ImageBase  大小就是SRC的SizeOfImage
	PIMAGE_OPTIONAL_HEADER optHeader = pe.GetOptionHeader(srcData);

	LPVOID address = VirtualAllocEx(pi.hProcess, (LPVOID)optHeader->ImageBase, optHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (address == NULL)
	{
		TCHAR msg[MAX_PATH]{ 0 };
		_stprintf_s(msg, MAX_PATH, TEXT("%s %d"), TEXT("分配空间失败"), GetLastError());
		MessageBox(NULL, msg, TEXT("提示"), MB_OK);
		return -1;
	}

	//7、如果成功，将SRC的PE文件拉伸 复制到该空间中	
	pe.FileBufferToImageBuffer(srcData, &imageBuf);

	if (!WriteProcessMemory(pi.hProcess, address, imageBuf, optHeader->SizeOfImage, NULL))
	{
		MessageBox(NULL, TEXT("写入SRC失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//10、修改外壳程序的Context
	//将Context的ImageBase改成SRC的ImageBase
	DWORD imageBase = (DWORD)address;
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &imageBase, 4, NULL))
	{
		MessageBox(NULL, TEXT("写入ImageBase失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//将Context的OEP改成SRC的OEP	
	ctx.Eax = optHeader->AddressOfEntryPoint + imageBase;


	//11、设置Context 并恢复主线程		
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	//释放资源
	free(fileBuf);
	free(imageBuf);
	free(srcData);

	return 0;
}