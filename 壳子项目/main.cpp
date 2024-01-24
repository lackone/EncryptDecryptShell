#include <windows.h>
#include <tchar.h>
#include "PETools.h"
#include "PETools.cpp"
#include "Tools.h"

typedef DWORD(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID);

/**
 * 再次尝试申请内存
 */
LPVOID AgainTryVirtualAlloc(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize)
{
	LPVOID address = NULL;

	DWORD start = (DWORD)lpAddress;
	DWORD end = 0x08000000;

	//模块地址对齐为 10000H，这里我们以 100000 为步长
	for (; start < end; start += 0x100000)
	{
		//注意这里，注意这里，有可能会返回 487
		address = VirtualAllocEx(hProcess, (LPVOID)start, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (address != NULL)
		{
			Tools::OutputDebugStringFormat(TEXT("申请内存成功 0x%x"), address);
			return address;
		}
		Tools::OutputDebugStringFormat(TEXT("申请内存失败 0x%x %d"), start, GetLastError());
	}

	return address;
}

//如果不以管理员运行壳子程序，会报提权失败，错误码：1300
//当我们右键以管理员运行壳子程序时，又会报 0xc0000005

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	if (!Tools::AdjustPrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
	{
		Tools::OutputDebugStringFormat(TEXT("DEBUG 提权失败 %d"), GetLastError());
		MessageBox(NULL, TEXT("主进程提权失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//获取当前程序的路径
	TCHAR shellExePath[MAX_PATH]{ 0 };
	GetModuleFileName(GetModuleHandle(NULL), shellExePath, MAX_PATH);

	//1、读取主模块的数据
	PETools pe;
	LPVOID shellFileBuf = NULL;
	LPVOID srcImageBuf = NULL;
	pe.ReadPEFile(shellExePath, &shellFileBuf);

	//获取最后一个节
	PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(shellFileBuf);
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
	memcpy(srcData, (LPBYTE)shellFileBuf + last_section->PointerToRawData, srcSize);

	//2、把SRC数据进行解密
	pe.Decrypt(srcData, srcSize);

	//3、以挂起的形式创建进程
	STARTUPINFO si{ 0 };
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi{ 0 };
	if (!CreateProcess(NULL, shellExePath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		MessageBox(NULL, TEXT("创建进程失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	if (!Tools::AdjustPrivileges(pi.hProcess, SE_DEBUG_NAME))
	{
		Tools::OutputDebugStringFormat(TEXT("DEBUG 提权失败 %d"), GetLastError());
		MessageBox(NULL, TEXT("子进程提权失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//4、获取外壳程序的context，后面要用
	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);

	//注意这里，我们获取shell的imagebase
	DWORD shellImageBase = Tools::GetProcessImageBase(pi.hProcess, ctx);

	Tools::OutputDebugStringFormat(TEXT("DEBUG shellImageBase 0x%x"), shellImageBase);

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
	PIMAGE_OPTIONAL_HEADER srcOptHeader = pe.GetOptionHeader(srcData);

	//尝试申请内存
	//我们在shellImageBase处申请，不使用SRC的ImageBase(srcOptHeader->ImageBase)，防止ASLR
	//ASLR只会检测原始baseAddress存在与否, 并不对里面的数据加以验证
	//只要我们不改shell的基址，里面的数据我们可以随便改
	LPVOID address = AgainTryVirtualAlloc(pi.hProcess, (LPVOID)shellImageBase, srcOptHeader->SizeOfImage);

	Tools::OutputDebugStringFormat(TEXT("DEBUG address 0x%x"), address);

	if (address == NULL)
	{
		MessageBox(NULL, TEXT("申请内存失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//如果申请到的地址，与原shellImageBase不一致，则需要修正重定位表
	if ((DWORD)address != shellImageBase)
	{
		DWORD offset = (DWORD)address - shellImageBase;
		pe.ReviseRelocation(srcData, offset);
	}

	//7、如果成功，将SRC的PE文件拉伸 复制到该空间中	
	pe.FileBufferToImageBuffer(srcData, &srcImageBuf);

	if (!WriteProcessMemory(pi.hProcess, address, srcImageBuf, srcOptHeader->SizeOfImage, NULL))
	{
		MessageBox(NULL, TEXT("写入SRC失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//10、修改外壳程序的Context
	//将Context的ImageBase改成SRC的ImageBase
	DWORD srcImageBase = (DWORD)address;

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), &srcImageBase, 4, NULL))
	{
		MessageBox(NULL, TEXT("写入srcImageBase失败"), TEXT("提示"), MB_OK);
		return -1;
	}

	//将Context的OEP改成SRC的OEP	
	ctx.Eax = srcOptHeader->AddressOfEntryPoint + srcImageBase;

	Tools::OutputDebugStringFormat(TEXT("DEBUG Eax 0x%x"), ctx.Eax);

	//11、设置Context 并恢复主线程		
	ctx.ContextFlags = CONTEXT_FULL;
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);

	//释放资源
	free(shellFileBuf);
	free(srcImageBuf);
	free(srcData);

	return 0;
}