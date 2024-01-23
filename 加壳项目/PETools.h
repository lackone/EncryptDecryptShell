#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
protected:
	int key[7] = { 1,2,3,4,5,6,7 };
public:
	//读取PE文件到内存中
	DWORD ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer);
	//将内存偏移转换为文件偏移
	DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
	//将文件偏移转换为内存偏移
	DWORD FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa);
	//字节对齐
	DWORD Align(IN DWORD x, IN DWORD y);
	//保存文件
	DWORD SaveFile(IN LPVOID pFileBuffer, IN DWORD fileSize, IN LPCTSTR filePath);
	//添加节
	DWORD AddSection(IN LPVOID pFileBuffer, IN DWORD fileSize, IN DWORD addSize, IN LPCTSTR addName, OUT LPVOID* pNewFileBuffer);
	//拉伸文件buffer为imageBuffer
	DWORD FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
	//将TCHAR转换成CHAR
	VOID TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str);
	//加密，最简单的异或
	VOID Encrypt(IN LPVOID pFileBuffer, IN DWORD fileSize);
	//解密，最简单的异或
	VOID Decrypt(IN LPVOID pFileBuffer, IN DWORD fileSize);
	//获取最后一个节
	PIMAGE_SECTION_HEADER GetLastSection(IN LPVOID pFileBuffer);
	//获取可选PE头
	PIMAGE_OPTIONAL_HEADER GetOptionHeader(IN LPVOID pFileBuffer);
};

