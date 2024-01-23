#pragma once

#include <windows.h>
#include <stdio.h>

class PETools
{
protected:
	int key[7] = { 1,2,3,4,5,6,7 };
public:
	//��ȡPE�ļ����ڴ���
	DWORD ReadPEFile(IN LPCTSTR filePath, OUT LPVOID* pFileBuffer);
	//���ڴ�ƫ��ת��Ϊ�ļ�ƫ��
	DWORD RvaToFoa(IN LPVOID pFileBuffer, IN DWORD dwRva);
	//���ļ�ƫ��ת��Ϊ�ڴ�ƫ��
	DWORD FoaToRva(IN LPVOID pFileBuffer, IN DWORD dwFoa);
	//�ֽڶ���
	DWORD Align(IN DWORD x, IN DWORD y);
	//�����ļ�
	DWORD SaveFile(IN LPVOID pFileBuffer, IN DWORD fileSize, IN LPCTSTR filePath);
	//��ӽ�
	DWORD AddSection(IN LPVOID pFileBuffer, IN DWORD fileSize, IN DWORD addSize, IN LPCTSTR addName, OUT LPVOID* pNewFileBuffer);
	//�����ļ�bufferΪimageBuffer
	DWORD FileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
	//��TCHARת����CHAR
	VOID TCHARToChar(IN LPCTSTR tstr, OUT LPSTR* str);
	//���ܣ���򵥵����
	VOID Encrypt(IN LPVOID pFileBuffer, IN DWORD fileSize);
	//���ܣ���򵥵����
	VOID Decrypt(IN LPVOID pFileBuffer, IN DWORD fileSize);
	//��ȡ���һ����
	PIMAGE_SECTION_HEADER GetLastSection(IN LPVOID pFileBuffer);
	//��ȡ��ѡPEͷ
	PIMAGE_OPTIONAL_HEADER GetOptionHeader(IN LPVOID pFileBuffer);
};

