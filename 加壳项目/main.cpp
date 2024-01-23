#include <windows.h>
#include <tchar.h>
#include "resource.h"
#include "PETools.h"

//�ı�����
HWND editShell;
HWND editSrc;
//�ǳ���·��
TCHAR shellPath[MAX_PATH]{ 0 };
//Դ����·��
TCHAR srcPath[MAX_PATH]{ 0 };
//����·��
TCHAR savePath[MAX_PATH]{ 0 };

/**
 * �Ի�����Ϣ����
 */
INT_PTR CALLBACK dlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	TCHAR szFileName[MAX_PATH]{ 0 };
	OPENFILENAME ofn{ 0 };
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hwnd;
	ofn.lpstrFile = szFileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = TEXT("EXE Files\0*.exe\0");
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

	PETools pe;

	switch (uMsg)
	{
	case WM_INITDIALOG:
		//��ʼ���Ի��򣬰��ı�����Ϊ��
		editShell = GetDlgItem(hwnd, IDC_EDIT_SHELL);
		editSrc = GetDlgItem(hwnd, IDC_EDIT_SRC);
		//�����ı�
		SetWindowText(editShell, TEXT(""));
		SetWindowText(editSrc, TEXT(""));
		return TRUE;
	case WM_CLOSE:
		//�رնԻ���
		EndDialog(hwnd, 0);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_SHELL: //�������ť
		{
			if (!GetOpenFileName(&ofn))
			{
				MessageBox(hwnd, TEXT("��ѡ���ļ�"), TEXT("��ʾ"), MB_OK);
				return TRUE;
			}
			if (_tcslen(szFileName) <= 0)
			{
				MessageBox(hwnd, TEXT("�ļ���Ϊ��"), TEXT("��ʾ"), MB_OK);
				return TRUE;
			}
			_tcscpy_s(shellPath, MAX_PATH, szFileName);
			SetWindowText(editShell, szFileName);
		}
		break;
		case IDC_BUTTON_SRC: //Դ�����ť
		{
			if (!GetOpenFileName(&ofn))
			{
				MessageBox(hwnd, TEXT("��ѡ���ļ�"), TEXT("��ʾ"), MB_OK);
				return TRUE;
			}
			if (_tcslen(szFileName) <= 0)
			{
				MessageBox(hwnd, TEXT("�ļ���Ϊ��"), TEXT("��ʾ"), MB_OK);
				return TRUE;
			}
			_tcscpy_s(srcPath, MAX_PATH, szFileName);
			SetWindowText(editSrc, szFileName);
		}
		break;
		case IDC_BUTTON_ADD_SHELL: //�ӿǰ�ť
		{
			//1����ȡShell�����·��
			//2����ȡsrc�����·��
			//�����������Ѿ�����

			LPVOID srcFileBuf = NULL;
			LPVOID shellFileBuf = NULL;
			LPVOID newShellFileBuf = NULL;

			//3����src�����ȡ���ڴ��У�����
			DWORD srcSize = pe.ReadPEFile(srcPath, &srcFileBuf);
			//���м���
			pe.Encrypt(srcFileBuf, srcSize);

			//4����Shell����������һ���ڣ��������ܺ��src����׷�ӵ�Shell�������������
			DWORD shellSize = pe.ReadPEFile(shellPath, &shellFileBuf);

			//�¼ӽ�
			DWORD newShellSize = pe.AddSection(shellFileBuf, shellSize, srcSize, TEXT(".shell"), &newShellFileBuf);

			//�����ܺ��SRC��׷�ӵ���������
			PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(newShellFileBuf);
			memcpy((LPBYTE)newShellFileBuf + last_section->PointerToRawData, (LPBYTE)srcFileBuf, srcSize);

			//�����ļ�
			size_t ix = _tcsrchr(srcPath, TEXT('.')) - srcPath;
			_tcsncpy_s(savePath, MAX_PATH, srcPath, ix);
			_tcscat_s(savePath, MAX_PATH, TEXT("_shell"));
			_tcscpy_s(savePath + _tcslen(savePath), MAX_PATH, srcPath + ix);

			pe.SaveFile(newShellFileBuf, newShellSize, savePath);

			//5���ӿǹ������
			MessageBox(hwnd, TEXT("�ӿǳɹ�"), TEXT("�ӿǳɹ�"), MB_OK);

			free(srcFileBuf);
			free(shellFileBuf);
			free(newShellFileBuf);
		}
		break;
		}
		return TRUE;
	}

	return FALSE;
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, dlgProc);
	return 0;
}