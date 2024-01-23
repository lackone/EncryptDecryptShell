#include <windows.h>
#include <tchar.h>
#include "resource.h"
#include "PETools.h"

//文本框句柄
HWND editShell;
HWND editSrc;
//壳程序路径
TCHAR shellPath[MAX_PATH]{ 0 };
//源程序路径
TCHAR srcPath[MAX_PATH]{ 0 };
//保存路径
TCHAR savePath[MAX_PATH]{ 0 };

/**
 * 对话框消息函数
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
		//初始化对话框，把文本框置为空
		editShell = GetDlgItem(hwnd, IDC_EDIT_SHELL);
		editSrc = GetDlgItem(hwnd, IDC_EDIT_SRC);
		//设置文本
		SetWindowText(editShell, TEXT(""));
		SetWindowText(editSrc, TEXT(""));
		return TRUE;
	case WM_CLOSE:
		//关闭对话框
		EndDialog(hwnd, 0);
		return TRUE;
	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_SHELL: //壳浏览按钮
		{
			if (!GetOpenFileName(&ofn))
			{
				MessageBox(hwnd, TEXT("请选择文件"), TEXT("提示"), MB_OK);
				return TRUE;
			}
			if (_tcslen(szFileName) <= 0)
			{
				MessageBox(hwnd, TEXT("文件名为空"), TEXT("提示"), MB_OK);
				return TRUE;
			}
			_tcscpy_s(shellPath, MAX_PATH, szFileName);
			SetWindowText(editShell, szFileName);
		}
		break;
		case IDC_BUTTON_SRC: //源浏览按钮
		{
			if (!GetOpenFileName(&ofn))
			{
				MessageBox(hwnd, TEXT("请选择文件"), TEXT("提示"), MB_OK);
				return TRUE;
			}
			if (_tcslen(szFileName) <= 0)
			{
				MessageBox(hwnd, TEXT("文件名为空"), TEXT("提示"), MB_OK);
				return TRUE;
			}
			_tcscpy_s(srcPath, MAX_PATH, szFileName);
			SetWindowText(editSrc, szFileName);
		}
		break;
		case IDC_BUTTON_ADD_SHELL: //加壳按钮
		{
			//1、获取Shell程序的路径
			//2、获取src程序的路径
			//这两步上面已经做了

			LPVOID srcFileBuf = NULL;
			LPVOID shellFileBuf = NULL;
			LPVOID newShellFileBuf = NULL;

			//3、将src程序读取到内存中，加密
			DWORD srcSize = pe.ReadPEFile(srcPath, &srcFileBuf);
			//进行加密
			pe.Encrypt(srcFileBuf, srcSize);

			//4、在Shell程序中新增一个节，并将加密后的src程序追加到Shell程序的新增节中
			DWORD shellSize = pe.ReadPEFile(shellPath, &shellFileBuf);

			//新加节
			DWORD newShellSize = pe.AddSection(shellFileBuf, shellSize, srcSize, TEXT(".shell"), &newShellFileBuf);

			//将加密后的SRC，追加到新增节中
			PIMAGE_SECTION_HEADER last_section = pe.GetLastSection(newShellFileBuf);
			memcpy((LPBYTE)newShellFileBuf + last_section->PointerToRawData, (LPBYTE)srcFileBuf, srcSize);

			//保存文件
			size_t ix = _tcsrchr(srcPath, TEXT('.')) - srcPath;
			_tcsncpy_s(savePath, MAX_PATH, srcPath, ix);
			_tcscat_s(savePath, MAX_PATH, TEXT("_shell"));
			_tcscpy_s(savePath + _tcslen(savePath), MAX_PATH, srcPath + ix);

			pe.SaveFile(newShellFileBuf, newShellSize, savePath);

			//5、加壳过程完毕
			MessageBox(hwnd, TEXT("加壳成功"), TEXT("加壳成功"), MB_OK);

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