#include <windows.h>

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{
	//一个简单的弹出对话框，主要用来测试加壳项目
	MessageBox(NULL, TEXT("OK"), TEXT("OK"), MB_OK);
	return 0;
}