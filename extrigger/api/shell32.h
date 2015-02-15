
HMODULE _SHELL32=0;
HRESULT (WINAPI *_SHGetFolderPath)(HWND hwndOwner,int nFolder,HANDLE hToken,DWORD dwFlags,LPTSTR pszPath);


char shell32HandleStr[] = "shell32.dll";

char shell32Str[] = "SHGetFolderPathA";


void InitShell32()
{
	//fix strange "POP ECX"
	_SHELL32 = _GetModuleHandle(shell32HandleStr); 
	if (_SHELL32 == NULL) 
		_SHELL32 = _LoadLibrary(shell32HandleStr);

	_SHGetFolderPath = _GetProcAddress(_SHELL32, shell32Str);
}
