
HANDLE _SFC=0;

BOOL (WINAPI *_SfcIsFileProtected)(HANDLE rpc,LPCWSTR fname);


char sfcHandleStr[] = "sfc.dll";

char sfcStr[] = "SfcIsFileProtected";


void InitSFC()
{
	_SFC = _GetModuleHandle(sfcHandleStr);
	if (_SFC == NULL) 
		_SFC = _LoadLibrary(sfcHandleStr);
	if (_SFC == NULL)
		return; // no sfc.dll

	_SfcIsFileProtected = (DWORD *)_GetProcAddress(_SFC, sfcStr);
}
