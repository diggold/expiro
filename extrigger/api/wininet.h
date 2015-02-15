
//BOOL (WINAPI *_InternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
//HINTERNET (WINAPI *_InternetOpenA)(LPCTSTR lpszAgent, DWORD dwAccessType, LPCTSTR lpszProxy,  LPCTSTR lpszProxyBypass, DWORD dwFlags);
//HINTERNET (WINAPI *_InternetConnectA)(HINTERNET hInternet, LPCTSTR lpszServerName, INTERNET_PORT nServerPort, LPCTSTR lpszUserName, LPCTSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD dwContext);
//HINTERNET (WINAPI *_HttpOpenRequestA)(HINTERNET hConnect, LPCTSTR lpszVerb, LPCTSTR lpszObjectName, LPCTSTR lpszVersion, LPCTSTR lpszReferrer, LPCTSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD dwContext);
//BOOL (WINAPI *_HttpAddRequestHeadersA)(HINTERNET hHttpRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
//BOOL (WINAPI *_HttpSendRequestA)(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
//BOOL (WINAPI *_InternetCloseHandle)(HINTERNET hInternet );

BOOL (WINAPI *_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
LPVOID (WINAPI *_InternetOpenA)(LPCTSTR, DWORD, LPCTSTR,  LPCTSTR, DWORD);
LPVOID (WINAPI *_InternetConnectA)(HINTERNET, LPCTSTR, INTERNET_PORT, LPCTSTR, LPCTSTR, DWORD, DWORD, DWORD);
LPVOID (WINAPI *_HttpOpenRequestA)(HINTERNET, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR, PVOID/* LPCTSTR* */, DWORD, DWORD);
BOOL (WINAPI *_HttpAddRequestHeadersA)(HINTERNET, LPCTSTR, DWORD, DWORD);
BOOL (WINAPI *_HttpSendRequestA)(HINTERNET, LPCTSTR, DWORD, LPVOID, DWORD);
BOOL (WINAPI *_InternetCloseHandle)(HINTERNET);

HANDLE _WININET = 0;


void* padrWininet[] = 
{ 
	&_InternetReadFile, 
	&_InternetOpenA, 
	&_InternetConnectA, 
	&_HttpOpenRequestA, 
	&_HttpAddRequestHeadersA, 
	&_HttpSendRequestA, 
	&_InternetCloseHandle 
};


char wininetHandleStr[] = "wininet.dll";

char wininetStr[] = "/*@S|*/00InternetReadFile|01InternetOpenA|02InternetConnectA|03HttpOpenRequestA|04HttpAddRequestHeadersA|05HttpSendRequestA|06InternetCloseHandle/*@E*/|";


void InitWininet()
{
	_WININET = _GetModuleHandle(wininetHandleStr); 
	if (_WININET == NULL)
		_WININET = _LoadLibrary(wininetHandleStr);

	InitAPIbyStr(padrWininet, _WININET, wininetStr);
}
