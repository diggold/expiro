
HANDLE _URLMON = 0;

HRESULT (WINAPI *_ObtainUserAgentString)( DWORD dwOption, LPSTR pszUAOut, DWORD * cbSize );

void* padrUrlmon[] = 
{ 
	&_ObtainUserAgentString 
};


char urlmonHandleStr[] = "urlmon.dll";

char urlmonStr[] = "/*@S|*/00ObtainUserAgentString/*@E*/|";


void InitUrlmon()
{
 _URLMON = _GetModuleHandle(urlmonHandleStr); 
 if (_URLMON == NULL)
	 _URLMON = _LoadLibrary(urlmonHandleStr);

 InitAPIbyStr(padrUrlmon, _URLMON, urlmonStr);
}
