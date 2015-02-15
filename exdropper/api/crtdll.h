
HANDLE _CRTDLL=0;

int    (*__sleep)(unsigned long dwMilliseconds);
int    (*__toupper)(int c);

int    (*_atoi)    (char *_nptr);
void   (*_free)    (void *);
void * (*_malloc)  (size_t _size);
int    (*_memcmp)  (const void *, const void *, size_t);
void * (*_memcpy)  (void *, const void *, size_t);
void * (*_memset)  (void *, int, size_t);
void   (*_srand)   (unsigned _seed);
int    (*_rand)    (void);
char  *(*_strcat)  (char *, const char *);
int    (*_sprintf) (char *, const char *, ...);
int    (*_vsprintf)(char *, const char *, va_list);
int    (*_wcslen)  (char *wstr);


//char * (*_strcpy)  (char *, const char *);

/*DWORD _GPAecoCRT(char *fname) // Economy Code
{
	DWORD a=(DWORD)_GetProcAddress(_CRTDLL,fname);
	 return a;
}*/


char crtdllHandleStr[] = "crtdll.dll";

void InitCRTDLL_handle()
{
	_CRTDLL = _GetModuleHandle(crtdllHandleStr);
	if (_CRTDLL == NULL)
		_CRTDLL = _LoadLibrary(crtdllHandleStr);
}

DWORD  *padrCRT[] = 
{
	&__toupper,
	&__sleep,
	&_sprintf,
	&_atoi,
	&_free,
	&_malloc,
	&_memcmp,
	&_memcpy,
	&_memset,
	&_rand,
	&_srand,
	&_strcat,
	&_vsprintf,
	&_wcslen
};


char crtdllStr[] = "/*@S|*/00toupper|01_sleep|02sprintf|03atoi|04free|05malloc|06memcmp|07memcpy|08memset|09rand|10srand|11strcat|12vsprintf|13wcslen/*@E*/|";

void InitCRTDLL()
{
	InitCRTDLL_handle();

	InitAPIbyStr(padrCRT, _CRTDLL, crtdllStr);

	/*
	 __toupper = (DWORD *)_GPAecoCRT("toupper");//@S
	 __sleep   = (DWORD *)_GPAecoCRT("_sleep"); 
	 _sprintf  = (DWORD *)_GPAecoCRT("sprintf");
	 _atoi     = (DWORD *)_GPAecoCRT("atoi");
	 _free     = (DWORD *)_GPAecoCRT("free");
	 _malloc   = (DWORD *)_GPAecoCRT("malloc");
	 _memcmp   = (DWORD *)_GPAecoCRT("memcmp");
	 _memcpy   = (DWORD *)_GPAecoCRT("memcpy");
	 _memset   = (DWORD *)_GPAecoCRT("memset");
	 _rand     = (DWORD *)_GPAecoCRT("rand");
	 _srand    = (DWORD *)_GPAecoCRT("srand");
	 _strcat   = (DWORD *)_GPAecoCRT("strcat");
	 _vsprintf = (DWORD *)_GPAecoCRT("vsprintf"); //@E
	*/

	//_strcpy   = (DWORD *)_GPAecoCRT("strcpy");
}
