
///////////////////////////////////////////////////////////////
// structures for memory access ///////////////////////////////

 typedef struct wMEMORY_STRUCT{
  WORD word0;        
 } wMEMORY;

 typedef struct dMEMORY_STRUCT{
  DWORD dword0;        
 } dMEMORY;

///////////////////////////////////////////////////////////////
// Check is system NT or not //////////////////////////////////

BOOL SYSTEM_NT=FALSE;
DWORD MAJORW=0;

BOOL isSystemNT()
{
	OSVERSIONINFO osver;

	if (MAJORW != 0)
		return SYSTEM_NT;
	
	osver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO); 
	_GetVersionEx(&osver);

	if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
		SYSTEM_NT=TRUE;
	MAJORW = osver.dwMajorVersion;

	return SYSTEM_NT;
}

///////////////////////////////////////////////////////////////
// CloseCreateThread Economy //////////////////////////////////
void CloseCreateThreadEco(LPTHREAD_START_ROUTINE sr)
{
	DWORD tid;
	_CloseHandle(_CreateThread(NULL, 0, sr, NULL, 0, &tid));
}

