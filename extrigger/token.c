#ifdef dbgdbg

void Sid2Text( PSID ps, char *buf )
{
	PSID_IDENTIFIER_AUTHORITY psia; 
	DWORD dwSubAuthorities;
	DWORD dwSidRev = 1; //SID_REVISION;
	DWORD i;
	int n,size;
	char *p;                        

	// Get the identifier authority value from the SID.
	psia = _GetSidIdentifierAuthority( ps );           

	// Get the number of subauthorities in the SID.
	dwSubAuthorities = *_GetSidSubAuthorityCount( ps ); 

	// Compute the buffer length.
	// S-SID_REVISION- + IdentifierAuthority- + subauthorities- + NULL
	size = 15 + 12 + ( 12 * dwSubAuthorities ) + 1;

	// Add 'S' prefix and revision number to the string.
	size = _sprintf( buf, "S-%lu-", dwSidRev );
	p = buf + size;

	// Add SID identifier authority to the string.
	if (psia->Value[0] != 0 || psia->Value[1] != 0 )
	{
		n = _sprintf(p,"0x%02hx%02hx%02hx%02hx%02hx%02hx",
		(USHORT) psia->Value[0], (USHORT) psia->Value[1],
		(USHORT) psia->Value[2], (USHORT) psia->Value[3],
		(USHORT) psia->Value[4], (USHORT) psia->Value[5] );
		size += n; p += n;    
	}
	else
	{
		n = _sprintf(p,"%lu", ( (ULONG) psia->Value[5] ) +
		( (ULONG) psia->Value[4] << 8 ) + ( (ULONG) psia->Value[3] << 16 ) +
		( (ULONG) psia->Value[2] << 24 ) );
		size += n; p += n; 
	}

	// Add SID subauthorities to the string.
	for (i = 0; i < dwSubAuthorities; ++ i )
	{
		n = _sprintf( p, "-%lu", *_GetSidSubAuthority( ps, i ) );
		size += n; p += n;   
	}
}

#endif

////////////////////////////////////////////////////////

TOKEN_USER *ptu = NULL;
SECURITY_DESCRIPTOR *sdsc2 = NULL;

int EditOwnToken_or_CheckFiltered(BOOL CHKFILTONLY)
{	
	TOKEN_PRIVILEGES tp;
	HANDLE htk = NULL;
	HANDLE hprc = NULL;
	BOOL res;
	DWORD pid;

	DWORD tbf[10];     
	DWORD rl;

	if (isSystemNT() == 0) 
	{ 
		res=1; 
		goto exiteot; 
	}                          

	//vozmojno GetCurrentProcess() eto toje samoe chto OpenProcess(GetCurrentProcessId())
	//vozvrashaet s urovnem dostupa PROCESS_ALL_ACCESS

	pid = _GetCurrentProcessId();

	hprc = _OpenProcess(PROCESS_ALL_ACCESS,0,pid);
	res = _OpenProcessToken(hprc,TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&htk);

	if (res==0)
		goto exiteot;

	// check if token filtered 
	tbf[0] = 0;
	// 21=TokenHasRectrictions
	res=_GetTokenInformation(htk,21,&tbf[0],sizeof(tbf),&rl); 

	// only check is token filtered
	if (CHKFILTONLY!=0) 
	{
		if (res==0)
		{ 
			res=1;
			goto exiteot; 
		} // "not filtered" (xp/2k case GTI fail)
		res=1;
		if (tbf[0]!=0) 
			res=0; // "token filtered or error"
		goto exiteot;         
	}

	if (ptu==NULL) 
		ptu = (TOKEN_USER*)_LocalAlloc(LPTR,16384);
	_GetTokenInformation(htk,TokenUser,ptu,16384,&rl);


	// create our security descriptor
	if (sdsc2==NULL)
		sdsc2 = _LocalAlloc(LMEM_FIXED,SECURITY_DESCRIPTOR_MIN_LENGTH); 

	res=_InitializeSecurityDescriptor(sdsc2,SECURITY_DESCRIPTOR_REVISION); 

	//no DACL-unprotected
	res=_SetSecurityDescriptorDacl(sdsc2,TRUE,NULL,FALSE); 

	res=_SetSecurityDescriptorOwner(sdsc2,(ptu->User.Sid),FALSE);


	// set SE_TAKE_OWNERSHIP privilege
	res=_LookupPrivilegeValue(NULL,"SeTakeOwnershipPrivilege",&(tp.Privileges[0].Luid)); 


	if (res==0) 
		goto exiteot;

	tp.PrivilegeCount = 1;                               
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	res=_AdjustTokenPrivileges(htk,FALSE,&tp,0,NULL,NULL); 

	exiteot:;
	_CloseHandle(htk);
	_CloseHandle(hprc);
	return res;
}
