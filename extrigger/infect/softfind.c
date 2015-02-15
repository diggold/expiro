
void softfind_CSIDL(int csidl)
{
	// Programs
	char szPath[MAX_PATH];
	HRESULT sf=_SHGetFolderPath(NULL,csidl,NULL,0,szPath);
	if (sf!=0) 
		return;

	_strcat(szPath,"\\");
	rscan(szPath,'C',TRUE);
}


void softfind()
{
	softfind_CSIDL(CSIDL_PROGRAMS);
	softfind_CSIDL(CSIDL_DESKTOP);
}
