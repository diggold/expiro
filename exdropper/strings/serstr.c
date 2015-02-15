
///////////////////////////////////////////////////////////////////////////
// Search substring in string ////////////////////////////////////////////
int serstr(char *s1, char *s2, int pos)
{
	DWORD q;
	DWORD w;
	DWORD e;
	DWORD p=0;     

	DWORD l1=strlen(s1);
	DWORD l2=strlen(s2);

	for (q=0;q<l1;q++)
	{
		e=0;
		for (w=0;w<l2;w++)
		{
			if (s1[q+w] == s2[w]) 
				e++;
			else 
				break;
			if (e == l2) 
			{ 
				p++; 
				if (p == pos)
					return q;
			}
		}
	}
	return 0xffff;
}

