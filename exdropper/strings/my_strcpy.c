
///////////////////////////////////////////////////////////////
// my strcpy function ////////////////////////////////////////
//algo here is not optimal, becouse this code often used by mcafee as signature
int my_strcpy(char *s1,char *s2)
{
	DWORD q=0;

	loop:;
	s1[q]=s2[q];
	if (s2[q]!=0) 
	{
		q++; 
		goto loop;
	}
}
