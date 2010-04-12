%a 3300
%o 5000
%k 2000
%p 2000

unknown		[a-z]+
integer		[0-9]
white_space	[ \t\n]
ip_addr		([0-9]{1,3}\.){3}([0-9]{1,3})
passwd		\"([0-9a-zA-Z])*\"
comments	"#".*
%{
	#include "y.tab.h"
	#include "vrrpd.h"
	char l_strbuf[AUTH_PWD_BUF];
	int yylval;
	FILE * yyin;
%}

%%
{white_space}	;
{comments}	;

"interface"	{
			return KW_INTERFACE;
		}

"vrouter"	{
			return KW_VROUTER;
		}

"adverinterval"	{
			return KW_ADVERINT;
		}

"priority"	{
			return KW_PRIORITY;
		}

"preempt"	{
                        return KW_PREEMPT;
		}

"true"		{	
			yylval = 1;
			return INTEGER;
		}

"false"		{
			yylval = 0;
			return INTEGER;
		}

"low"		{
			yylval = 0;
			return INTEGER;
		}

"med"		{
			yylval = 1;
			return INTEGER;
		}

"high"		{
			yylval = 2;
			return INTEGER;
		}

"iplist"	{
			return KW_IPLIST;
		}

"auth"		{
			return KW_AUTH;
		}



"simple"	{
			yylval = 1;
			return INTEGER;
		}

"none"		{
			yylval = 0;
			return INTEGER;
		}


{ip_addr}	{
			yylval = inet_addr(yytext);
			return INTEGER;
		}

{integer}+	{
			yylval = atoi(yytext);
			return INTEGER;
		}

";"		{
			return EOS;
		}

"{"		{
			return BRA;
		}
"}"		{
			return KET;
		}

{passwd}	{
			bzero(l_strbuf, AUTH_PWD_BUF);
			memcpy(l_strbuf, yytext+1, yyleng - 2);
			return AUTH_PWD;	
		}	

{unknown}	{
			printf("unknown token: %s\n", yytext);
			exit(1);
		}
%%

int yywrap(void) {
    return 1;
}


