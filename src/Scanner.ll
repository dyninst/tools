%{

#include <string>
#include "Scanner.h"

#define yyterminate() return token::END

%}

%option c++

%{

#define YY_USER_ACTION  yylloc->columns(yyleng);

%}

%%

%{

yylloc->step();

%}

%%

#ifdef  yylex
#undef  yylex
#endif

int yyFkexLexer::yylex() {
    return 0;
}

int yyFlexLexer::yywrap() {
    return 1;
}
