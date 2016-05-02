%{

#include <string>
#include "scanner.h"

typedef Dyninst_aarch64::Parser::token token;
typedef Dyninst_aarch64::Parser::token_type token_type;

#define yyterminate() return token::END

%}

%option c++

%option batch

%{
#define YY_USER_ACTION  yylloc->columns(yyleng);
%}

%%

%{
    yylloc->step();
%}

%%

namespace Dyninst_aarch64 {

Scanner::Scanner(std::istream* in,
		 std::ostream* out)
    : yyFlexLexer(in, out)
{
}

Scanner::~Scanner()
{
}

}

#ifdef yylex
#undef yylex
#endif

int yyFlexLexer::yylex()
{
    return 0;
}

int yyFlexLexer::yywrap()
{
    return 1;
}
