%{

#include <cstdlib>
#include <sstream>
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

##[a-z_]+   {   std::cout<<"case "<<(yytext+2)<<":\n{\n";    }

@@          {   std::cout<<"\n}\nbreak;";    }

bits\(datasize\)\ (result|(operand[1|2]))[^\n]+\n    {
                                               int operandIdx;
                                               std::stringstream val;
                                               if(std::string(yytext).find(std::string("result")) != std::string::npos)
                                                   operandIdx = 0;
                                               else
                                                   operandIdx = (*(yytext + 22)) == '1'?1:2;
                                               val<<"uint32_t "<<std::string(yytext).substr(15, operandIdx == 0?6:8)<<" = policy.readGPR(operands["<<operandIdx<<"]);\n";
                                               yylval->strVal = new std::string(val.str());
                                               return token::OPERAND;
                                           }

bit(s\([0-9]\))?     {   return token::DTYPE_BITS;   }

NOT         {   return token::FUNC_NOT;  }

if          {   return token::COND_IF;   }

then        {   return token::COND_THEN; }

else        {   return token::COND_ELSE; }

case        {   return token::COND_CASE;  }

of          {   return token::COND_OF;  }

when        {   return token::COND_WHEN;    }

[0-9]+      {
                yylval->intVal = atoi(yytext);
                return token::NUM;
            }

[A-Za-z_]+[0-9]* {
                    yylval->strVal = new std::string(yytext);
                    return token::IDENTIFIER;
                 }

=           {   return token::SYMBOL_EQUAL;    }

\(          {   return token::SYMBOL_OPENROUNDED;  }

\)          {   return token::SYMBOL_CLOSEROUNDED; }

,           {   return token::SYMBOL_COMMA;    }

[ \t;\n]    ;

.           ;


%%

namespace Dyninst_aarch64 {

std::map<std::string, std::string> Scanner::operandExtractorMap;

Scanner::Scanner(std::istream* instream,
		 std::ostream* outstream)
    : yyFlexLexer(instream, outstream)
{
}

Scanner::~Scanner()
{
}

void Scanner::initOperandExtractorMap() {
    operandExtractorMap["sf"] = "field<31, 31>(insn)";
    operandExtractorMap["Rd"] = "field<0, 4>(insn)";
    operandExtractorMap["Rn"] = "field<5, 9>(insn)";
    operandExtractorMap["imm12"] = "field<10, 21>(insn)";
    operandExtractorMap["shift"] = "field<22, 23>(insn)";
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
