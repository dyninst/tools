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

##[a-z_]+   {
                yylval->strVal = new std::string(yytext+2);
                return token::INSN_START;
            }

@@          {   return token::INSN_END;    }

bits\(datasize\)\ (result|(operand[1|2]))[^\n]+\n    {
                                               int operandIdx;
                                               std::stringstream val;

                                               if(std::string(yytext).find(std::string("result")) != std::string::npos)
                                                   operandIdx = 0;

                                               val<<"uint32_t "<<std::string(yytext).substr(15, operandIdx == 0?6:8);
                                               if(operandIdx != 0)
                                               {
                                                   operandIdx = (*(yytext + 22)) == '1'?1:2;
                                                   val<<" = policy.readGPR(operands["<<operandIdx<<"])";
                                               }
                                               val<<";";
                                               yylval->strVal = new std::string(val.str());
                                               return token::OPERAND;
                                           }

bits\(64\)\ base\ =\ PC\[\] {   return token::READ_PC;  }

imm                 {
                        yylval->strVal = new std::string("policy.readOperand(1)");
                        return token::OPERAND;
                    }

bit(s\([0-9]\))?     {   return token::DTYPE_BITS;   }

NOT         {   return token::FUNC_NOT;  }

AddWithCarry    {   return token::FUNC_AWC; }

Zeros       {   return token::FUNC_ZEROS;   }

if          {   return token::COND_IF;   }

then        {   return token::COND_THEN; }

else        {   return token::COND_ELSE; }

end         {   return token::COND_END; }

\<			{	return token::OPER_LT;	}

>			{	return token::OPER_GT;	}

:			{	return token::SYMBOL_COLON;	}

!           {   return token::OPER_NOT; }

\+           {   return token::OPER_ADD; }

==          {   return token::OPER_DBLEQUAL;    }

&&          {   return token::OPER_AND; }

(SP|W|X)\[[a-z]?\]      {  return token::REG;  }

PSTATE[^<]C    {   return token::FLAG_CARRY;   }

PSTATE\.<[^\n]+  {   return token::SET_NZCV;     }

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
    initOperandExtractorMap();
}

Scanner::~Scanner()
{
}

void Scanner::initOperandExtractorMap() {
    operandExtractorMap[std::string("sub_op")] = std::string("(field<30, 30>(insn) == 1)");
    operandExtractorMap[std::string("setflags")] = std::string("(field<29, 29>(insn) == 1)");
    operandExtractorMap[std::string("d")] = std::string("(field<0, 4>(insn))");
    operandExtractorMap[std::string("page")] = std::string("(field<31, 31>(insn) == 1)");
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
