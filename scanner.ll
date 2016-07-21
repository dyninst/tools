%{

#include <cstdlib>
#include <sstream>
#include <string>
#include "scanner.h"

typedef Dyninst_aarch64::Parser::token token;
typedef Dyninst_aarch64::Parser::token_type token_type;

#define yyterminate() return token::END

int labelPos;

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
                labelPos = 0;
                return token::INSN_START;
            }

@@          {   return token::INSN_END;    }

bits\((datasize|64)\)\ (target|result|(operand[1|2]?))[^\n]+\n    {
                                                                   int operandIdx;
                                                                   std::stringstream val;
                                                                   std::string matched(yytext);

                                                                   if(matched.find("target") == std::string::npos)
                                                                   {
                                                                       if(matched.find(std::string("result")) != std::string::npos)
                                                                           operandIdx = 0;

                                                                       val<<"BaseSemantics::SValuePtr "<<matched.substr(15, operandIdx == 0?6:8);
                                                                       if(operandIdx != 0)
                                                                       {
                                                                           char idxChar = *(yytext + 22);
                                                                           operandIdx = (matched.find("X[t]") != std::string::npos)?0:(idxChar == '1')?1:2;
                                                                           val<<" = d->read(args["<<operandIdx<<"])";
                                                                       }
                                                                   }
                                                                   else
                                                                   {
                                                                        val<<"BaseSemantics::SValuePtr "<<matched.substr(9, 6);
                                                                        val<<" = d->read(args[0])";
                                                                   }
                                                                   val<<";";
                                                                   labelPos++;

                                                                   yylval->strVal = new std::string(val.str());
                                                                   return token::OPERAND;
                                                               }

bits\(64\)\ base\ =\ PC\[\] {   return token::READ_PC;  }

if\ branch_type[^_]+_CALL[^\n]+\n    {	return token::SET_LR;   }

imm|bit_pos                 {
                                yylval->strVal = new std::string("d->read(args[0])");
                                labelPos++;
                                return token::OPERAND;
                            }

PC\[\]\ \+\ offset   {
                        std::stringstream out;
                        out<<"d->read(args["<<labelPos<<"])";

                        yylval->strVal = new std::string(out.str());
                        return token::OPERAND;
                     }

bit(s\([0-9]\))?     {  return token::DTYPE_BITS;   }

AddWithCarry|Zeros|NOT|BranchTo|ConditionHolds|IsZero	      {
                                                                yylval->strVal = new std::string(yytext);
                                                                return token::FUNCNAME;
                                                              }

if          {   return token::COND_IF;   }

then        {   return token::COND_THEN; }

else        {   return token::COND_ELSE; }

end         {   return token::COND_END; }

\<	        {	return token::SYMBOL_LT;    }

>	        {	return token::SYMBOL_GT;    }

:	        {	return token::SYMBOL_COLON;	}

!|\+|==|&&		{
                    yylval->strVal = new std::string(yytext);
                    return token::OPER;
			    }

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
std::map<std::string, std::string> Scanner::operatorToFunctionMap;

Scanner::Scanner(std::istream* instream,
		 std::ostream* outstream)
    : yyFlexLexer(instream, outstream)
{
    initOperandExtractorMap();
    initOperatorToFunctionMap();
}

Scanner::~Scanner()
{
}

void Scanner::initOperandExtractorMap() {
    operandExtractorMap[std::string("sub_op")] = std::string("(EXTR(30, 30) == 1)");
    operandExtractorMap[std::string("setflags")] = std::string("(EXTR(29, 29) == 1)");
    operandExtractorMap[std::string("d")] = std::string("EXTR(0, 4)");
    operandExtractorMap[std::string("condition")] = std::string("EXTR(0, 4)");
    operandExtractorMap[std::string("page")] = std::string("(EXTR(31, 31) == 1)");
    operandExtractorMap[std::string("iszero")] = std::string("(EXTR(24, 24) == 0)");
    operandExtractorMap[std::string("bit_val")] = std::string("EXTR(24, 24)");
}

void Scanner::initOperatorToFunctionMap() {
    operatorToFunctionMap[std::string("+")] = std::string("ops->add");
    operatorToFunctionMap[std::string("==")] = std::string("ops->isEqual");
    operatorToFunctionMap[std::string("&&")] = std::string("ops->null");
    operatorToFunctionMap[std::string("!")] = std::string("ops->null");
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
