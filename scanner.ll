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

TRUE|FALSE          {
                        std::string matched(yytext);
                        std::transform(matched.begin(), matched.end(), matched.begin(), ::tolower);
                        yylval->strVal = new std::string(matched);
                        return token::BOOLVAL;
                    }

bits\(64\)\ base\ =\ PC\[\];\n {   return token::READ_PC;  }

bits\((datasize|64)\)\ (address|target|result|(operand[1|2]?))[^\n]+\n    {
                                                                               int operandIdx;
                                                                               std::stringstream val;
                                                                               std::string matched(yytext);

                                                                               if(matched.find("64") == std::string::npos)
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
                                                                                    int idx = 9;
                                                                                    while(matched[idx] >= 97 && matched[idx] <= 122)
                                                                                        idx++;

                                                                                    std::string operandName = matched.substr(9, idx - 9);
                                                                                    val<<"BaseSemantics::SValuePtr "<<operandName;
                                                                                    val<<" = d->read(args["<<operandPosMap[operandName]<<"])";
                                                                               }
                                                                               val<<";";
                                                                               labelPos++;

                                                                               yylval->strVal = new std::string(val.str());
                                                                               return token::OPERAND;
                                                                           }

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

boolean              {  return token::DTYPE_BOOLEAN;    }

bit(s\((datasize|[0-9])\))?     {  return token::DTYPE_BITS;   }

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
                    std::string *ret = new std::string(yytext);
                    //FIXME should probably have a table of IDs seen so far and perform a join-like check
                    if(*ret == "offset")
                        *ret = "d->read(args[2])";
                    yylval->strVal = ret;
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
std::vector<std::string> Scanner::ignoreOperands;
std::map<std::string, int> Scanner::operandPosMap;

Scanner::Scanner(std::istream* instream,
		 std::ostream* outstream)
    : yyFlexLexer(instream, outstream)
{
    initOperandExtractorMap();
    initOperatorToFunctionMap();
    initIgnoreOperands();
    initOperandPosMap();
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
    operandExtractorMap[std::string("postindex")] = std::string("(EXTR(11, 11) == 0 && EXTR(24, 24) == 0)");
    operandExtractorMap[std::string("iszero")] = std::string("(EXTR(24, 24) == 0)");
    operandExtractorMap[std::string("bit_val")] = std::string("EXTR(24, 24)");
}

void Scanner::initOperatorToFunctionMap() {
    operatorToFunctionMap[std::string("+")] = std::string("ops->add");
    operatorToFunctionMap[std::string("==")] = std::string("ops->isEqual");
    operatorToFunctionMap[std::string("&&")] = std::string("ops->null");
    operatorToFunctionMap[std::string("!")] = std::string("ops->null");
}

void Scanner::initIgnoreOperands() {
    ignoreOperands.push_back("wb_unknown");
    ignoreOperands.push_back("rt_unknown");
}

void Scanner::initOperandPosMap() {
    operandPosMap["target"] = 0;
    operandPosMap["address"] = 1;
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
