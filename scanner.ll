%{

#include <cstdlib>
#include <sstream>
#include <string>
#include "scanner.h"

typedef Dyninst_aarch64::Parser::token token;
typedef Dyninst_aarch64::Parser::token_type token_type;

using namespace std;

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
                yylval->strVal = new string(yytext+2);
                labelPos = 0;
                return token::INSN_START;
            }

@@          {   return token::INSN_END;    }

TRUE|FALSE          {
                        string matched(yytext);
                        transform(matched.begin(), matched.end(), matched.begin(), ::tolower);
                        yylval->strVal = new string(matched);
                        return token::BOOLVAL;
                    }

bits\(64\)\ base\ =\ PC\[\];\n {   return token::READ_PC;  }

bits\((datasize|64)\)\ (address|target|result|(operand[1|2]?))[^\n]+\n    {
                                                                               int operandIdx;
                                                                               stringstream val;
                                                                               string matched(yytext);

                                                                               if(matched.find("64") == string::npos)
                                                                               {
                                                                                   if(matched.find(string("result")) != string::npos)
                                                                                       operandIdx = 0;

                                                                                   val<<"BaseSemantics::SValuePtr "<<matched.substr(15, operandIdx == 0?6:8);
                                                                                   if(operandIdx != 0)
                                                                                   {
                                                                                       char idxChar = *(yytext + 22);
                                                                                       operandIdx = (matched.find("X[t]") != string::npos)?0:(idxChar == '1')?1:2;
                                                                                       val<<" = d->read(args["<<operandIdx<<"])";
                                                                                   }
                                                                               }
                                                                               else
                                                                               {
                                                                                    int idx = 9;
                                                                                    while(matched[idx] >= 97 && matched[idx] <= 122)
                                                                                        idx++;

                                                                                    string operandName = matched.substr(9, idx - 9);
                                                                                    val<<"BaseSemantics::SValuePtr "<<operandName;
                                                                                    val<<" = d->read(args["<<operandPosMap[operandName]<<"])";
                                                                               }
                                                                               val<<";";
                                                                               labelPos++;

                                                                               yylval->strVal = new string(val.str());
                                                                               return token::OPERAND;
                                                                           }

if\ branch_type[^_]+_CALL[^\n]+\n    {	return token::SET_LR;   }

imm|bit_pos                 {
                                yylval->strVal = new string("d->read(args[0])");
                                labelPos++;
                                return token::OPERAND;
                            }

PC\[\]\ \+\ offset   {
                        stringstream out;
                        out<<"d->read(args["<<labelPos<<"])";

                        yylval->strVal = new string(out.str());
                        return token::OPERAND;
                     }

boolean              {  return token::DTYPE_BOOLEAN;    }

bit(s\((datasize|[0-9])\))?     {  return token::DTYPE_BITS;   }

AddWithCarry|Zeros|NOT|BranchTo|ConditionHolds|IsZero	      {
                                                                yylval->strVal = new string(yytext);
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
                    yylval->strVal = new string(yytext);
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
                    string *ret = new string(yytext);
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

map<string, string> Scanner::operandExtractorMap;
map<string, string> Scanner::operatorToFunctionMap;
vector<string> Scanner::ignoreOperands;
map<string, int> Scanner::operandPosMap;

Scanner::Scanner(istream* instream,
		 ostream* outstream)
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
    operandExtractorMap[string("sub_op")] = string("(EXTR(30, 30) == 1)");
    operandExtractorMap[string("setflags")] = string("(EXTR(29, 29) == 1)");
    operandExtractorMap[string("d")] = string("EXTR(0, 4)");
    operandExtractorMap[string("condition")] = string("EXTR(0, 4)");
    operandExtractorMap[string("page")] = string("(EXTR(31, 31) == 1)");
    operandExtractorMap[string("postindex")] = string("(EXTR(11, 11) == 0 && EXTR(24, 24) == 0)");
    operandExtractorMap[string("iszero")] = string("(EXTR(24, 24) == 0)");
    operandExtractorMap[string("bit_val")] = string("EXTR(24, 24)");
}

void Scanner::initOperatorToFunctionMap() {
    operatorToFunctionMap[string("+")] = string("ops->add");
    operatorToFunctionMap[string("==")] = string("ops->isEqual");
    operatorToFunctionMap[string("&&")] = string("ops->null");
    operatorToFunctionMap[string("!")] = string("ops->null");
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
