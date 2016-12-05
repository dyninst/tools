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

vector<string> extendInsns = {"uxtb", "uxth", "sxtb", "sxth", "sxtw"};
vector<string> shiftInsns = {"lsl", "lsr", "asr"};
bool isExtendInsn, isShiftInsn;

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

    /****************************************/
    /*Instruction boundary recognition rules*/
    /****************************************/

##[a-z_]+   {
                yylval->strVal = new string(yytext+2);

                string subInsn = *(yylval->strVal);
                subInsn = subInsn.substr(0, subInsn.find("_"));
                if(find(extendInsns.begin(), extendInsns.end(), subInsn) != extendInsns.end())
                    isExtendInsn = true;
                else if(find(shiftInsns.begin(), shiftInsns.end(), subInsn) != shiftInsns.end())
                    isShiftInsn = true;

                labelPos = 0;
                return token::INSN_START;
            }

@@          {
                isExtendInsn = isShiftInsn = false;
                return token::INSN_END;
            }


    /****************************************/
    /*           bool declarations          */
    /****************************************/

boolean              {
                        yylval->strVal = new string("bool");
                        return token::DTYPE;
                     }

TRUE|FALSE           {
                        string matched(yytext);
                        transform(matched.begin(), matched.end(), matched.begin(), ::tolower);
                        yylval->strVal = new string(matched);
                        return token::BOOLVAL;
                     }


    /****************************************/
    /*             Special Cases            */
    /****************************************/

    /* Setting the link register is identified by the presence of "branch_type" keyword.
       This is not included in the generic rules because of the enum used for branch types
       which was adding an unnecessary complexity even though its use is very limited.     */
if\ branch_type[^_]+_CALL[^\n]+\n    {	 return token::SET_LR;   }

    /* This can probably be merged with a generic declaration detection case. */
bits\(64\)\ base\ =\ PC\[\];\n       {   return token::READ_PC;  }

(SP|W|X)\[[a-z]?[2]?\]                   {
                                         string matched(yytext);

                                         if(matched.find("SP") != string::npos)
                                            yylval->strVal = new string("s");
                                         else
                                         {
                                            int startpos = matched.find("["), endpos = matched.find("]");
                                            yylval->strVal = new string(matched.substr(startpos + 1, endpos - startpos - 1));
                                         }

                                         return token::REG;
                                     }

PSTATE[^<]C                          {   return token::FLAG_CARRY;   }

PSTATE\.<[^;]+                       {
                                         string matched(yytext);
                                         yylval->strVal = new string(matched.substr(matched.find("=") + 2));

                                         return token::SET_NZCV;
                                     }

address\ =\ (SP|(X|W)\[[a-z]\])[^\n]+		     {
                                                    yylval->strVal = new string(yytext);
                                                    return token::IGNORE;
                                                 }

((Extend|Shift)Reg)\([^\)]+\)                 {
                                                 yylval->strVal = new string("d->read(args[2])");
                                                 return token::OPERAND;
                                              }

    /****************************************/
    /*        Instruction Operands          */
    /****************************************/

bits\((datasize|64)\)\ (address|target|result|(operand[1|2]?))[^\n]+\n    {
                                                                               int operandIdx = -1;
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
                                                                                    val<<" = d->"<<(matched.find("address") == string::npos?"read":"effectiveAddress")<<
                                                                                         "(args["<<operandPosMap[operandName]<<"])";
                                                                               }
                                                                               val<<";\n";
                                                                               labelPos++;

                                                                               yylval->strVal = new string(val.str());
                                                                               return token::OPERAND;
                                                                           }

imm|bit_pos                 {
                                yylval->strVal = new string("d->read(args[1])");
                                labelPos++;
                                return token::OPERAND;
                            }

PC\[\]\ \+\ offset   {
                        stringstream out;
                        out<<"d->read(args["<<labelPos<<"])";

                        yylval->strVal = new string(out.str());
                        return token::OPERAND;
                     }

R|S                    {
                            stringstream out;
                            if(!isExtendInsn)
                            {
                                if(isShiftInsn && yytext[0] == 'S')
                                    out<<"ops->number_(32, EXTR(10, 15))";
                                else
                                {
                                    out<<"d->read(args[";
                                    out<<2 + (yytext[0] - 'R');
                                    out<<"])";
                                }
                            }
                            else
                            {
                                if(yytext[0] == 'R')
                                    out<<"ops->number_(32, EXTR(16, 21))";
                                else
                                    out<<"ops->number_(32, EXTR(10, 15))";
                            }

                            yylval->strVal = new string(out.str());
                            return token::OPERAND;
                       }


    /****************************************/
    /*     Pseudocode keywords/symbols      */
    /****************************************/

if          {   return token::COND_IF;   }

then        {   return token::COND_THEN; }

else        {   return token::COND_ELSE; }

elsif       {   return token::COND_ELSIF; }

end         {   return token::COND_END; }

case	    {	return token::SWITCH_CASE;  }

when	    {	return token::SWITCH_WHEN;  }

of	        {	return token::SWITCH_OF;    }

\<	        {	return token::SYMBOL_LT;    }

>	        {	return token::SYMBOL_GT;    }

:	        {	return token::SYMBOL_COLON;	}

=           {   return token::SYMBOL_EQUAL;    }

\(          {   return token::SYMBOL_OPENROUNDED;  }

\[          {   return token::SYMBOL_OPENSQUARE; }

\]          {   return token::SYMBOL_CLOSESQUARE;   }

\)          {   return token::SYMBOL_CLOSEROUNDED; }

,           {   return token::SYMBOL_COMMA;    }

UNKNOWN	    {	return token::UNKNOWN;	}

Mem         {   return token::MEMORY;   }

[ \t;\n]    ;

!=|!|\+|==|\/|\-|\*|&&|\|\||AND|OR|EOR  	{
                                                yylval->strVal = new string(yytext);
                                                return token::OPER;
                                            }



bit(s\(((datasize|[0-9]+)|([a-z]+\*[0-9]+))\))?     {
                                                        yylval->strVal = new string("BaseSemantics::SValuePtr");
                                                        return token::DTYPE;
                                                    }

(constant\ )?integer    {
                            yylval->strVal = new string("int");
                            return token::DTYPE;
                        }

    /****************************************/
    /*        Variables and literals        */
    /****************************************/

[0-9]+           {
                    yylval->intVal = atoi(yytext);
                    return token::NUM;
                 }

[A-Za-z_]+[0-9]* {
                    string *ret = new string(yytext);

                    /*//FIXME should probably have a table of IDs seen so far and perform a join-like check
                    if(*ret == "offset")
                        *ret = "d->read(args[2])";*/
                    yylval->strVal = ret;
                    return token::IDENTIFIER;
                 }

    
    /****************************************/
    /*        Ignore everything else        */
    /****************************************/
\/\/[^\n]+    ;

.           ;
%%

namespace Dyninst_aarch64 {

map<string, string> Scanner::operandExtractorMap;
map<string, string> Scanner::operatorToFunctionMap;
vector<string> Scanner::ignoreOperands;
map<string, int> Scanner::operandPosMap;
map<string, string> Scanner::newSymbolType, Scanner::newSymbolVal;

Scanner::Scanner(istream* instream,
		 ostream* outstream)
    : yyFlexLexer(instream, outstream)
{
    initOperandExtractorMap();
    initOperatorToFunctionMap();
    initIgnoreOperands();
    initOperandPosMap();
    initNewSymbolMaps();
}

Scanner::~Scanner()
{
}

void Scanner::initOperandExtractorMap() {
    operandExtractorMap["sub_op"] = "(EXTR(30, 30) == 1)";
    operandExtractorMap["setflags"] = "d->setflags(raw)";
    operandExtractorMap["d"] = operandExtractorMap["t"] = "EXTR(0, 4)";
    operandExtractorMap["n"] = "EXTR(5, 9)";
    operandExtractorMap["t2"] = "EXTR(10, 14)";
    operandExtractorMap["condition"] = "EXTR(0, 4)";
    operandExtractorMap["page"] = "(EXTR(31, 31) == 1)";
    operandExtractorMap["postindex"] = "(EXTR(11, 11) == 0 && EXTR(24, 24) == 0)";
    operandExtractorMap["iszero"] = "(EXTR(24, 24) == 0)";
    operandExtractorMap["bit_val"] = "EXTR(24, 24)";
    operandExtractorMap["memop"] = "(EXTR(22, 22)^EXTR(23, 23))";
    operandExtractorMap["signed"] = "(EXTR(23, 23) == 1)";
    operandExtractorMap["regsize"] = "d->getRegSize(raw)";
    operandExtractorMap["wback"] = "((EXTR(24, 24) == 0) && EXTR(21, 21) == 0)";
    operandExtractorMap["inzero"] = "d->inzero(raw)";
    operandExtractorMap["opcode"] = "EXTR(29, 30)";
    operandExtractorMap["extend"] = "d->extend(raw)";
    operandExtractorMap["pos"] = "(EXTR(21, 22) << 4)";\
    operandExtractorMap["op"] = "d->op(raw)";
    operandExtractorMap["invert"] = "(EXTR(21, 21) == 1)";
    operandExtractorMap["datasize"] = "d->getDatasize(raw)";
}

void Scanner::initOperatorToFunctionMap() {
    operatorToFunctionMap["+"] = "ops->add";
    operatorToFunctionMap["=="] = "ops->isEqual";
    operatorToFunctionMap["&&"] = "ops->null";
    operatorToFunctionMap["!"] = "ops->null";
}

void Scanner::initIgnoreOperands() {
    ignoreOperands.push_back("wb_unknown");
    ignoreOperands.push_back("rt_unknown");
}

void Scanner::initOperandPosMap() {
    operandPosMap["target"] = 0;
    operandPosMap["address"] = 1;
}

void Scanner::initNewSymbolMaps() {
    newSymbolType["wmask"] = "BaseSemantics::SValuePtr";
    newSymbolType["tmask"] = "BaseSemantics::SValuePtr";
    newSymbolType["result"] = "BaseSemantics::SvaluePtr";

    newSymbolVal["wmask"] = "d->getBitfieldMask(EXTR(16, 21), EXTR(10, 15), EXTR(22, 22), true, (EXTR(31, 31) + 1) * 32)";
    newSymbolVal["tmask"] = "d->getBitfieldMask(EXTR(16, 21), EXTR(10, 15), EXTR(22, 22), false, (EXTR(31, 31) + 1) * 32)";
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