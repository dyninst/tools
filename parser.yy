%{
#include <iostream>
#include <cstdio>
#include <cassert>
#include <algorithm>
#include <string>
#include <vector>
#include <sstream>
#include <stdint.h>
#include "scanner.h"

using namespace std;

#define STR(s)  new string(s)
#define ARGS_VEC(arglist...)    vector<string> args = {arglist}
#define DEL_VEC(arglist...)     vector<string *> del = {arglist}
#define DEL_VEC_ADD(arg)        del.push_back(arg)

bool foundNewSymbol = false;
vector<string> newSymbols;
vector<string> symbols;

void getBitMaskParts(string in, string &var, string &start, string &end) {
    size_t lbar = in.find("|"), rbar = in.find("|", lbar + 1);

    var = in.substr(0, lbar);
    end = in.substr(lbar + 1, rbar - lbar - 1);
    start = in.substr(rbar + 1);
}

void parseBitPos(string bmask, string repltarg, string &res) {
    string var, start, end;
    getBitMaskParts(bmask, var, start, end);

    stringstream top, bottom;
    bottom<<((start != "0")?("ops->extract(" + var + ", 0, " + start + ")"):var);
    top<<"ops->extract("<<var<<", "<<end<<" + 1, "<<var<<"->get_width())";

    stringstream ret, mid;
    ret<<var<<" = ";

    mid<<"ops->or_(ops->shiftLeft("<<repltarg<<", ops->number_(32, "<<start<<")), ";
    mid<<" ops->shiftLeft("<<top.str()<<", ops->number_(32, "<<end<<" + 1)))";

    if(bottom.str()== var)
    {
        ret<<mid.str()<<";";
    }
    else
    {
        ret<<"ops->or_("<<bottom.str()<<", "<<mid.str()<<");";
    }

    res = ret.str();
}

void delArgs(vector<string *> del) {
    for(int i = 0; i < del.size(); i++)
        delete del[i];
}

string makeStr(vector<string> &args, vector<string *> *del) {
    int len = 0;
    for(int i = 0; i < args.size(); i++)
        len += args[i].size();

    string ret;
    ret.reserve(len);

    for(int i = 0; i < args.size(); i++)
        ret += args[i];

    if(del != NULL)
        delArgs(*del);

    return ret;
}

string *makeProgramBlock(string *arg1, string *arg2) {
    stringstream out;
    out<<"";

    if(foundNewSymbol)
    {
        for(vector<string>::iterator i = newSymbols.begin(); i != newSymbols.end(); i++)
        {
            if(Dyninst_aarch64::Scanner::newSymbolType.count(*i))
            {
                out<<Dyninst_aarch64::Scanner::newSymbolType[*i]<<" "<<*i;
                if(Dyninst_aarch64::Scanner::newSymbolVal.count(*i))
                    out<<" = "<<Dyninst_aarch64::Scanner::newSymbolVal[*i];
                out<<";\n";
            }
        }

        foundNewSymbol = false;
        newSymbols.clear();
    }

    ARGS_VEC(out.str(), *arg1, *arg2);
    DEL_VEC(arg1, arg2);

    return STR(makeStr(args, &del));
}

string makeDeclCondAsnmt(string in) {
    size_t equalPos = in.find("=");
    string id = in.substr(0, equalPos - 1);
    string rem = in.substr(equalPos + 2);

    size_t ifend = rem.find("\n");
    size_t condend = rem.find("\n", ifend + 1);
    size_t st1end = rem.find("\n", condend + 1);

    string cond = rem.substr(ifend + 1, condend - ifend - 1);
    string st1 = rem.substr(condend + 1, st1end - condend - 1);
    string st2 = rem.substr(st1end + 1);

    stringstream val;
    val<<id<<";\n";
    val<<"if ("<<cond<<")\n";
    val<<id<<" = "<<st1<<";\nelse\n";
    val<<id<<" = "<<st2;

    return val.str();
}

string pruneCond(string cond_str) {
    int nextpos = 1, prevpos = 0;

    string curblock = "";
    int stmtcnt;
    while(nextpos < cond_str.length() && (nextpos = cond_str.find("\n", nextpos)) != string::npos) {
        string cur = cond_str.substr(prevpos, nextpos - prevpos);
        curblock += cur + "\n";
        if(cur == "{")
            stmtcnt = 0;
        else if(cur == "}") 
        {
            if(stmtcnt > 0)
                return cond_str;
            curblock = "";
        }
        else if((cur.find("if") == string::npos || cur[cur.find("if") + 1] != ' ') && cur.find("else") == string::npos)
            stmtcnt++;

        prevpos = nextpos + 1;
        nextpos++;
    }

    return "";
}

void addSymbolMaybe(string str) {
    str = str.substr(0, str.find(";"));
    string varname = str;

    if(str.find("=") != string::npos)
    {
        size_t fspace = str.find(" ");
        varname = str.substr(0, fspace);
    }

    size_t commapos;
    if((commapos = varname.find(",")) == string::npos)
    {
        if(find(symbols.begin(), symbols.end(), varname) == symbols.end())
            symbols.push_back(varname);
    }
    else
    {
        vector<string> vars;
        size_t prevpos = 0;
        while(commapos != string::npos)
        {
            vars.push_back(varname.substr(prevpos, commapos - prevpos));
            prevpos = commapos + 1;
            commapos = varname.find(",", prevpos);
        }
        vars.push_back(varname.substr(prevpos));

        for(vector<string>::iterator itr = vars.begin(); itr != vars.end(); itr++)
            if(find(symbols.begin(), symbols.end(), *itr) == symbols.end())
                symbols.push_back(*itr);
    }
}

bool isInt(string s) {
    for(int idx = 0; idx < s.length(); idx++)
        if(!isdigit(s[idx]))
            return false;

    return true;
}

bool haswback = false;

%}

%require "2.3"

%defines

%error-verbose

%skeleton "lalr1.cc"

%name-prefix="Dyninst_aarch64"

%define "parser_class_name" "Parser"

%locations
%initial-action
{
    @$.begin.filename = @$.end.filename;
};

%parse-param { class Driver& driver }

%union {
    int intVal;
    std::string* strVal;
}

%token		    END	     0	"end of file"
%token          <strVal>    DTYPE
%token          <strVal>    INSN_START
%token          INSN_END
%token          <strVal>    OPERAND
%token          COND_IF
%token          COND_THEN
%token          COND_ELSE
%token          COND_ELSIF
%token          COND_END
%token		    SWITCH_CASE
%token		    SWITCH_WHEN
%token		    SWITCH_OF
%token          <strVal>    OPER
%token          <strVal>    REG
%token          <intVal>    NUM
%token          <strVal>    BOOLVAL
%token          <strVal>    IDENTIFIER
%token          SYMBOL_OPENROUNDED
%token          SYMBOL_OPENSQUARE
%token          SYMBOL_CLOSEROUNDED
%token          SYMBOL_CLOSESQUARE
%token		    SYMBOL_LT
%token		    SYMBOL_GT
%token          SYMBOL_EQUAL
%token          SYMBOL_COMMA
%token		    SYMBOL_COLON
%token          READ_PC
%token          <strVal>    SET_NZCV
%token		    SET_LR
%token          FLAG_CARRY
%token		    IGNORE
%token		    UNKNOWN
%token		    MEMORY

%type           <strVal>  program datatype varname targ expr funccall args condblock decl cond asnmt bitmask blockdata srcreg bmaskend bmasksrc
%type           <strVal>  bitpos declblock switch whenblocks whenblock condshalf condterm condelsif asnmtsrc blockcode deccondsrc bmaskstart memory

%{

#include "scanner.h"
#include "driver.h"

#undef yylex
#define yylex driver.scanner->lex

%}

%%

insn:       INSN_START program INSN_END {
                                            cout<<"struct IP_"<<*$1<<": P {\nvoid p(D d, Ops ops, I insn, A args, B raw) {\n";
                                            cout<<*$2;
                                            cout<<"\n}\n};\n";

                                            delete $1;
                                            delete $2;

                                            symbols.clear();
                                            newSymbols.clear();
                                        }
            ;

program:    program decl     { $$ = makeProgramBlock($1, $2); } |
            program asnmt    { $$ = makeProgramBlock($1, $2); } |
            program funccall {
                                string *str = new string((*$2) + ";");
                                delete $2;

                                $$ = makeProgramBlock($1, str);
                             } |
            program cond     { $$ = makeProgramBlock($1, $2); } |
	        program switch   { $$ = makeProgramBlock($1, $2); } |
                             { $$ = STR("");                  }
            ;

decl:       OPERAND                     {
                                            size_t spacepos = (*$1).find(" ");
                                            addSymbolMaybe((*$1).substr(spacepos + 1));

                                            $$ = $1;
                                        }   |
            READ_PC                     {  $$ = STR("BaseSemantics::SValuePtr base = d->readRegister(d->REG_PC);\n");   } |
	        SET_LR			            {  $$ = STR("if(EXTR(31, 31) == 1)\nd->writeRegister(d->findRegister(\"x30\", 64), ops->add(d->readRegister(d->REG_PC), ops->number_(32, 4)));\n");	} |
            datatype declblock          {
                                            if($2 != NULL)
                                            {
                                                addSymbolMaybe(*$2);

                                                string dtype = *$1;
                                                if((*$2).find("carry_in") != string::npos)
                                                    dtype = "bool";
                                                else if(dtype == "int" && (*$2).find("result") != string::npos)
                                                    dtype = "BaseSemantics::SValuePtr";

                                                ARGS_VEC(dtype, " ", *$2);
                                                DEL_VEC($1, $2);
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else
                                            {
                                                $$ = STR("");
                                            }
                                        }
            ;

deccondsrc: funccall    { $$ = $1; } |
            srcreg      { $$ = $1; } |
            varname     { $$ = $1; }
            ;

datatype:   DTYPE                  {  $$ = $1;   }
            ;

declblock:  varname                     {  
                                            DEL_VEC($1);
                                            ARGS_VEC((*$1 == "nzcv")?"n,z,c,v":(*$1), ";\n");

                                            $$ = STR(makeStr(args, &del));    
                                        } |
            asnmt                       {
                                            if($1 != NULL)
                                            {
                                                string ret = *$1;

                                                if(ret.find("if\n") != string::npos)
                                                {
                                                   $$ = STR(makeDeclCondAsnmt(ret));
                                                }
                                                else
                                                   $$ = $1;
                                            }
                                            else
                                                $$ = NULL;
                                        }
            ;

varname:    IDENTIFIER                  {
                                            if((*$1) == "wback")
                                                haswback = true;

                                            if(Scanner::newSymbolType.count(*$1) == 0 && Scanner::operandExtractorMap.find(*$1) != Scanner::operandExtractorMap.end())
                                                $$ = STR(Scanner::operandExtractorMap[*$1]);
                                            else
                                                $$ = STR(*$1);
                                            delete $1;
                                        }
            ;

asnmt:      targ SYMBOL_EQUAL asnmtsrc       {
                                                DEL_VEC($1, $3);

                                                if((*$1) == "carry_in")
                                                {
                                                    ARGS_VEC(*$1, " = ", ((*$3) == "1"?"true":"false"), ";\n");
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                                else if((*$1).find("writeMemory") != string::npos)
                                                {
                                                    ARGS_VEC(*$1, *$3, ");\n");
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                                else if((*$1).find("write") != string::npos)
                                                {
                                                    ARGS_VEC((*$1).substr(0, (*$1).length() - 1), ", ", *$3, ");\n");
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                                //We ignore declaration of 'offset', since it is anyway encoded in the instruction representation
                                                else if((*$1) == "offset")
                                                {
                                                    $$ = NULL;
                                                }
                                                else
                                                {
                                                    ARGS_VEC(((*$1) != "null"?((*$1) + " = "):""), *$3, ";\n");
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                            } |
	        bitmask SYMBOL_EQUAL bmasksrc   {
                                                string res;

                                                parseBitPos(*$1, *$3, res);
                                                ARGS_VEC(res, "\n");
                                                DEL_VEC($1, $3);

                                                $$ = STR(makeStr(args, &del));
                                            } |
            SET_NZCV                        {
                                                stringstream ret;
                                                char flags[] = {'n', 'z', 'c', 'v'};

                                                string srcval = *$1;
                                                delete $1;

                                                if(srcval == "nzcv")
                                                {
                                                    for(int idx = 0; idx < sizeof(flags)/sizeof(char); idx++)
                                                        ret<<"d->writeRegister(d->REG_"<<(char)(flags[idx] - 32)<<", "<<flags[idx]<<");\n";
                                                }
                                                else
                                                {
                                                    ret<<"d->writeRegister(d->REG_N, ops->extract(result, result->get_width() - 1, result->get_width()));\n";
                                                    ret<<"d->writeRegister(d->REG_Z, d->isZero(result));\n";
                                                    ret<<"d->writeRegister(d->REG_C, ops->number_(1, 0));\n";
                                                    ret<<"d->writeRegister(d->REG_V, ops->number_(1, 0));\n";
                                                }

                                                $$ = STR(ret.str());
                                            }
            ;

bmasksrc:   funccall    {   $$ = $1;    } |
            OPERAND     {   $$ = $1;    }
            ;

targ:       varname                                                             {   $$ = $1;    }  |
            SYMBOL_OPENROUNDED varname SYMBOL_COMMA varname SYMBOL_CLOSEROUNDED {   $$ = $2;    }  |
	        REG									{
                                                    DEL_VEC($1);
                                                    string regstr = "";

                                                    switch((*$1)[0])
                                                    {
                                                        case 't': {
                                                                string argnum = ((*$1).length() == 2 && (*$1)[1] == '2')?"1":"0";
                                                                regstr += "d->write(args[" + argnum + "])";
                                                            }
                                                            break;
                                                        case 'd':regstr += "d->write(args[0])";
                                                            break;
                                                        case 'n':{
                                                                if(!haswback)
                                                                    regstr += "d->write(args[1])";
                                                                else
                                                                    regstr += "d->write(d->getWriteBackTarget(args[1]))";
                                                            }
                                                            break;
                                                        case 's':regstr += "d->writeRegister(d->REG_SP)";
                                                            break;
                                                        default: assert("appears to be an invalid destination register.");
                                                    }
                                                    delArgs(del);

                                                    $$ = STR(regstr);
			        							} |
            memory                              {
                                                    string out = "d->writeMemory(" + *$1 + ", ";
                                                    delete $1;
                                                    $$ = STR(out);
                                                }
            ;

asnmtsrc:   expr		        {  $$ = $1;	} |
            DTYPE UNKNOWN   	{  $$ = STR("ops->unspecified_(1)");   } |
            COND_IF expr COND_THEN deccondsrc COND_ELSE deccondsrc  {
                                                                        DEL_VEC($2, $4, $6);

                                                                        $$ = STR(string("if\n" + *$2 + "\n" + *$4 + "\n" + *$6));

                                                                        delArgs(del);
                                                                    } |
            srcreg     			{  $$ = $1; } |
            memory              {
                                    string out = "d->readMemory(" + *$1 + ")";
                                    delete $1;
                                    $$ = STR(out);
                                } |
            bitmask             {   string in(*$1), var, start, end;
                                    getBitMaskParts(in, var, start, end);

                                    stringstream out;
                                    out<<"ops->extract("<<var<<", "<<start<<", "<<end<<" + 1)";

                                    $$ = STR(out.str());
                                }
            ;

memory:     MEMORY SYMBOL_OPENSQUARE args SYMBOL_CLOSESQUARE {
                                                                        vector<string> params;
                                                                        string argsstr(*$3);

                                                                        size_t startpos = 0, nextcompos = argsstr.find(",", startpos);
                                                                        while(nextcompos != string::npos)
                                                                        {
                                                                            params.push_back(argsstr.substr(startpos, nextcompos - startpos));
                                                                            startpos = nextcompos + 1;
                                                                            nextcompos = argsstr.find(",", startpos);
                                                                        }
                                                                        params.push_back(argsstr.substr(startpos));
                                                                        params.pop_back();

                                                                        string firstparam = params[0];
                                                                        size_t pluspos;
                                                                        if((pluspos = firstparam.find("+")) != string::npos)
                                                                        {
                                                                            string lhs = firstparam.substr(0, pluspos);
                                                                            string rhs = firstparam.substr(pluspos + 1);
                                                                            params[0] = "ops->add(" + lhs + ", ops->number_(32, " + rhs + "))";
                                                                        }

                                                                        stringstream out;
                                                                        for(int idx = 0; idx < params.size(); idx++)
                                                                        {
                                                                            out<<params[idx];
                                                                            if(idx != params.size() - 1)
                                                                                out<<",";
                                                                        }

                                                                        delete $3;
                                                                        $$ = STR(out.str());
                                                             }
            ;

srcreg:     REG     			{
                                    DEL_VEC($1);

                                    map<string, string> reglettermap = {{"d", "0"}, {"t", "0"}, {"t2", "1"}, {"n", "1"}, {"m", "2"}, {"a", "3"}};
                                    string regstr = "d->read(args[";
                                    if(reglettermap.count(*$1) > 0)
                                        regstr += reglettermap[*$1] + "])";
                                    else
                                        assert("appears to be an invalid source register.");

                                    delArgs(del);

                                    $$ = STR(regstr);
                                }
            ;

bitmask:    varname SYMBOL_LT bmaskend SYMBOL_COLON bmaskstart SYMBOL_GT	{
                                                                                stringstream out;
                                                                                out<<*$1<<"|"<<*$3<<"|"<<*$5;
                                                                                DEL_VEC($1, $3, $5);
                                                                                delArgs(del);

                                                                                $$ = STR(out.str());
                                                                           }
	        ;

bmaskend:   NUM                 {
                                    stringstream out;
                                    out<<$1;

                                    $$ = STR(out.str());
                                } |
            varname OPER NUM    {
                                    stringstream out;
                                    out<<*$1<<*$2<<$3;
                                    delete $1;

                                    $$ = STR(out.str());
                                }
            ;

bmaskstart: NUM     {
                        stringstream out;
                        out<<$1;

                        $$ = STR(out.str());
                    } |
            varname {   $$ = $1;    }
            ;

expr:       NUM                         {
                                            stringstream out;
                                            //out<<"ops->number_(32, "<<$1<<")";
                                            out<<$1;

                                            $$ = STR(out.str());
                                        } |
            SYMBOL_OPENROUNDED expr SYMBOL_CLOSEROUNDED {   $$ = $2;    } |
            funccall                    {   $$ = $1;    } |
            varname                     {   $$ = $1;    } |
            bitpos                      {   $$ = $1;    } |
            expr OPER expr              {
                                            DEL_VEC($1, $2, $3);
                                            map<string, string> logicalFuncs = {{"AND", "and_"}, {"OR", "or_"}, {"EOR", "xor_"}, {"MOD", "unsignedModulo"}};
                                            map<string, string> arithFuncs = {{"+", "add"}, {"*", "unsignedMultiply"}, {"-", "add"}};

                                            if(arithFuncs.count(*$2))
                                            {
                                                string cur = *$3;
                                                //NOTE: special case, if 'offset' is an argument replace it with the expression reading the third operand
                                                //Don't replace if it has already been declared though
                                                if(cur == "offset" && find(symbols.begin(), symbols.end(), cur) == symbols.end())
                                                    cur = "d->read(args[2])";

                                                bool isRhsNum = true;
                                                for(int idx = 0; idx < cur.length(); idx++)
                                                    if(cur[idx] < 48 || cur[idx] > 57)
                                                    {
                                                        isRhsNum = false;
                                                        break;
                                                    }

                                                if(isRhsNum)
                                                    cur = "ops->number_(32, " + cur + ")";

                                                if((*$2) == "-")
                                                    cur = "ops->negate(" + cur + ")";

                                                ARGS_VEC("ops->", arithFuncs[*$2], "(", *$1, ", ", cur, ")");
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else if((*$2) == "/")
                                            {
                                                ARGS_VEC(*$1, *$2, *$3);
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else if(logicalFuncs.count(*$2))
                                            {
                                                ARGS_VEC("ops->", logicalFuncs[*$2], "(", *$1, ", ", *$3, ")");

                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else
                                            {
                                                if((*$2) == "-") cout<<"xxx"<<endl;
                                                ARGS_VEC(*$1, " ", *$2, " ", *$3);
                                                $$ = STR(makeStr(args, &del));
                                            }
                                        } |
                                        {   $$ = STR("");   } |
            OPERAND                     {   $$ = $1;  } |
            BOOLVAL                     {   $$ = $1;  }
            ;

bitpos:     varname SYMBOL_LT OPERAND SYMBOL_GT {
                                                    DEL_VEC($1, $3);
                                                    ARGS_VEC("ops->and_(ops->shiftRight(", *$1, ", ", *$3, "), ops->number_(1, 1))");

                                                    $$ = STR(makeStr(args, &del));
                                                }
            ;

funccall:   varname SYMBOL_OPENROUNDED args SYMBOL_CLOSEROUNDED    {
                                                                        DEL_VEC($1, $3);

                                                                        if((*$1) == "AddWithCarry")
                                                                        {
                                                                            ARGS_VEC("d->doAddOperation(", *$3, ", ops->boolean_(false), n, z, c, v)");
                                                                            $$ = STR(makeStr(args, &del));
                                                                        }
                                                                        else if((*$1) == "ConditionHolds")
                                                                        {
                                                                            ARGS_VEC("isTrue(d->", *$1, "(ops->number_(32, ", *$3, ")))");
                                                                            $$ = STR(makeStr(args, &del));
                                                                        }
                                                                        else if((*$1) == "IsZero")
                                                                        {
                                                                            ARGS_VEC("isTrue(d->isZero(", *$3, "))");
                                                                            $$ = STR(makeStr(args, &del));
                                                                        }
                                                                        else
                                                                        {
                                                                            ARGS_VEC("d->", *$1, "(", *$3, ")");
                                                                            $$ = STR(makeStr(args, &del));
                                                                        }
                                                                    }
            ;

args:       args SYMBOL_COMMA args      {
                                            bool otherArgs = (*$3 != "branch_type" && (*$3).find("BranchType") == string::npos);
                                            DEL_VEC($1, $3);
                                            ARGS_VEC(*$1, otherArgs?", ":"", otherArgs?*$3:"");

                                            $$ = STR(makeStr(args, &del));
                                        } |
            varname                     {
                                            string var = *$1;
                                            if(find(symbols.begin(), symbols.end(), var) == symbols.end())
                                            {
                                                foundNewSymbol = true;
                                                newSymbols.push_back(var);
                                            }

                                            if(var == "EXTR(5, 9)")
                                                var = "d->read(args[1])";

                                            $$ = STR(var);
                                        } |
            NUM                         {
                                            stringstream out;
                                            out<<$1;

                                            $$ = STR(out.str());
                                        } |
            expr OPER expr              {
                                            DEL_VEC($1, $2, $3);

                                            if((*$2) == "+" || (*$2) == "/")
                                            {
                                                if((*$2) == "/" && !isInt(*$3) && (*$1).find("d->") != string::npos && (*$3).find("d->") != string::npos)
                                                {
                                                    ARGS_VEC("ops->unsignedDivide(", *$1, ", ", *$3, ")");
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                                else
                                                {
                                                    ARGS_VEC(*$1, *$2, *$3);
                                                    $$ = STR(makeStr(args, &del));
                                                }
                                            }
                                            else if((*$2) == "MOD")
                                            {
                                                ARGS_VEC("ops->unsignedModulo(", *$1, ", ops->number_(32, ", *$3, "))");
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else
                                                assert(!"invalid operator in expression as argument for memory access!");

                                        } |
            bitmask                     {
                                            string in(*$1), var, start, end;
                                            getBitMaskParts(in, var, start, end);

                                            stringstream out;
                                            out<<"ops->extract("<<var<<", "<<start<<", "<<end<<" + 1)";

                                            $$ = STR(out.str());
                                        } |
            bitpos                      {   $$ = $1;    } |
	        OPERAND			            {   $$ = $1;	} |
            FLAG_CARRY                  {   $$ = STR("d->readRegister(d->REG_C)"); } |
            funccall                    {   $$ = $1;    }
            ;

cond:	    COND_IF expr COND_THEN condblock condshalf      {
                                                                DEL_VEC($2, $4, $5);
                                                                ARGS_VEC("\nif(", *$2, ")\n{\n", *$4, "}\n", *$5);

                                                                $$ = STR(pruneCond(makeStr(args, &del)));
                                                            }
            ;

condshalf:  condterm    {   $$ = $1;    } |
            condelsif   {   $$ = $1;    };
            ;

condelsif:  COND_ELSIF expr COND_THEN condblock condshalf   {
                                                                DEL_VEC($2, $4, $5);
                                                                ARGS_VEC("\nelse if(", *$2, ")\n{\n", *$4, "}\n", *$5);

                                                                $$ = STR(pruneCond(makeStr(args, &del)));
                                                            }
            ;

condterm:   COND_END			            {   $$ = new string("");    } |
	        COND_ELSE condblock COND_END    {
                                                DEL_VEC($2);
                                                ARGS_VEC("else\n{\n", *$2, "}\n");

                                                $$ = STR(makeStr(args, &del));
                                            }
            ;

condblock:  condblock blockdata {
                                    DEL_VEC($1, $2);
                                    ARGS_VEC(*$1, *$2);

                                    $$ = STR(makeStr(args, &del));
                                } |
            blockdata           {   $$ = $1;    }
            ;

blockcode:  blockcode blockdata {
                                    DEL_VEC($1, $2);
                                    ARGS_VEC(*$1, *$2);

                                    $$ = STR(makeStr(args, &del));
                                } |
            blockdata           {   $$ = $1;    };
            ;

blockdata:  asnmt       {   $$ = $1;    } |
            funccall    {
                            DEL_VEC($1);
                            ARGS_VEC(*$1, ";\n");

                            $$ = STR(makeStr(args, &del));
                        }   |
            cond        {   $$ = $1;    } |
	        switch	    {   $$ = $1;	} |
            IGNORE      {   $$ = STR("");   }
            ;

switch:	    SWITCH_CASE	varname	SWITCH_OF whenblocks		  {
                                                                     DEL_VEC($2, $4);
    
                                                                     if(*$4 != "")
                                                                     {
                                                                        ARGS_VEC("\nswitch(", *$2, ")\n{\n", *$4, "}\n");
                                                                        $$ = STR(makeStr(args, &del));
                                                                     }
                                                                     else
                                                                     {
                                                                        delArgs(del);
                                                                        $$ = STR("");
                                                                     }
                                                              }
	        ;

whenblocks: whenblocks whenblock    {
                                        DEL_VEC($1, $2);
                                        ARGS_VEC(*$1, *$2);

                                        $$ = STR(makeStr(args, &del));
                                    } |
	        whenblock		        {	$$ = $1; } |
	        /* empty */		        {	$$ = STR("");	}
	        ;

whenblock:  SWITCH_WHEN	varname blockcode COND_END	 {
                                                        DEL_VEC($3);

                                                        //Ignore the block if it is a prefetch operation
                                                        if((*$2) != "MemOp_PREFETCH")
                                                        {
                                                            ARGS_VEC("case ", *$2, ":\n{\n", *$3, "}\nbreak;\n");
                                                            $$ = STR(makeStr(args, &del/*NULL*/));
                                                        }
                                                        else
                                                            $$ = STR("");
                                                     }
	    ;	 
%%

void Dyninst_aarch64::Parser::error(const Parser::location_type& l,
			    const string& m)
{
    driver.error(l, m);
}