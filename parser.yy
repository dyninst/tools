%{

#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <sstream>
#include <stdint.h>

using namespace std;

#define STR(s)  new string(s)
#define ARGS_VEC(arglist...)    vector<string> args = {arglist}
#define DEL_VEC(arglist...)     vector<string *> del = {arglist}
#define DEL_VEC_ADD(arg)        del.push_back(arg)

void parseBitPos(string str, string &var, string &expr) {
    string temp;
    for(int idx = 0; idx < str.length(); idx++)
        if(str[idx] != ' ')
            temp += str[idx];

    size_t equalPos = temp.find_first_of("=");
    var = temp.substr(0, equalPos);
    expr = temp.substr(equalPos + 1);
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
    ARGS_VEC(*arg1, *arg2);
    DEL_VEC(arg1, arg2);

    return STR(makeStr(args, &del));
}
#include <iostream>
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
        else if(cur.find("if") == string::npos && cur.find("else") == string::npos)
            stmtcnt++;

        prevpos = nextpos + 1;
        nextpos++;
    }

    return "";
}

%}

%require "2.3"

%defines

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
%token          DTYPE_BITS
%token          DTYPE_BOOLEAN
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
%token          <strVal>    FUNCNAME
%token          <strVal>    REG
%token          <intVal>    NUM
%token          <strVal>    BOOLVAL
%token          <strVal>    IDENTIFIER
%token          SYMBOL_OPENROUNDED
%token          SYMBOL_CLOSEROUNDED
%token		    SYMBOL_LT
%token		    SYMBOL_GT
%token          SYMBOL_EQUAL
%token          SYMBOL_COMMA
%token		    SYMBOL_COLON
%token          READ_PC
%token          SET_NZCV
%token		    SET_LR
%token          FLAG_CARRY
%token		    IGNORE
%token		    UNKNOWN
%token		    <strVal>    MEMORY

%type           <strVal>  program datatype varname targ expr funccall args condblock decl cond asnmt bitmask blockdata
%type           <strVal>  bitpos declblock switch whenblocks whenblock condshalf condterm condelsif asnmtsrc blockcode

%{

#include "driver.h"
#include "scanner.h"

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

decl:       OPERAND                     {  $$ = $1; }   |
            READ_PC                     {  $$ = STR("BaseSemantics::SValuePtr base = d->readRegister(d->REG_PC);\n");   } |
	        SET_LR			            {  $$ = STR("if(EXTR(31, 31) == 1)\nd->writeRegister(d->findRegister(\"x30\", 64), ops->add(d->readRegister(d->REG_PC), ops->number_(32, 4)));\n");	} |
            datatype declblock          {
                                            if($2 != NULL)
                                            {
                                                ARGS_VEC(((*$2).find("carry_in") != string::npos?"bool ":*$1), *$2);
                                                DEL_VEC($1, $2);
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else
                                            {
                                                $$ = STR("");
                                            }
                                        }
            ;

datatype:   DTYPE_BITS                  {  $$ = STR("BaseSemantics::SValuePtr ");   }   |
            DTYPE_BOOLEAN               {  $$ = STR("bool ");    }
            ;

declblock:  varname                     {  
                                            DEL_VEC($1);
                                            ARGS_VEC(*$1, ";\n");

                                            $$ = STR(makeStr(args, &del));    
                                        } |
            asnmt                       {  $$ = $1;    }
            ;

varname:    IDENTIFIER                  {
                                            if(Scanner::operandExtractorMap.find(*$1) != Scanner::operandExtractorMap.end())
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
	        bitmask SYMBOL_EQUAL funccall   {
                                                string var, expr;

                                                parseBitPos(*$1, var, expr);
                                                ARGS_VEC(var, " = ops->or_(", expr, ", ", *$3, ");\n");
                                                DEL_VEC($1, $3);

                                                $$ = STR(makeStr(args, &del));
                                            } |
            SET_NZCV                        {   $$ = STR("d->writeRegister(REG_NZCV, nzcv);\n");   }
            ;

targ:       varname                                                             {   $$ = $1;    }  |
            SYMBOL_OPENROUNDED varname SYMBOL_COMMA varname SYMBOL_CLOSEROUNDED {   $$ = $2;    }  |
	        REG									{
                                                    DEL_VEC($1);
                                                    string regstr = "";

                                                    switch((*$1)[0])
                                                    {
                                                        case 't':
                                                        case 'd':regstr += "d->write(args[0])";
                                                            break;
                                                        case 'n':regstr += "d->write(args[1])";
                                                            break;
                                                        case 's':regstr += "d->writeRegister(REG_SP)";
                                                            break;
                                                        default: assert("appears to be an invalid destination register.");
                                                    }
                                                    delArgs(del);

                                                    $$ = STR(regstr);
			        							} |
			MEMORY                              { $$ = STR("d->writeMemory(address, 0x8 << EXTR(30, 31), "); }
            ;

asnmtsrc:   expr		        {  $$ = $1;	} |
            DTYPE_BITS UNKNOWN	{  $$ = STR("ops->unspecified_(1)");   } |
            REG     			{
                                    DEL_VEC($1);
                                    string regstr = "";

                                    switch((*$1)[0])
                                    {
                                        case 't':regstr += "d->read(args[0])";
                                            break;
                                        case 'n':regstr += "d->read(args[1])";
                                            break;
                                        case 'm':regstr += "d->read(args[2])";
                                            break;
                                        default: assert("appears to be an invalid source register.");
                                    }
                                    delArgs(del);

                                    $$ = STR(regstr);
                                } |
            MEMORY              {
                                    DEL_VEC($1);

                                    $$ = STR(string("d->readMemory(address, ") + string((((*$1) == "size")?"d->ldStrLiteralAccessSize(raw))":"0x8 << EXTR(30, 31))")));

                                    delArgs(del);
                                }
            ;

bitmask:    varname SYMBOL_LT NUM SYMBOL_COLON NUM SYMBOL_GT	{	//add support for bit ranges not starting at 0 and for custom varname lengths

                                                                    int hibit = $3, lobit = $5, range = hibit - lobit + 1;
                                                                    uint64_t mask = (1<<range) - 1;
                                                                    stringstream out;

                                                                    out<<*$1<<" = ops->and_("<<*$1<<", ops->number_("<<range<<", 0x"<<hex<<mask<<"))";
                                                                    delete $1;

                                                                    $$ = STR(out.str());
                                                                }
	    ;

expr:       NUM                         {
                                            stringstream out;
                                            //out<<"ops->number_(32, "<<$1<<")";
                                            out<<$1;

                                            $$ = STR(out.str());
                                        } |
            funccall                    {   $$ = $1;    } |
            varname                     {   $$ = $1;    } |
            bitpos                      {   $$ = $1;    } |
            expr OPER expr              {   //FIXME
                                            //$$ = STR(Scanner::operatorToFunctionMap[*$2] + "(" + string(*$1) + ", " + string(*$3) + ")");
                                            DEL_VEC($1, $2, $3);

                                            if((*$2) == "+")
                                            {
                                                string cur = *$3;
                                                //NOTE: special case, if 'offset' is an argument replace it with the expression reading the third operand
                                                //TODO don't replace if 'offset' has already been seen before as a declared variable
                                                if(cur == "offset")
                                                    cur = "d->read(args[2])";

                                                ARGS_VEC("ops->add(", *$1, ", ", cur, ")");
                                                $$ = STR(makeStr(args, &del));
                                            }
                                            else
                                            {
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
                                                    ARGS_VEC("ops->and_(ops->shiftRight(", *$1, ", ", *$3, "), ops->number(1, 1))");

                                                    $$ = STR(makeStr(args, &del));
                                                }
            ;

funccall:   FUNCNAME SYMBOL_OPENROUNDED args SYMBOL_CLOSEROUNDED    {
                                                                        DEL_VEC($1, $3);

                                                                        if((*$1) == "AddWithCarry")
                                                                        {
                                                                            ARGS_VEC("d->doAddOperation(", *$3, ", ops->boolean_(false), nzcv)");
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
            varname                     {   $$ = $1;  } |
            NUM                         {
                                            stringstream out;
                                            out<<$1;

                                            $$ = STR(out.str());
                                        } |
            bitmask                     {   $$ = $1;    } |
	        OPERAND			            {   $$ = $1;	}   |
            FLAG_CARRY                  {   $$ = STR("ops->and_(d->readRegister(REG_NZCV), ops->number_(32, 0x2))"); }
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

/*cond:       COND_IF expr COND_THEN condblock COND_END {
                                                        DEL_VEC($2, $4);
                                                        ARGS_VEC("if(", *$2, ")\n{\n", *$4, "}\n");

                                                        $$ = STR(makeStr(args, &del));
                                                      } |
              COND_IF expr COND_THEN condblock COND_ELSE condblock COND_END {
                                                                                 DEL_VEC($2, $4, $6);
                                                                                 ARGS_VEC("if(", *$2, ")\n{\n", *$4, "}\n", "else\n{\n", *$6, "}\n");

                                                                                 $$ = STR(makeStr(args, &del));
 			                                        						 }
*/
void Dyninst_aarch64::Parser::error(const Parser::location_type& l,
			    const string& m)
{
    driver.error(l, m);
}
