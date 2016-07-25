%{

#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <stdint.h>

using namespace std;

#define STR(s)  new string(s)
#define ARGS_VEC(arglist...)    vector<string> args = {arglist}
#define DEL_VEC(arglist...)    vector<string *> del = {arglist}

void parseBitPos(string str, string &var, string &expr) {
    string temp;
    for(int idx = 0; idx < str.length(); idx++)
        if(str[idx] != ' ')
            temp += str[idx];

    size_t equalPos = temp.find_first_of("=");
    var = temp.substr(0, equalPos);
    expr = temp.substr(equalPos + 1);
}

string makeStr(vector<string> &args) {
    int len = 0;
    for(int i = 0; i < args.size(); i++)
        len += args[i].size();

    string ret;
    ret.reserve(len);

    for(int i = 0; i < args.size(); i++)
        ret += args[i];

    return ret;
}

void delArgs(vector<string *> &del) {
    for(int i = 0; i < del.size(); i++)
        delete del[i];
}

string *makeProgramBlock(string *arg1, string *arg2) {
    ARGS_VEC(*arg1, "\n", *arg2);
    DEL_VEC(arg1, arg2);
    delArgs(del);

    return STR(makeStr(args));
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

%token			END	     0	"end of file"
%token          DTYPE_BITS
%token          DTYPE_BOOLEAN
%token          <strVal>    INSN_START
%token          INSN_END
%token          <strVal>    OPERAND
%token          COND_IF
%token          COND_THEN
%token          COND_ELSE
%token          COND_END
%token          <strVal>    OPER
%token          <strVal>    FUNCNAME
%token          REG
%token          <intVal>    NUM
%token          <strVal>    BOOLVAL
%token          <strVal>    IDENTIFIER
%token          SYMBOL_OPENROUNDED
%token          SYMBOL_CLOSEROUNDED
%token		    SYMBOL_LT
%token		    SYMBOL_GT
%token          SYMBOL_EQUAL
%token          SYMBOL_COMMA
%token			SYMBOL_COLON
%token          READ_PC
%token          SET_NZCV
%token		    SET_LR
%token          FLAG_CARRY

%type           <strVal>  program datatype varname targ reg_name expr funccall args condblock decl cond asnmt bitmask blockdata bitpos declblock

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
                                            cout<<"}\n};\n";

                                            delete $1;
                                            delete $2;
                                        }
            ;

program:    program decl     { $$ = makeProgramBlock($1, $2); } |
            program asnmt    { $$ = makeProgramBlock($1, $2); } |
	        program funccall { $$ = makeProgramBlock($1, $2); } |
            program cond     { $$ = makeProgramBlock($1, $2); } |
                             { $$ = STR("");                  }
            ;

decl:       OPERAND                     {
                                            $$ = $1;
                                        }   |
            READ_PC                     {  $$ = STR("BaseSemantics::SValuePtr base = d->readRegister(d->REG_PC);\n");   } |
	        SET_LR			            {  $$ = STR("if(EXTR(31, 31) == 1)\nd->writeRegister(d->readRegister(findRegister(\"x30\", 64)), ops->add(d->readRegister(d->REG_PC), ops->number_(32, 4)));\n");	} |
            datatype declblock          {
                                            stringstream out;
                                            out<<((*$2).find("carry_in") != string::npos?"bool":*$1)<<" "<<*$2<<";\n";

                                            delete $1;
                                            delete $2;

                                            $$ = STR(out.str());
                                        }
            ;

datatype:   DTYPE_BITS                  {   $$ = STR("BaseSemantics::SValuePtr");   }   |
            DTYPE_BOOLEAN               {   $$ = STR("bool");    }
            ;

declblock:  varname                     {  $$ = $1;    } |
            asnmt                       {   $$ = $1;    }
            ;

varname:    IDENTIFIER                  {
                                            if(Scanner::operandExtractorMap.find(*$1) != Scanner::operandExtractorMap.end())
                                                $$ = STR(Scanner::operandExtractorMap[*$1]);
                                            else
                                                $$ = STR(*$1);
                                            delete $1;
                                        }
            ;

asnmt:      targ SYMBOL_EQUAL expr           {
                                                stringstream out;

                                                if($1 != NULL)
                                                {
                                                    if((*$1) == "carry_in")
                                                        out<<*$1<<" = "<<((*$3) == "1"?"true":"false")<<";\n";
                                                    else
                                                        out<<((*$1) != "null"?((*$1) + " = "):"")<<*$3<<";\n";
                                                    delete $1;
                                                }
                                                else
                                                    out<<"d->write(args[0], "<<*$3<<");\n";
                                                delete $3;

                                                $$ = STR(out.str());
                                            } |
			bitmask SYMBOL_EQUAL funccall   {
												stringstream out;
                                                string var, expr;

                                                parseBitPos(*$1, var, expr);

												out<<var<<" = ops->or_("<<expr<<", "<<*$3<<");\n";
												
												delete $1;
												delete $3;
												
												$$ = STR(out.str());
											} |
            SET_NZCV                        {   $$ = STR("d->writeRegister(REG_NZCV, nzcv);\n");   }
            ;

bitmask:	varname SYMBOL_LT NUM SYMBOL_COLON NUM SYMBOL_GT	{	//add support for bit ranges not starting at 0 and for custom varname lengths

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
                                            if((*$2) == "+")
                                                $$ = STR("ops->add(" + string(*$1) + ", " + string(*$3) + ")");
                                            else
                                                $$ = STR(string(*$1) + string(*$2) + string(*$3));

                                            delete $1;
                                            delete $2;
                                            delete $3;
                                        } |
                                        {   $$ = STR("");   } |
            OPERAND                     {   $$ = $1;  } |
            BOOLVAL                     {   $$ = $1;  }
            ;

targ:       varname                                                             {   $$ = $1;    }  |
            SYMBOL_OPENROUNDED varname SYMBOL_COMMA varname SYMBOL_CLOSEROUNDED {   $$ = $2;    }  |
            reg_name                                                            {   $$ = NULL;  }
            ;

bitpos:     varname SYMBOL_LT OPERAND SYMBOL_GT {
                                                    stringstream out;
                                                    out<<"ops->and_(ops->shiftRight("<<*$1<<", "<<*$3<<"), ops->number(1, 1))";

                                                    delete $1;
                                                    delete $3;

                                                    $$ = STR(out.str());
                                                }
            ;

reg_name:   REG                         {}
            ;

funccall:   FUNCNAME SYMBOL_OPENROUNDED args SYMBOL_CLOSEROUNDED    {
                                                                        stringstream out;
                                                                        if((*$1) == "AddWithCarry")
                                                                            out<<"d->doAddOperation"<<"("<<*$3<<", ops->boolean_(false), nzcv)";
                                                                        else
                                                                            out<<"d->"<<*$1<<"("<<*$3<<")";

                                                                        delete $1;
                                                                        delete $3;

                                                                        $$ = STR(out.str());
                                                                    }
            ;

args:       args SYMBOL_COMMA args      {
                                            stringstream out;
                                            out<<*$1;
                                            if(*$3 != "branch_type" && (*$3).find("BranchType") == string::npos)
                                                out<<", "<<*$3;

                                            delete $1;
                                            delete $3;

                                            $$ = STR(out.str());
                                        } |
            varname                     {   $$ = $1;    } |
            NUM                         {
                                            stringstream out;
                                            out<<$1;

                                            $$ = STR(out.str());
                                        } |
	        OPERAND			            {   $$ = $1;	}   |
            FLAG_CARRY                  {   $$ = STR("ops->and_(d->readRegister(REG_NZCV), ops->number_(32, 0x2))"); }
            ;

cond:       COND_IF expr COND_THEN condblock COND_END {
                                                        stringstream out;
                                                        out<<"if("<<*$2<<")\n{\n"<<*$4<<"}\n";

                                                        delete $2;
                                                        delete $4;

                                                        $$ = STR(out.str());
                                                     } |
            COND_IF expr COND_THEN condblock COND_ELSE condblock COND_END {
                                                                             stringstream out;
                                                                             out<<"if("<<*$2<<")\n{\n"<<*$4<<"}\n";
                                                                             out<<"else\n{\n"<<*$6<<"}\n";

                                                                             delete $2;
                                                                             delete $4;
                                                                             delete $6;

                                                                             $$ = STR(out.str());
                                                                          }
            ;

condblock:  condblock blockdata {
                                    stringstream out;
                                    out<<*$1<<"\n"<<*$2<<"\n";

                                    delete $1;
                                    delete $2;

                                    $$ = STR(out.str());
                                } |
            blockdata           {   $$ = $1;    }
            ;

blockdata:  asnmt       {   $$ = $1;    } |
            funccall    {
                            stringstream out;
                            out<<*$1<<";\n";

                            delete $1;

                            $$ = STR(out.str());
                        }   |
            cond        {   $$ = $1;    }
            ;

%%

/*
switch:     COND_CASE OPERAND COND_OF whenblock                       {   cout<<"switch("<<*$2<<")\n{\n";    }
            ;

whenblock:  whenstmt whenblock |
            ;

whenstmt:   COND_WHEN NUM IDENTIFIER SYMBOL_EQUAL FUNC_ZEROEXTEND SYMBOL_OPENROUNDED OPERAND SYMBOL_COMMA IDENTIFIER SYMBOL_CLOSEROUNDED  {   cout<<"case "<<$2<<": "<<*$3<<" = ZeroExtend("<<$7<<", "<<*$9<<");\nbreak;\n";   delete $3; delete $9;    }
            ;
*/

void Dyninst_aarch64::Parser::error(const Parser::location_type& l,
			    const string& m)
{
    driver.error(l, m);
}
