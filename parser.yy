%{

#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>

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
%token          <strVal>    INSN_START
%token          INSN_END
%token          <strVal>    OPERAND
%token          COND_IF
%token          COND_THEN
%token          COND_ELSE
%token          COND_END
%token          OPER_NOT
%token          OPER_DBLEQUAL
%token          OPER_AND
%token          FUNC_AWC
%token          FUNC_NOT
%token          REG
%token          <intVal>    NUM
%token          <strVal>    IDENTIFIER
%token          SYMBOL_OPENROUNDED
%token          SYMBOL_CLOSEROUNDED
%token          SYMBOL_EQUAL
%token          SYMBOL_COMMA
%token          SET_NZCV
%token          FLAG_CARRY

%type           <strVal>  program datatype varname targ reg_name expr oper funccall funcname args condblock decl cond asnmt

%{

#include "driver.h"
#include "scanner.h"

#undef yylex
#define yylex driver.scanner->lex

%}

%%

insn:       INSN_START program INSN_END {
                                            std::cout<<"case "<<*$1<<":\n{\n";
                                            std::cout<<*$2;
                                            std::cout<<"}\nbreak;\n";

                                            delete $1;
                                            delete $2;
                                        }
            ;

program:    program decl {
                            std::stringstream out;
                            out<<*$1<<"\n"<<*$2;

                            delete $1;
                            delete $2;

                            $$ = new std::string(out.str());
                         } |
            program asnmt {
                              std::stringstream out;
                              out<<*$1<<"\n"<<*$2;

                              delete $1;
                              delete $2;

                              $$ = new std::string(out.str());
                           } |
            program cond {
                             std::stringstream out;
                             out<<*$1<<"\n"<<*$2;

                             delete $1;
                             delete $2;

                             $$ = new std::string(out.str());
                          }|
                          {    $$ = new std::string("");    }
            ;

decl:       OPERAND                     {
                                            $$ = $1;
                                        }   |
            datatype varname            {
                                            std::stringstream out;
                                            out<<*$1<<" "<<*$2<<";\n";

                                            delete $1;
                                            delete $2;

                                            $$ = new std::string(out.str());
                                        }
            ;

datatype:   DTYPE_BITS                  {   $$ = new std::string("uint32_t");   }
            ;

varname:    IDENTIFIER                  {
                                            if(Scanner::operandExtractorMap.find(*$1) != Scanner::operandExtractorMap.end())
                                                $$ = new std::string(Scanner::operandExtractorMap[*$1]);
                                            else
                                                $$ = new std::string(*$1);
                                            delete $1;
                                        } |
            FLAG_CARRY                  {   $$ = new std::string("policy.readFlags() & 0x2"); }
            ;

asnmt:      targ SYMBOL_EQUAL expr      {
                                            std::stringstream out;
                                            if($1 != NULL)
                                            {
                                                out<<*$1<<" = "<<*$3<<";\n";
                                                delete $1;
                                            }
                                            else
                                                out<<"policy.writeGPR(operands[0], "<<*$3<<");\n";
                                            delete $3;

                                            $$ = new std::string(out.str());
                                        } |
            SET_NZCV                    {   $$ = new std::string("policy.writeFlags(nzcv);\n");   }
            ;

expr:       NUM                         {
                                            std::stringstream out;
                                            out<<$1;

                                            $$ = new std::string(out.str());
                                        } |
            funccall                    {   $$ = $1;    } |
            varname                     {   $$ = $1;    } |
            expr oper expr              {
                                            $$ = new std::string(std::string(*$1) + std::string(*$2) + std::string(*$3));

                                            delete $1;
                                            delete $2;
                                            delete $3;
                                        } |
                                        {   $$ = new std::string("");   }
            ;

targ:       varname                     {   $$ = $1;    }  |
            SYMBOL_OPENROUNDED varname SYMBOL_COMMA varname SYMBOL_CLOSEROUNDED {   $$ = $2;    }  |
            reg_name                    {   $$ = NULL;  }
            ;

reg_name:   REG                         {}
            ;

oper:       OPER_NOT                    {   $$ = new std::string("!");  } |
            OPER_DBLEQUAL               {   $$ = new std::string(" == "); } |
            OPER_AND                    {   $$ = new std::string(" && "); }
            ;

funccall:   funcname SYMBOL_OPENROUNDED args SYMBOL_CLOSEROUNDED    {
                                                                        std::stringstream out;
                                                                        out<<*$1<<"("<<*$3<<")";

                                                                        delete $1;
                                                                        delete $3;

                                                                        $$ = new std::string(out.str());
                                                                    }
            ;

funcname:   FUNC_NOT                    {   $$ = new std::string("Not");    } |
            FUNC_AWC                    {   $$ = new std::string("AddWithCarry");   }
            ;

args:       args SYMBOL_COMMA args      {
                                            std::stringstream out;
                                            out<<*$1<<", "<<*$3;

                                            delete $1;
                                            delete $3;

                                            $$ = new std::string(out.str());
                                        } |
            varname                     {   $$ = $1;    }
            ;

cond:       COND_IF expr COND_THEN condblock COND_END {
                                                std::stringstream out;
                                                out<<"if("<<*$2<<")\n{\n"<<*$4<<"}\n";

                                                delete $2;
                                                delete $4;

                                                $$ = new std::string(out.str());
                                             } |
            COND_IF expr COND_THEN condblock COND_ELSE condblock COND_END {
                                                                     std::stringstream out;
                                                                     out<<"if("<<*$2<<")\n{\n"<<*$4<<"}\n";
                                                                     out<<"else\n{\n"<<*$6<<"}\n";

                                                                     delete $2;
                                                                     delete $4;
                                                                     delete $6;

                                                                     $$ = new std::string(out.str());
                                                                  }
            ;

condblock:  condblock asnmt {
                                std::stringstream out;
                                out<<*$1<<"\n"<<*$2<<"\n";

                                delete $1;
                                delete $2;

                                $$ = new std::string(out.str());
                            } |
            asnmt           {   $$ = $1;    }
            ;

%%

/*
switch:     COND_CASE OPERAND COND_OF whenblock                       {   std::cout<<"switch("<<*$2<<")\n{\n";    }
            ;

whenblock:  whenstmt whenblock |
            ;

whenstmt:   COND_WHEN NUM IDENTIFIER SYMBOL_EQUAL FUNC_ZEROEXTEND SYMBOL_OPENROUNDED OPERAND SYMBOL_COMMA IDENTIFIER SYMBOL_CLOSEROUNDED  {   std::cout<<"case "<<$2<<": "<<*$3<<" = ZeroExtend("<<$7<<", "<<*$9<<");\nbreak;\n";   delete $3; delete $9;    }
            ;
*/

void Dyninst_aarch64::Parser::error(const Parser::location_type& l,
			    const std::string& m)
{
    driver.error(l, m);
}
