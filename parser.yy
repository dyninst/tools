%{

#include <stdio.h>
#include <string>
#include <vector>
#include <sstream>
#include <stdint.h>

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
%token          <strVal>    OPER
%token          <strVal>    FUNCNAME
%token          REG
%token          <intVal>    NUM
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

%type           <strVal>  program datatype varname targ reg_name expr funccall args condblock decl cond asnmt bitmask blockdata bitpos

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
	    program funccall {
				std::stringstream out;
				out<<*$1<<"\n"<<*$2<<";\n";

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
            READ_PC                     {  $$ = new std::string("base = policy.readPC();\n");   } |
	    SET_LR			{  $$ = new std::string("if(field<31, 31>(insn) == 1)\npolicy.writeGPR(X30, policy.readPC() + 4);\n");	} |
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
                                        }
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
			bitmask SYMBOL_EQUAL funccall   {
												std::stringstream out;
												out<<*$1<<" | "<<*$3<<";\n";
												
												delete $1;
												delete $3;
												
												$$ = new std::string(out.str());
											} |
            SET_NZCV                    {   $$ = new std::string("policy.writeFlags(nzcv);\n");   }
            ;

bitmask:	varname SYMBOL_LT NUM SYMBOL_COLON NUM SYMBOL_GT	{	//add support for bit ranges not starting at 0 and for custom varname lengths

																int hibit = $3, lobit = $5, range = hibit - lobit + 1;
																uint64_t mask = (1<<range) - 1;
																std::stringstream out;
																
																out<<*$1<<" = ("<<*$1<<" & 0x"<<std::hex<<mask<<")";
																
																delete $1;
																
																$$ = new std::string(out.str());
															}
			;

expr:       NUM                         {
                                            std::stringstream out;
                                            out<<$1;

                                            $$ = new std::string(out.str());
                                        } |
            funccall                    {   $$ = $1;    } |
            varname                     {   $$ = $1;    } |
            bitpos                      {   $$ = $1;    } |
            expr OPER expr              {
                                            $$ = new std::string(std::string(*$1) + std::string(*$2) + std::string(*$3));

                                            delete $1;
                                            delete $2;
                                            delete $3;
                                        } |
                                        {   $$ = new std::string("");   } |
            OPERAND                     {   $$ = $1;  }
            ;

targ:       varname                     {   $$ = $1;    }  |
            SYMBOL_OPENROUNDED varname SYMBOL_COMMA varname SYMBOL_CLOSEROUNDED {   $$ = $2;    }  |
            reg_name                    {   $$ = NULL;  }
            ;

bitpos:     varname SYMBOL_LT OPERAND SYMBOL_GT {
                                                    std::stringstream out;
                                                    out<<"("<<*$1<<" & (1 << "<<*$3<<"))";

                                                    delete $1;
                                                    delete $3;

                                                    $$ = new std::string(out.str());
                                                }
            ;

reg_name:   REG                         {}
            ;

funccall:   FUNCNAME SYMBOL_OPENROUNDED args SYMBOL_CLOSEROUNDED    {
                                                                        std::stringstream out;
                                                                        out<<*$1<<"("<<*$3<<")";

                                                                        delete $1;
                                                                        delete $3;

                                                                        $$ = new std::string(out.str());
                                                                    }
            ;

args:       args SYMBOL_COMMA args      {
                                            std::stringstream out;
                                            out<<*$1;
                                            if(*$3 != "branch_type" && (*$3).find("BranchType") == std::string::npos)
                                                out<<", "<<*$3;

                                            delete $1;
                                            delete $3;

                                            $$ = new std::string(out.str());
                                        } |
            varname                     {   $$ = $1;    } |
            NUM                         {
                                            std::stringstream out;
                                            out<<$1;

                                            $$ = new std::string(out.str());
                                        } |
	    OPERAND			{   $$ = $1;	}   |
            FLAG_CARRY                  {   $$ = new std::string("policy.readFlags() & 0x2"); }
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

condblock:  condblock blockdata {
                                std::stringstream out;
                                out<<*$1<<"\n"<<*$2<<"\n";

                                delete $1;
                                delete $2;

                                $$ = new std::string(out.str());
                            } |
            blockdata       {   $$ = $1;    }
            ;

blockdata:  asnmt   {   $$ = $1;    } |
            funccall    {
                            std::stringstream out;
                            out<<*$1<<";\n";

                            delete $1;

                            $$ = new std::string(out.str());
                        }
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
