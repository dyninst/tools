%{

#include <stdio.h>
#include <string>
#include <vector>

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
%token          DTYPE_INTEGER
%token          DTYPE_BITS
%token          CAST_UINT
%token          <strVal>    OPERAND
%token          COND_IF
%token          COND_THEN
%token          COND_ELSE
%token          COND_CASE
%token          COND_OF
%token          COND_WHEN
%token          FUNC_ZEROEXTEND
%token          <intVal>    NUM
%token          <strVal>    IDENTIFIER
%token          SYMBOL_OPENROUNDED
%token          SYMBOL_CLOSEROUNDED
%token          SYMBOL_EQUAL
%token          SYMBOL_COMMA

%{

#include "driver.h"
#include "scanner.h"

#undef yylex
#define yylex driver.scanner->lex

%}

%% 

program:    program decl |
            program asnmt |
            ;

decl:       OPERAND                                                   {   std::cout<<*$1; delete $1;    }               |
            DTYPE_BITS IDENTIFIER                                     {   std::cout<<"int "<<*$2<<";\n"; delete $2;  }
            ;

asnmt:      IDENTIFIER SYMBOL_EQUAL NUM                               {   std::cout<<*$1<<" = "<<$3<<";\n"; delete $1;  }
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
