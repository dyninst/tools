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

%{

#include "driver.h"
#include "scanner.h"

#undef yylex
#define yylex driver.scanner->lex

%}

%% 

stmt:	;

%%

void Dyninst_aarch64::Parser::error(const Parser::location_type& l,
			    const std::string& m)
{
    driver.error(l, m);
}
