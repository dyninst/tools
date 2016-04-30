%{

#include <string>
#include <iostream>

%}

%defines

%skeleton "lalr1.cc"

%define namespace "Dyninst_aarch64"

%define "parser_class_name" "Parser"

%parse-param {class Driver &driver }

%union {
    int intVal;
    std::string *strVal;
}

%{

#include "Driver.h"
#include "Scanner.h"

#undef yylex
#define yylex driver.lexer->lex

%}

%%

stmt:   ;
