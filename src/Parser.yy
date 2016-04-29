%{

#include <string>
#include <iostream>

%}

%defines

%skeleton "lalr1.cc"

%define namespace "Dyninst_aarch64"

%define "parser_class_name" "Parser"

%union {
    int intVal;
    std::string *strVal;
}

%{

#include "Scanner.h"

%}

%%

stmt:   ;
