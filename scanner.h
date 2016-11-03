#ifndef DYNINST_AARCH64_SCANNER_H
#define DYNINST_AARCH64_SCANNER_H

#ifndef YY_DECL

#define    YY_DECL                        \
    Dyninst_aarch64::Parser::token_type                \
    Dyninst_aarch64::Scanner::lex(                \
    Dyninst_aarch64::Parser::semantic_type* yylval,        \
    Dyninst_aarch64::Parser::location_type* yylloc        \
    )
#endif

#ifndef __FLEX_LEXER_H

#include "FlexLexer.h"

#endif

#include <map>
#include <vector>
#include "y.tab.hh"

namespace Dyninst_aarch64 {

    class Scanner : public yyFlexLexer {
    public:

        Scanner(std::istream *instream = 0,
                std::ostream *oustream = 0);

        virtual ~Scanner();

        virtual Parser::token_type lex(
                Parser::semantic_type *yylval,
                Parser::location_type *yylloc
        );

        static void initOperandExtractorMap();
        static std::map<std::string, std::string> operandExtractorMap;

        static void initOperatorToFunctionMap();
        static std::map<std::string, std::string> operatorToFunctionMap;

        static void initIgnoreOperands();
        static std::vector<std::string> ignoreOperands;

        static void initOperandPosMap();
        static std::map<std::string, int> operandPosMap;

        static void initNewSymbolMaps();
        static std::map<std::string, std::string> newSymbolType, newSymbolVal;

    };

}

#endif 
