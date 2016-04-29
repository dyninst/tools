//
// Created by cygnus on 4/28/2016.
//

#ifndef SEMANTICS_BROAD_TEST_SCANNER_H
#define SEMANTICS_BROAD_TEST_SCANNER_H

#ifndef YY_DECL
#define YY_DECL     \
    Dyninst_aarch64::Parser::token_type    \
    Dyninst_aarch64::Scanner::lex(          \
    Dyninst_aarch64::Parser::semantic_type *yylval, \
    Dyninst_aarch64::Parser::token_type *yylloc \
    )
#endif

namespace Dyninst_aarch64 {
    class Scanner : public yyFlexLexer {
        virtual ~Scanner();

        virtual Parser::token_type lex(Parser::semantic_type *yylval, Parser::location_type *yylloc);
    };
}

#endif //SEMANTICS_BROAD_TEST_SCANNER_H
