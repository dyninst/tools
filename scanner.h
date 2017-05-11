/*
 * See the dyninst/COPYRIGHT file for copyright information.
 *
 * We provide the Paradyn Tools (below described as "Paradyn")
 * on an AS IS basis, and do not warrant its validity or performance.
 * We reserve the right to update, modify, or discontinue this
 * software at any time.  We shall have no obligation to supply such
 * updates or modifications or any other form of support to you.
 *
 * By your use of Paradyn, you understand and agree that we (or any
 * other person or entity with proprietary rights in Paradyn) are
 * under no obligation to provide either maintenance services,
 * update services, notices of latent defects, or correction of
 * defects for Paradyn.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef DYNINST_AARCH64_SCANNER_H
#define DYNINST_AARCH64_SCANNER_H

#ifndef YY_DECL

#define YY_DECL                        \
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

        /* Map to convert an identifier appearing in the pseudocode to a statement that extracts the equivalent bits from the raw instruction.
         * This identifier always represents a field within the instruction, but is initialized in the decode pseudocode, not the operation pseudocode.
         * Because of this, the only way to retrieve the field (without parsing the decode pseudocode) is by extracting it from the instruction. */
        static void initOperandExtractorMap();
        static std::map<std::string, std::string> operandExtractorMap;

        /* Map to convert an operator (+, - etc) to an equivalent function defined in the Dispatcher/SymEvalSemantics. */
        static void initOperatorToFunctionMap();
        static std::map<std::string, std::string> operatorToFunctionMap;

        /* Some identifiers need to be ignored since they serve no purpose for our analysis. This map defines them. */
        static void initIgnoreOperands();
        static std::vector<std::string> ignoreOperands;

        /* Maps to automatically create a declaration for identifiers that are not declared in the operation pseudocode and that cannot
         * be converted to a simple equivalent field extraction like with initOperandExtractorMap. */

        static void initOperandPosMap();
        static std::map<std::string, int> operandPosMap;

        static void initNewSymbolMaps();
        static std::map<std::string, std::string> newSymbolType, newSymbolVal;

    };

}

#endif 
