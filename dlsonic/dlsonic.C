#include <iostream>
#include <cstring>
#include <vector>

#include "BPatch.h"

#include "CFG.h"
#include "CodeObject.h"

#include <elf.h>

namespace dp = Dyninst::ParseAPI; 
namespace ds = Dyninst::SymtabAPI;

int main()
{
    ds::Symtab* obj = nullptr;
    std::ignore = ds::Symtab::openFile( obj, "testbins/trydl" ); 
    
    std::vector<ds::Region*> reg;
    std::ignore = obj->getCodeRegions(reg);

    int64_t pltBeginAddr = 0, pltEndAddr = 0;

    for ( const auto r: reg ) {
        auto rgnName = r->getRegionName();
        if ( rgnName == ".plt" ) {
           pltBeginAddr = r->getMemOffset();
           pltEndAddr = r->getMemOffset() + r->getMemSize();
        }
    }

    // traverse call graph
    auto sts = new dp::SymtabCodeSource( "testbins/trydl" );
    auto co = new dp::CodeObject( sts );
    co->parse();
    auto funcList = co->funcs();

    std::unordered_set<Dyninst::Address> seen;

    for ( auto const* f: funcList ) {
        for ( auto b: f->blocks() ) {
            if ( seen.count( b->start() ) > 0 ) {
                continue;	
            }
            seen.insert( b->start() );
            // look at outgoing edges to find calls
            for ( auto e: b->targets() ) {
                if ( ! e ) {
                    continue;
                }
                if ( e->type() == dp::CALL ) {
                    // if it is a call we are going to follow it
                    auto calltgt = e->trg();
                    if ( calltgt->start() >= pltBeginAddr && calltgt->end() <= pltEndAddr ) {

                        std::vector<dp::Function*> containingFuncs;

                        calltgt->getFuncs( containingFuncs );
                        
                        if ( calltgt->containingFuncs() != 1 ) {
                            std::cerr << "each plt slot entry should belong to "
                                         "exactly one function" << std::endl;
                            return 1;
                        }
                        
                        auto funcName = containingFuncs.back()->name();
                        if ( funcName == "dlopen" || funcName == "dlsym" ) {
                            std::cout << "Found: " << funcName << std::endl;
                        }
                   }
                }
            }
        }
    }

}
