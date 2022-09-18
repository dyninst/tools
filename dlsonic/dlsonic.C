#include <iostream>
#include <cstring>
#include <vector>

#include "BPatch.h"

#include "dyn_regs.h"
#include "CFG.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "entryIDs.h"
#include <elf.h>

namespace dp = Dyninst::ParseAPI; 
namespace ds = Dyninst::SymtabAPI;
namespace di = Dyninst::InstructionAPI;


void ondlopen( dp::Block* blk, ds::Symtab* obj )
{
    ds::Region* reg = obj->findEnclosingRegion( blk->start() );
    if ( ! reg ) {
        return;
    }

    auto bufStart = (const char*) reg->getPtrToRawData() + blk->start() - reg->getMemOffset();
    auto bufSize = blk->end() - blk->start();

    auto decoder = di::InstructionDecoder( bufStart, bufSize, Dyninst::Arch_x86_64 );
    
    std::vector<std::pair<di::Instruction, uint32_t>> instrVec;

    // We are know that our code block will end with a call to dlopen, we are
    // interested in instructions immediately before it to figure out how the
    // arguments are setup.


    int offset = blk->start();

    while ( true ) {
        auto currInst = decoder.decode();
        if ( ! currInst.isValid() ) {
            break;
        }
        instrVec.push_back( std::make_pair( currInst, offset ) );
        offset += currInst.size();
    }

    std::reverse( instrVec.begin(), instrVec.end() );

    // We want to look for first LEA instruction to %rdi / %edi
    // This is because the library name is the first argument
   
    std::pair<di::Instruction, uint32_t> targetInst;
    bool found = false;
    for ( auto inst: instrVec ) {
        // find first instruction whose operands involve RDI/EDI in the write set
        std::vector<di::Operand> instOpr;
        inst.first.getOperands( instOpr );
        for ( auto op: instOpr ) {
            std::set<di::RegisterAST::Ptr> write;
            op.getWriteSet( write );
            for ( auto w: write ) {
               if ( w->format() == "RDI" || w->format() == "EDI" ) {
                    found = true;
                    break;
                }
            }
            if ( found ) {
                break;
            }
        }
        if ( found ) {
            targetInst = inst;        
            break;
        }
    }

    if ( ! found ) {
        std::cerr << "could not locate parameter for dlopen call" << std::endl;
        return;
    }


    if ( targetInst.first.getOperation().getID() == e_lea 
         && targetInst.first.getOperand(0).getValue()->format() == "RDI") {
        // We will try to evaluate this, by just plugging in RIP
        auto targetValue = targetInst.first.getOperand(1).getValue();
        di::Expression::Ptr ripExpr;

        // We should be traversing the entire graph
        std::vector<di::Expression::Ptr> ret;
        targetValue->getChildren(ret);
        for ( auto e: ret ) {
            if ( e->format() == "RIP" ) {
                ripExpr = e;
            }
        }
        targetValue->bind(
            ripExpr.get(),
            di::Result( di::u32, targetInst.first.size() + targetInst.second ) );
        
        auto targetResult = targetValue->eval();

        if ( ! targetResult.defined  ) {
            std::cerr << "could not calculate address loaded to RDI! strange!" << std::endl;
            return;
        }


        auto targetRegion = obj->findEnclosingRegion( targetResult.val.u32val );
        std::cout << std::string(
            (const char*)targetRegion->getPtrToRawData()
            + targetResult.val.u32val
            - targetRegion->getMemOffset()
        ) << std::endl;
    }

}

int main( int argc, char* argv[] )
{
    std::string execName = argv[1];
    std::cout << "Processing File: " << execName << std::endl;

    ds::Symtab* obj = nullptr;
    std::ignore = ds::Symtab::openFile( obj, execName ); 
    
    std::vector<ds::Region*> reg;
    std::ignore = obj->getCodeRegions( reg );

    int64_t pltBeginAddr = 0, pltEndAddr = 0;

    for ( const auto r: reg ) {
        auto rgnName = r->getRegionName();
        if ( rgnName == ".plt" ) {
           pltBeginAddr = r->getMemOffset();
           pltEndAddr = r->getMemOffset() + r->getMemSize();
        }
    }
    
    const char* rodataStartPtr = nullptr;
    const char* rodataEndPtr = nullptr;
    int64_t rodataBeginAddr = 0, rodataEndAddr = 0;

    std::ignore = obj->getDataRegions( reg );

    for ( const auto r: reg ) {
        auto rgnName = r->getRegionName();
        if ( rgnName == ".rodata" ) {
            rodataStartPtr = (const char*)r->getPtrToRawData();
            rodataEndPtr = rodataStartPtr + r->getMemSize();
            rodataBeginAddr = r->getMemOffset();
            rodataEndAddr = r->getMemOffset() + r->getMemSize();
        }
    }

    // traverse call graph
    auto sts = new dp::SymtabCodeSource( const_cast<char*>( execName.c_str() ) );
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

                        if ( funcName == "dlopen" ) {
                            ondlopen( b, obj );
                        } else if ( funcName == "dlsym" ) {
                            // @TODO
                        }
                    }
                }
            }
        }
    }
}
