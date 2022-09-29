#include <iostream>
#include <cstring>
#include <vector>
#include <queue>
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

namespace {

struct Stats
{
    int dlopenCount = 0;
    int dlsymCount = 0;
    int dlmopenCount = 0;
    int dlopenWithStaticString = 0;
    int dlsymWithStaticString = 0;
    int dlmopenWithStaticString = 0;

    static Stats& Instance() {
        static Stats obj;
        return obj;
    }

    void print()
    {
        std::cout << "Analysis Summary\n"
                  << " total # dlopen(...) calls:   " << dlopenCount << '\n' 
                  << " dlopen with static strings:  " << dlopenWithStaticString << '\n'
                  << " total # dlsym(...) calls:    " << dlsymCount << '\n'
                  << " dlsym with static strings:   " << dlsymWithStaticString << '\n'
                  << " total # dlmopen(...) calls:  " << dlmopenCount << '\n'
                  << " dlmopen with static strings: " << dlmopenWithStaticString
                  << std::endl;
    }
    
private:
    Stats() {}
};

std::string UNKNOWN = "<unknown>";

std::string trackArgRegisterString( std::string rgName, dp::Block* blk, ds::Symtab* obj )
{
    // Currently we only handle the case when we have a static string assigned
    // i.e. we have an instruction: lea REG [ADDR in RODATA]
    // Note that the address here may depend on RIP, so we manually calculate
    // RIP and plug it into the AST to evaluate.
    ds::Region* reg = obj->findEnclosingRegion( blk->start() );
    if ( ! reg ) {
        return UNKNOWN;
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
               if ( w->format() == rgName ) {
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
        std::cerr << "could not locate given register: " << rgName << std::endl;
        return UNKNOWN;
    }

    // We want to look for first LEA instruction to the arg register we are tracking
    if ( targetInst.first.getOperation().getID() == e_lea 
         && targetInst.first.getOperand(0).getValue()->format() == rgName ) {
        // We will try to evaluate this, by just plugging in RIP.
        // The address may depend on RIP in PIC.
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

        if ( ripExpr ) {
            targetValue->bind(
                ripExpr.get(),
                di::Result( di::u32, targetInst.first.size() + targetInst.second ) );
        }
        auto targetResult = targetValue->eval();

        if ( ! targetResult.defined  ) {
            std::cout << "could not calculate address loaded to the given register: "
                      << rgName << std::endl;
            return UNKNOWN;
        }


        auto targetRegion = obj->findEnclosingRegion( targetResult.val.u32val );
        
        if ( targetRegion->getRegionName() != ".rodata" ) {
            // We are reading an address but not from the rodata section.
            std::cerr << "the read address does not belong to rodata" << std::endl;
            return UNKNOWN;
        }

        return std::string(
            (const char*)targetRegion->getPtrToRawData()
            + targetResult.val.u32val
            - targetRegion->getMemOffset()
        );        
    } else {
        // All other cases will land here, which we don't know how to
        // handle just yet.
        return UNKNOWN;
    }
}

} // end anonymous namespace

int main( int argc, char* argv[] )
{
    std::string execName = argv[1];
    
    if ( execName.empty() ) {
        std::cerr << "Please provide input binary file via cmdline" << std::endl;
        return 1;
    }

    ds::Symtab* obj = nullptr;
    bool success = ds::Symtab::openFile( obj, execName ); 
    
    if ( ! success ) {
        std::cerr << "Could not open file: " << execName << std::endl;
        return 1;
    }

    std::cout << "Processing File: " << execName << std::endl;

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

                        if ( funcName == "dlopen" ) {
                            Stats::Instance().dlopenCount++;
                            auto param = trackArgRegisterString( "RDI", b, obj );
                            if ( param != UNKNOWN ) { 
                                Stats::Instance().dlopenWithStaticString++;    
                            }
                            std::cout << funcName << " : " << param << std::endl;
                        } else if ( funcName == "dlsym" ) {
                            Stats::Instance().dlsymCount++;
                            auto param = trackArgRegisterString( "RSI", b, obj );
                            if ( param != UNKNOWN ) {
                                Stats::Instance().dlsymWithStaticString++;
                            }
                            std::cout << funcName << " : " << param << std::endl;
                        } else if ( funcName == "dlmopen" ) {
                            Stats::Instance().dlmopenCount++;
                            auto param = trackArgRegisterString( "RSI", b, obj );
                            if ( param != UNKNOWN ) {
                                Stats::Instance().dlmopenWithStaticString++;
                            }
                            std::cout << funcName << " : " << param << std::endl;
                        }
                    }
                }
            }
        }
    }
    Stats::Instance().print();
}
