#include <iostream>
#include <cstring>
#include <vector>
#include <queue>
#include "BPatch.h"
#include "Graph.h"
#include "slicing.h"
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

struct GlobalData
{
    int64_t pltStartAddr = 0;
    int64_t pltEndAddr = 0;
    int64_t pltSecStartAddr = 0;
    int64_t pltSecEndAddr = 0;
    // haven't seen a pltGot example but anyway:
    int64_t pltGotStartAddr = 0;
    int64_t pltGotEndAddr = 0;

    // index to identify particular calls to dlopen and dlsym
    uint32_t index = 0;

    std::map<uint32_t, std::vector<std::pair<di::Instruction, uint32_t>>> dlsymIndex2RDISlice;
    std::map<uint32_t, std::pair<uint32_t, uint32_t>> dlopenIndex2CallFTBlock;

    static GlobalData& Instance() {
        static GlobalData obj;
        return obj;
    }

    void updateIndex() {
        index++;
    }
private:
    GlobalData() {}
};

std::string UNKNOWN = "<unknown>";


std::vector<std::pair<di::Instruction, uint32_t>> doSlice(
    ds::Symtab* obj, di::Instruction insObj, int32_t insAddr,
    const dp::Function* fn, dp::Block* blk, int machRegInt,
    bool sliceForward, bool isInput )
{
    auto fnNoConst = const_cast<dp::Function*>( fn );
    
    Dyninst::AssignmentConverter ac( true, true );
    std::vector<Dyninst::Assignment::Ptr> assignments;
    ac.convert( insObj, insAddr, fnNoConst, blk, assignments );

    Dyninst::Assignment::Ptr regAssign;
    for ( auto it = assignments.begin(); it != assignments.end(); ++it ) {
        bool found = false;
        if ( isInput ) {
            for ( auto curr: (*it)->inputs() ) {
                if ( curr.absloc().type() == Dyninst::Absloc::Register && curr.absloc().reg() == machRegInt ) {
                    found = true;
                    regAssign = *it;
                    break;
                }
            }
        } else {
            auto curr = (*it)->out();
            if ( curr.absloc().type() == Dyninst::Absloc::Register && curr.absloc().reg() == machRegInt ) {
                found = true;
                regAssign = *it;
            }
        }
        if ( found ) {
            break;
        }
    }

    if ( ! regAssign.get() ) {
        return {};
    }
    
    Dyninst::Slicer handle( regAssign, blk, fnNoConst, true, true );
    Dyninst::Slicer::Predicates predicate;

    auto slice = sliceForward ? handle.forwardSlice( predicate ) : handle.backwardSlice( predicate );
    
    slice->printDOT( std::to_string( insAddr ) + "_" + regAssign->format() );

    Dyninst::NodeIterator bgn, edn;
    slice->allNodes( bgn, edn );

    
    std::vector<std::pair<di::Instruction, uint32_t>> ret;

    for ( auto it = bgn; it != edn; ++it ) {
        auto sliceNode = dynamic_cast<Dyninst::SliceNode*>( (*it).get() );
        auto insn = sliceNode->assign()->insn();
        ret.push_back( std::make_pair( insn, sliceNode->addr() ) );
    }

    return ret;
    
}

std::optional<std::pair<di::Instruction, uint32_t>> locateAssignmentInstruction(
    int rgId, dp::Block* blk, ds::Symtab* obj, const dp::Function* fn, bool isInput, bool isFirst )
{
    ds::Region* reg = obj->findEnclosingRegion( blk->start() );
    if ( ! reg ) {
        return {};;
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

    if ( ! isFirst ) {
        std::reverse( instrVec.begin(), instrVec.end() );
    }

    std::pair<di::Instruction, uint32_t> targetInst;
    bool found = false;
    for ( auto inst: instrVec ) {
        // find first instruction whose operands involve RDI/EDI in the write set
        std::vector<di::Operand> instOpr;
        inst.first.getOperands( instOpr );
        for ( auto op: instOpr ) {
            std::set<di::RegisterAST::Ptr> regSet;
            if ( isInput ) {
                op.getReadSet( regSet );
            } else {
                op.getWriteSet( regSet );
            }
            
            for ( auto w: regSet ) {
               if ( w->getID() == rgId ) {
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
        std::cerr << "could not locate given register: " << rgId << std::endl;
        return {};
    }
    return targetInst;
}

std::vector<std::string> trackArgRegisterString( int rgId, dp::Block* blk, ds::Symtab* obj, const dp::Function* fn )
{
    // Currently we only handle the case when we have a static string assigned
    // i.e. we have an instruction: lea REG [ADDR in RODATA]
    // Note that the address here may depend on RIP, so we manually calculate
    // RIP and plug it into the AST to evaluate.

    auto firstInstObj = locateAssignmentInstruction ( rgId, blk, obj, fn, false, false ); 

    if ( ! firstInstObj.has_value() ) {
        return {};
    }

    auto firstInst = firstInstObj.value();

    auto allTargets = doSlice(
        obj, firstInst.first, firstInst.second, fn, blk, rgId, false, false );

    std::vector<std::string> results;
    
    for ( auto targetInst: allTargets ) {
        // We want to look for first LEA instruction to the arg register we are tracking
        if ( targetInst.first.getOperation().getID() == e_lea ) {
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
                          << rgId << std::endl;
                continue;
            }


            auto targetRegion = obj->findEnclosingRegion( targetResult.val.u32val );
            
            if ( targetRegion->getRegionName() != ".rodata" ) {
                // We are reading an address but not from the rodata section.
                std::cerr << "the read address does not belong to rodata" << std::endl;
                continue;
            }

            results.push_back( std::string(
                (const char*)targetRegion->getPtrToRawData()
                + targetResult.val.u32val
                - targetRegion->getMemOffset()
            ) );
        }
    }
    return results;
}

bool containedInPLT( int64_t startAddr, int64_t endAddr )
{
    auto& state = GlobalData::Instance();
    return ( startAddr >= state.pltStartAddr && endAddr <= state.pltEndAddr ) ||
           ( startAddr >= state.pltSecStartAddr && endAddr <= state.pltSecEndAddr ) ||
           ( startAddr >= state.pltGotStartAddr && endAddr <= state.pltGotEndAddr );
}

void recordCallFTBlock(
    dp::Block* b, ds::Symtab* obj, const dp::Function* fn )
{
    dp::Block* currFTBlk = nullptr;
    int callFTEdgeCount = 0;
    for ( auto e : b->targets() ) {
        if ( e->type() == dp::CALL_FT ) {
            callFTEdgeCount++;
            currFTBlk = e->trg();
        }
    }

    // there should only be one CALL_FT block corresponding to a dlopen call
    assert( callFTEdgeCount == 1 );

    // save the CALL_FT block's start and end addresses
    GlobalData::Instance().dlopenIndex2CallFTBlock[GlobalData::Instance().index]
        = std::make_pair( currFTBlk->start(), currFTBlk->end() );
}

void recordRDISlice( dp::Block* b, ds::Symtab* obj, const dp::Function* fn )
{
    auto inst =  locateAssignmentInstruction( Dyninst::x86_64::irdi, b, obj, fn, false, false );
    assert ( inst.has_value() );
    auto val = inst.value();
    auto allTargets = doSlice( obj, val.first, val.second, fn, b, Dyninst::x86_64::irdi, false, false );
    GlobalData::Instance().dlsymIndex2RDISlice[GlobalData::Instance().index] = allTargets; 
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
            GlobalData::Instance().pltStartAddr = r->getMemOffset();
            GlobalData::Instance().pltEndAddr = r->getMemOffset() + r->getMemSize();
        } else if ( rgnName == ".plt.sec" ) {
            GlobalData::Instance().pltSecStartAddr = r->getMemOffset();
            GlobalData::Instance().pltSecEndAddr = r->getMemOffset() + r->getMemSize();
        } else if ( rgnName == ".plt.got" ) {
            GlobalData::Instance().pltGotStartAddr = r->getMemOffset();
            GlobalData::Instance().pltGotEndAddr = r->getMemOffset() + r->getMemSize();
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
                    if ( containedInPLT( calltgt->start(), calltgt->end() ) ) {

                        std::vector<dp::Function*> containingFuncs;

                        calltgt->getFuncs( containingFuncs );
                        
                        if ( calltgt->containingFuncs() != 1 ) {
                            std::cerr << "each plt slot entry should belong to "
                                         "exactly one function" << std::endl;
                            return 1;
                        }

                        auto funcName = containingFuncs.back()->name();
                        auto printAndRecordResults = [&]( auto&& callCntr, auto&& strCntr, auto&& reg ) {
                            callCntr++;
                            auto strVec = trackArgRegisterString( reg, b, obj, f );
                            std::cout << GlobalData::Instance().index << " => " << funcName << " : ";
                            if ( ! strVec.empty() ) {
                                strCntr++;
                                for ( auto val: strVec ) {
                                    std::cout << val << " ";
                                }
                            } else {
                                std::cout << UNKNOWN;
                            }
                            std::cout << std::endl;
                        };
                        
                        if ( funcName == "dlopen" ) {
                            GlobalData::Instance().updateIndex();
                            printAndRecordResults(
                                Stats::Instance().dlopenCount,
                                Stats::Instance().dlopenWithStaticString,
                                Dyninst::x86_64::irdi 
                            );
                            recordCallFTBlock( b, obj, f );
                        } else if ( funcName == "dlsym" ) {
                            GlobalData::Instance().updateIndex();
                            printAndRecordResults(
                                Stats::Instance().dlsymCount,
                                Stats::Instance().dlsymWithStaticString,
                                Dyninst::x86_64::irsi
                            );
                            recordRDISlice( b, obj, f );
                        } else if ( funcName == "dlmopen" ) {
                            GlobalData::Instance().updateIndex();
                            printAndRecordResults(
                                Stats::Instance().dlmopenCount,
                                Stats::Instance().dlmopenWithStaticString,
                                Dyninst::x86_64::irsi
                            );
                        }
                    }
                }
            }
        }
    }


    Stats::Instance().print();


    std::cout << "Finding DLSYM <- DLOPEN mappings" << std::endl;
    for ( auto& index2slice : GlobalData::Instance().dlsymIndex2RDISlice ) {
        auto index = index2slice.first;
        auto& slice = index2slice.second;
        
        for ( auto& node : slice ) {
            std::vector<di::Operand> instOpr;
            node.first.getOperands( instOpr );
            for ( auto op: instOpr ) {
                std::set<di::RegisterAST::Ptr> regSet;
                op.getReadSet( regSet );
                bool found = false;
                for ( auto w: regSet ) {
                    if ( w->getID() == Dyninst::x86_64::irax ) {
                        found = true;
                        break;
                    }
                }
                if ( found ) {
                    // we have found an instruction in the slice that reads from the
                    // RAX, just need to see if this RAX has anything to do        
                    for ( auto index2range : GlobalData::Instance().dlopenIndex2CallFTBlock ) {
                        if ( node.second >= index2range.second.first && node.second < index2range.second.second ) {
                            std::cout << index << " <- " << index2range.first << std::endl;
                        }
                    }
                }
            }
        }
    }
    std::cout << "End of mappings" << std::endl;
}
