#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <queue>
#include <dlfcn.h>
#include "BPatch.h"
#include "Graph.h"
#include "slicing.h"
#include "dyn_regs.h"
#include "CFG.h"
#include "CodeObject.h"
#include "InstructionDecoder.h"
#include "entryIDs.h"
#include "dyntypes.h"
#include <elf.h>

namespace dp = Dyninst::ParseAPI; 
namespace ds = Dyninst::SymtabAPI;
namespace di = Dyninst::InstructionAPI;

namespace {

std::string UNKNOWN = "<unknown>";

// Statistics to capture binary analysis summary for a given binary.
struct Stats
{
    std::string filename;
    // counters for the 4 functions we are tracking
    int dlopenCount = 0;
    int dlsymCount = 0;
    int dlvsymCount = 0;
    int dlmopenCount = 0;

    // counters for calls for which we are able to backtrack
    // arguments (or parts of them) to .rodata
    int dlopenWithStaticString = 0;
    int dlsymWithStaticString = 0;
    int dlvsymWithStaticString = 0;
    int dlmopenWithStaticString = 0;

    // these are to count the # dlsym/dlvsym calls that can be matched
    // with a corresponding dlopen call.
    int dlsymMapped = 0;
    int dlvsymMapped = 0;

    // ideally dlsymWithConstHandl == dlsymWithRTLD_NEXT + dlsymWithRTLD_DEFAULT
    int dlsymWithConstHandle = 0;
    int dlsymWithRTLD_NEXT = 0;
    int dlsymWithRTLD_DEFAULT = 0;
    
    static Stats& Instance() {
        static Stats obj;
        return obj;
    }

    void print()
    {
#define STAT_FIX_STR(x) (#x "=" + std::to_string(x)) 
        std::cout << "DIGEST:" << filename << "=["
                  << STAT_FIX_STR(dlopenCount) << "|"
                  << STAT_FIX_STR(dlopenWithStaticString) << "|"
                  << STAT_FIX_STR(dlsymCount) << "|"
                  << STAT_FIX_STR(dlsymWithStaticString) << "|"
                  << STAT_FIX_STR(dlvsymCount) << "|"
                  << STAT_FIX_STR(dlvsymWithStaticString) << "|"
                  << STAT_FIX_STR(dlmopenCount) << "|"
                  << STAT_FIX_STR(dlmopenWithStaticString) << "|"
                  << STAT_FIX_STR(dlsymMapped) << "|"
                  << STAT_FIX_STR(dlsymWithConstHandle) << "|"
                  << STAT_FIX_STR(dlsymWithRTLD_NEXT) << "|"
                  << STAT_FIX_STR(dlsymWithRTLD_DEFAULT) << "|"
                  << STAT_FIX_STR(dlvsymMapped)
                  << "]\n";
#undef STAT_FIX_STR
    }
    
private:
    Stats() {}
};

// Store global state helpful in processing
struct GlobalData
{
    // .plt and .plt.sec section limits
    Dyninst::Address pltStartAddr = 0;
    Dyninst::Address pltEndAddr = 0;
    Dyninst::Address pltSecStartAddr = 0;
    Dyninst::Address pltSecEndAddr = 0;
    // haven't seen a pltGot example but anyway:
    Dyninst::Address pltGotStartAddr = 0;
    Dyninst::Address pltGotEndAddr = 0;

    // index to identify particular calls to dlopen and dlsym
    uint32_t index = 0;

    enum class CallType {
        DLOPEN,
        DLSYM,
        DLMOPEN,
        DLVSYM
    };

    enum class DlHandleType {
        CONST_RTLDDEFAULT,
        CONST_RTLDNEXT,
        CONST_UNKNOWN,  // a const handle which we don't know about
        UNRESOLVED      // this means handle comes from dlopen
    };

    // We capture this information each time we find a call to one of the functions
    // we are tracking.
    struct CallDetail {
        uint64_t id = 0;
        CallType ctype;
        DlHandleType htype = DlHandleType::UNRESOLVED;
        std::optional<uint32_t> mappedTo;
        Dyninst::Address addr = 0;
        std::vector<std::string> paramStrs;
    };

    std::vector<CallDetail> calldetails;

    // used to map dlsym calls to corresponding dlopen calls
    std::map<uint32_t, std::vector<Dyninst::Node::Ptr>> dlsymIndex2RDISlice;
    std::map<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>> dlopenIndex2CallFTBlock;

    // used while traversing the block graph
    std::map<Dyninst::Address, bool> seen;
    
    static GlobalData& Instance() {
        static GlobalData obj;
        return obj;
    }

    static std::string getFuncName( CallType ct ) {
        if ( ct == CallType::DLOPEN  ) return "dlopen";
        if ( ct == CallType::DLMOPEN ) return "dlmopen";
        if ( ct == CallType::DLSYM   ) return "dlsym";
        if ( ct == CallType::DLVSYM  ) return "dlvsym";
        return UNKNOWN;
    }
private:
    GlobalData() {}
};

// Extract needed assignment from an assignment and slice forward/backward
std::vector<Dyninst::Node::Ptr> doSlice(
    di::Instruction insObj, Dyninst::Address insAddr,
    const dp::Function* fn, dp::Block* blk, int machRegInt )
{
    auto fnNoConst = const_cast<dp::Function*>( fn );
    
    Dyninst::AssignmentConverter ac( true, true );
    std::vector<Dyninst::Assignment::Ptr> assignments;
    ac.convert( insObj, insAddr, fnNoConst, blk, assignments );

    Dyninst::Assignment::Ptr regAssign;
    for ( auto it = assignments.begin(); it != assignments.end(); ++it ) {
        auto curr = (*it)->out();
        if ( curr.absloc().type() == Dyninst::Absloc::Register
                && curr.absloc().reg() == machRegInt )
        {
            regAssign = *it;
            break;
        }
    }

    if ( ! regAssign.get() ) {
        return {};
    }
    
    Dyninst::Slicer handle( regAssign, blk, fnNoConst, true, true );
    Dyninst::Slicer::Predicates predicate;

    auto slice = handle.backwardSlice( predicate );
    
    // slice->printDOT( std::to_string( insAddr ) + "_" + regAssign->format() );

    Dyninst::NodeIterator bgn, edn;
    slice->allNodes( bgn, edn );

    std::vector<Dyninst::Node::Ptr> ret;
    for ( auto it = bgn; it != edn; ++it ) {
        ret.push_back(*it);
    }

    return ret;
}

// locate the last assignment to a register in a given basic block
std::optional<std::pair<di::Instruction, Dyninst::Address>> locateAssignmentInstruction(
    int rgId, dp::Block* blk, ds::Symtab* obj )
{
    ds::Region* reg = obj->findEnclosingRegion( blk->start() );
    if ( ! reg ) {
        return {};;
    }

    auto bufStart = (const char*) reg->getPtrToRawData() + blk->start() - reg->getMemOffset();
    auto bufSize = blk->end() - blk->start();

    auto decoder = di::InstructionDecoder( bufStart, bufSize, Dyninst::Arch_x86_64 );
    
    std::vector<std::pair<di::Instruction, Dyninst::Address>> instrVec;

    // We are know that our code block will end with a call to dlopen, we are
    // interested in instructions immediately before it to figure out how the
    // arguments are setup.

    Dyninst::Address offset = blk->start();

    while ( true ) {
        auto currInst = decoder.decode();
        if ( ! currInst.isValid() ) {
            break;
        }
        instrVec.push_back( std::make_pair( currInst, offset ) );
        offset += currInst.size();
    }

    std::reverse( instrVec.begin(), instrVec.end() );

    std::pair<di::Instruction, Dyninst::Address> targetInst;
    bool found = false;
    for ( auto inst: instrVec ) {
        // find first instruction whose operands involve RDI/EDI in the write set
        std::vector<di::Operand> instOpr;
        inst.first.getOperands( instOpr );
        for ( auto op: instOpr ) {
            std::set<di::RegisterAST::Ptr> regSet;
            op.getWriteSet( regSet );
            
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
        return {};
    }
    return targetInst;
}

// Main entry point for tracking arguments for a call. The block passed here is assumed
// to end in a call instruction and rgId denotes the register that is supposed to
// contain the passed argument to the call. Currently, we use backward slice and fetch
// all instances where we end in .rodata.
std::vector<std::string> trackArgRegisterString(
    int rgId, dp::Block* blk, ds::Symtab* obj, const dp::Function* fn )
{
    auto firstInstObj = locateAssignmentInstruction ( rgId, blk, obj ); 

    if ( ! firstInstObj.has_value() ) {
        return {};
    }

    auto firstInst = firstInstObj.value();

    auto allNodes = doSlice(
        firstInst.first, firstInst.second, fn, blk, rgId );

    std::vector<std::pair<di::Instruction, Dyninst::Address>> allTargets;

    for ( auto it = allNodes.begin(); it != allNodes.end(); ++it ) {
        auto sliceNode = dynamic_cast<Dyninst::SliceNode*>( (*it).get() );
        auto insn = sliceNode->assign()->insn();
        allTargets.push_back( std::make_pair( insn, sliceNode->addr() ) );
    }


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
                continue;
            }


            auto targetRegion = obj->findEnclosingRegion( targetResult.val.u32val );
            
            if ( targetRegion->getRegionName() != ".rodata" ) {
                // We are reading an address but not from the rodata section.
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

bool containedInPLT( Dyninst::Address startAddr, Dyninst::Address endAddr )
{
    auto& state = GlobalData::Instance();
    return ( state.pltStartAddr     <= startAddr && endAddr <= state.pltEndAddr )    ||
           ( state.pltSecStartAddr  <= startAddr && endAddr <= state.pltSecEndAddr ) ||
           ( state.pltGotStartAddr  <= startAddr && endAddr <= state.pltGotEndAddr );
}


// Discover more blocks starting from block b, without follwing CALL or RET branches.
void discover( dp::Block* b, uint32_t index )
{
    GlobalData::Instance().seen[b->start()] = true;
    GlobalData::Instance().dlopenIndex2CallFTBlock[index]
        .push_back(std::make_pair(b->start(), b->end()));
    
    for ( auto e : b->targets() ) {
        // If this block has a CALL edge, it means the last instruction is a
        // CALL, which means we should not follow through any further.
        if ( e->type() == dp::CALL ) {
            return;
        }
    }

    for ( auto e : b->targets() ) {
        // We need to follow all edges, except for those relating to function calls
        if ( e->type() == dp::CALL  || e->type() == dp::RET || e->type() == dp::CATCH ) {
            continue;
        }
        if ( ! GlobalData::Instance().seen[e->trg()->start()] ) {
            discover( e->trg(), index );
        }
    }
}

// Upon seeing a dlopen/dlmopen call, we record all the potential basic blocks
// where the return value register might be valid.
void recordCallFTBlock( dp::Block* b )
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
    auto index = GlobalData::Instance().calldetails.back().id; 
    GlobalData::Instance().dlopenIndex2CallFTBlock[index].push_back(
        std::make_pair( currFTBlk->start(), currFTBlk->end() ) );
    
    // similar mark all blocks which are reachable from CALL_FT block without
    // returning from current function, 
    discover( currFTBlk, index );
}

// Upon seeing a dlsym/dlvsym call, we backward slice for the argument register containing
// the handle. While doing so we also check if the handle is one RTLD_DEFAULT or RTLD_NEXT.
void recordRDISlice( dp::Block* b, ds::Symtab* obj, const dp::Function* fn )
{
    std::optional<std::pair<di::Instruction, Dyninst::Address>> inst;
    auto inst_rdi =  locateAssignmentInstruction( Dyninst::x86_64::irdi, b, obj );
    auto inst_edi = locateAssignmentInstruction( Dyninst::x86_64::iedi, b, obj );
    
    if ( inst_rdi.has_value() ) {
        inst = inst_rdi;
    } else if ( inst_edi.has_value() ) {
        inst = inst_edi;
    } else {
        // this means we couldn't find any assignment to RDI
        // typically this will imply that a dlsym with nullptr
        // often this appears as xor rdi rdi.
        return;
    }

    auto val = inst.value();
    auto allNodes = doSlice( val.first, val.second, fn, b, Dyninst::x86_64::irdi );

    auto index = GlobalData::Instance().calldetails.back().id;

    // now we look at constant assignment case
    // instead of the handle for dlsym, RTLD_NEXT / RTLD_DEFAULT are often passed
    // we need to keep track of these 
    if ( allNodes.size() == 1 ) {
        auto sliceNode = dynamic_cast<Dyninst::SliceNode*>( allNodes.back().get() );
        auto tgt = sliceNode->assign()->insn();
        if ( tgt.getOperation().getID() == e_mov ) {
            auto result = tgt.getOperand(1).getValue()->eval();
            if ( result.defined ) {
                // Internally dyninst is storing void* values as unsigned 4 byte values
                auto val = result.convert<int32_t>();
                if ( val == reinterpret_cast<int64_t>( RTLD_DEFAULT ) ) {
                    GlobalData::Instance().calldetails[index-1].htype = GlobalData::DlHandleType::CONST_RTLDDEFAULT;
                    Stats::Instance().dlsymWithRTLD_DEFAULT++;
                } else if (val == reinterpret_cast<int64_t>( RTLD_NEXT ) ) {
                    GlobalData::Instance().calldetails[index-1].htype = GlobalData::DlHandleType::CONST_RTLDNEXT; 
                    Stats::Instance().dlsymWithRTLD_NEXT++;
                } else {
                    std::cerr << "Found an unknown const handle found for dlsym call: " << val << std::endl;
                    GlobalData::Instance().calldetails[index-1].htype = GlobalData::DlHandleType::CONST_UNKNOWN; 
                }
                Stats::Instance().dlsymWithConstHandle++;
            }
        }
    }

    GlobalData::Instance().dlsymIndex2RDISlice[index] = allNodes; 
}

bool sliceNodeContainsRAXIn( Dyninst::Node::Ptr node )
{
    auto insn = dynamic_cast<Dyninst::SliceNode*>(node.get())->assign()->insn();

    std::vector<di::Operand> instOpr;
    insn.getOperands( instOpr );

    for ( auto op: instOpr ) {
        std::set<di::RegisterAST::Ptr> regSet;
        op.getReadSet( regSet );
        for ( auto w: regSet ) {
            if ( w->getID() == Dyninst::x86_64::irax ) {
                return true;
            }
        }
    }

    return false;
}


} // end anonymous namespace

int main( int argc, char* argv[] )
{
    if ( argc != 2 ) {
        std::cerr << "Expected number of arguments is 1" << std::endl;
        return 1;
    }

    std::string execName = argv[1];
    
    if ( execName.empty() ) {
        std::cerr << "Please provide input binary file via cmdline" << std::endl;
        return 1;
    }

    Stats::Instance().filename = execName;

    ds::Symtab* obj = nullptr;
    bool success = ds::Symtab::openFile( obj, execName ); 
    
    if ( ! success ) {
        std::cerr << "Could not open file, are you sure it is an ELF file? " << execName << std::endl;
        return 1;
    }

    std::cout << "Processing File: " << execName << std::endl;

    std::vector<ds::Region*> reg;
    std::ignore = obj->getCodeRegions( reg );

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
                        auto recordResults = [&]( auto&& callCntr, auto&& strCntr, auto&& reg, auto&& calltype ) {
                            callCntr++;
                            auto strVec = trackArgRegisterString( reg, b, obj, f );
                            if ( ! strVec.empty() ) {
                                strCntr++;
                            }
                            GlobalData::Instance().calldetails.push_back(GlobalData::CallDetail{
                                .id = GlobalData::Instance().calldetails.size()+1, 
                                .ctype = calltype,
                                .htype = GlobalData::DlHandleType::UNRESOLVED,
                                .mappedTo = {},
                                .addr = b->last(),
                                .paramStrs = strVec
                            });
                        };
                        
                        if ( funcName == "dlopen" ) {
                            recordResults(
                                Stats::Instance().dlopenCount,
                                Stats::Instance().dlopenWithStaticString,
                                Dyninst::x86_64::irdi,
                                GlobalData::CallType::DLOPEN
                            );
                            // Take note of the call fallthrough block for this dlopen call
                            // the returned value i.e. the lib handle is likely to be handled here.
                            // This does not extensively cover all cases, control flow change (like ifs)
                            // right after function call may break this scheme. But using it as a
                            // starting point.
                            recordCallFTBlock( b );
                        } else if ( funcName == "dlsym" ) {
                            recordResults(
                                Stats::Instance().dlsymCount,
                                Stats::Instance().dlsymWithStaticString,
                                Dyninst::x86_64::irsi,
                                GlobalData::CallType::DLSYM
                            );
                            // For each dlsym call, we look at the backward slice of RDI.
                            // This should help us find references to RAX that belong to the call FT
                            // block of corresponding dlopen.
                            recordRDISlice( b, obj, f );
                        } else if ( funcName == "dlmopen" ) {
                            recordResults(
                                Stats::Instance().dlmopenCount,
                                Stats::Instance().dlmopenWithStaticString,
                                Dyninst::x86_64::irsi,
                                GlobalData::CallType::DLMOPEN
                            );
                            recordCallFTBlock( b );
                        } else if ( funcName == "dlvsym" ) {
                            recordResults(
                                Stats::Instance().dlvsymCount,
                                Stats::Instance().dlvsymWithStaticString,
                                Dyninst::x86_64::irsi,
                                GlobalData::CallType::DLVSYM
                            );
                            recordRDISlice( b, obj, f ); 
                        }
                    }
                }
            }
        }
    }

    for ( auto& index2slice : GlobalData::Instance().dlsymIndex2RDISlice ) {
        auto index = index2slice.first;
        if ( GlobalData::Instance().calldetails[index-1].htype != GlobalData::DlHandleType::UNRESOLVED ) {
            continue;
        }
        auto& slice = index2slice.second;
        bool done = false;
        for ( auto& node : slice ) {            
            Dyninst::NodeIterator bgn, edn;
            bool isRAXIn = sliceNodeContainsRAXIn( node );
            if ( ! isRAXIn ) {
                continue;
            }
            node->ins( bgn, edn );
            for ( auto it = bgn; it != edn; ++it ) {
                if ( sliceNodeContainsRAXIn( *it ) ) {
                    isRAXIn = false;
                    break;
                }
            }
            if ( isRAXIn ) {
                auto addr = node->addr();
                for ( auto index2range : GlobalData::Instance().dlopenIndex2CallFTBlock ) {
                    for ( auto interval : index2range.second ) {
                        if ( addr >= interval.first && addr < interval.second ) {
                            done = true;
                            if ( GlobalData::Instance().calldetails.size() >= index ) {
                                GlobalData::Instance().calldetails[index-1].mappedTo = {index2range.first};
                            }
                            if ( GlobalData::Instance().calldetails.size() >= index &&
                                 GlobalData::Instance().calldetails[index-1].ctype 
                                 == GlobalData::CallType::DLVSYM )
                            {
                                Stats::Instance().dlvsymMapped++;    
                            } else {
                                Stats::Instance().dlsymMapped++;
                            }
                            break;
                        }
                    }
                }
            }
            if ( done ) {
                break;
            }
        }
    }

    // Print all results
    for ( auto& det : GlobalData::Instance().calldetails ) {
        std::cout   << "CALLDETAIL:" << execName << "=["
                    << "Id=" << std::dec << det.id << "|"
                    << "Addr=" << std::hex << det.addr << "|"
                    << "Type=" << GlobalData::getFuncName( det.ctype ) << "|"
                    << "Param=";
        if ( ! det.paramStrs.empty() ) {
            std::cout << "[";
            for ( size_t i = 0; i < det.paramStrs.size(); ++i ) {
                if ( i != 0 ) {
                    std::cout << "|";
                }
                std::cout << det.paramStrs[i];
            }
            std::cout << "]";
        } else {
            std::cout << UNKNOWN;
        }
        if ( det.ctype == GlobalData::CallType::DLSYM
             || det.ctype == GlobalData::CallType::DLVSYM )
        {
            std::cout << "|Handle=";
            if ( det.mappedTo.has_value() ) {
                std::cout << std::dec << det.mappedTo.value();
            } else if ( det.htype == GlobalData::DlHandleType::CONST_RTLDDEFAULT ) {
                std::cout << "RTLD_DEFAULT";
            } else if ( det.htype == GlobalData::DlHandleType::CONST_RTLDNEXT ) {
                std::cout << "RTLD_NEXT";
            } else {
                std::cout << UNKNOWN;
            }
        }
        std::cout << "]\n";
    }

    Stats::Instance().print();

}

