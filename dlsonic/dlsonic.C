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
#include <elf.h>

namespace dp = Dyninst::ParseAPI; 
namespace ds = Dyninst::SymtabAPI;
namespace di = Dyninst::InstructionAPI;

namespace {

std::string UNKNOWN = "<unknown>";

struct Stats
{
    std::string filename;
    int dlopenCount = 0;
    int dlsymCount = 0;
    int dlvsymCount = 0;
    int dlmopenCount = 0;
    int dlopenWithStaticString = 0;
    int dlsymWithStaticString = 0;
    int dlvsymWithStaticString = 0;
    int dlmopenWithStaticString = 0;
    int dlsymMapped = 0;
    int dlsymWithConstHandle = 0;
    int dlvsymMapped = 0;
    int dlvsymWithConstHandle = 0;
    
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
                  << STAT_FIX_STR(dlvsymMapped) << "|"
                  << STAT_FIX_STR(dlvsymWithConstHandle)
                  << "]\n";
#undef STAT_FIX_STR
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

    enum class CallType {
        DLOPEN,
        DLSYM,
        DLMOPEN,
        DLVSYM
    };

    enum class DlHandleType {
        CONST_RTLDDEFAULT,
        CONST_RTLDNEXT,
        CONST_UNKNOWN,
        CUSTOM
    };

    struct CallDetail {
        uint64_t id = 0;
        CallType ctype;
        DlHandleType htype = DlHandleType::CUSTOM;
        std::optional<uint32_t> mappedTo;
        uint64_t addr = 0;
        std::vector<std::string> paramStrs;
    };

    std::vector<CallDetail> calldetails;

    // used to map dlsym calls to corresponding dlopen calls
    std::map<uint32_t, std::vector<Dyninst::Node::Ptr>> dlsymIndex2RDISlice;
    std::map<uint32_t, std::vector<std::pair<uint32_t, uint32_t>>> dlopenIndex2CallFTBlock;

    // used while traversing the block graph
    std::map<uint32_t, bool> seen;
    
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

std::vector<Dyninst::Node::Ptr> doSlice(
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
                if ( curr.absloc().type() == Dyninst::Absloc::Register 
                        && curr.absloc().reg() == machRegInt )
                {
                    found = true;
                    regAssign = *it;
                    break;
                }
            }
        } else {
            auto curr = (*it)->out();
            if ( curr.absloc().type() == Dyninst::Absloc::Register
                    && curr.absloc().reg() == machRegInt )
            {
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

    auto slice = sliceForward ? handle.forwardSlice( predicate )
                              : handle.backwardSlice( predicate );
    
    // slice->printDOT( std::to_string( insAddr ) + "_" + regAssign->format() );

    Dyninst::NodeIterator bgn, edn;
    slice->allNodes( bgn, edn );

    std::vector<Dyninst::Node::Ptr> ret;
    for ( auto it = bgn; it != edn; ++it ) {
        ret.push_back(*it);
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
        return {};
    }
    return targetInst;
}

std::vector<std::string> trackArgRegisterString(
    int rgId, dp::Block* blk, ds::Symtab* obj, const dp::Function* fn )
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

    auto allNodes = doSlice(
        obj, firstInst.first, firstInst.second, fn, blk, rgId, false, false );

    std::vector<std::pair<di::Instruction, uint32_t>> allTargets;

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

bool containedInPLT( int64_t startAddr, int64_t endAddr )
{
    auto& state = GlobalData::Instance();
    return ( state.pltStartAddr     <= startAddr && endAddr <= state.pltEndAddr )    ||
           ( state.pltSecStartAddr  <= startAddr && endAddr <= state.pltSecEndAddr ) ||
           ( state.pltGotStartAddr  <= startAddr && endAddr <= state.pltGotEndAddr );
}


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
    auto index = GlobalData::Instance().calldetails.back().id; 
    GlobalData::Instance().dlopenIndex2CallFTBlock[index].push_back(
        std::make_pair( currFTBlk->start(), currFTBlk->end() ) );
    discover( currFTBlk, index );

}

void recordRDISlice( dp::Block* b, ds::Symtab* obj, const dp::Function* fn )
{
    std::optional<std::pair<di::Instruction, uint32_t>> inst;
    auto inst_rdi =  locateAssignmentInstruction( Dyninst::x86_64::irdi, b, obj, fn, false, false );
    auto inst_edi = locateAssignmentInstruction( Dyninst::x86_64::iedi, b, obj, fn, false, false );
    
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
    auto allNodes = doSlice( obj, val.first, val.second, fn, b, Dyninst::x86_64::irdi, false, false );

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
                // std::cout << result.convert<int64_t>() << std::endl;
                auto val = result.convert<int64_t>();
                if ( val == reinterpret_cast<int64_t>( RTLD_DEFAULT ) ) {
                    GlobalData::Instance().calldetails[index-1].htype = GlobalData::DlHandleType::CONST_RTLDDEFAULT;
                } else if (val == reinterpret_cast<int64_t>( RTLD_NEXT ) ) {
                    GlobalData::Instance().calldetails[index-1].htype = GlobalData::DlHandleType::CONST_RTLDNEXT; 
                } else {
                    std::cerr << "An unknown const handle found for dlsym call" << std::endl;
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
    std::string execName = argv[1];
    
    if ( execName.empty() ) {
        std::cerr << "Please provide input binary file via cmdline" << std::endl;
        return 1;
    }

    Stats::Instance().filename = execName;

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
                        auto recordResults = [&]( auto&& callCntr, auto&& strCntr, auto&& reg, auto&& calltype ) {
                            callCntr++;
                            auto strVec = trackArgRegisterString( reg, b, obj, f );
                            if ( ! strVec.empty() ) {
                                strCntr++;
                            }
                            GlobalData::Instance().calldetails.push_back(GlobalData::CallDetail{
                                .id = GlobalData::Instance().calldetails.size()+1, 
                                .ctype = calltype,
                                .htype = GlobalData::DlHandleType::CUSTOM,
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
                            recordCallFTBlock( b, obj, f );
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
                            recordCallFTBlock( b, obj, f );
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

    std::ostringstream mappingOut;

    for ( auto& index2slice : GlobalData::Instance().dlsymIndex2RDISlice ) {
        auto index = index2slice.first;
        if ( GlobalData::Instance().calldetails[index-1].htype != GlobalData::DlHandleType::CUSTOM ) {
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

