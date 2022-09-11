#include <iostream>
#include <cstring>
#include <vector>

#include "BPatch.h"

#include "CFG.h"
#include "CodeObject.h"

#include <elf.h>

namespace dp = Dyninst::ParseAPI; 
namespace ds = Dyninst::SymtabAPI;

const int PLT_INIT_SIZE = 16;
const int PLT_SLOT_SIZE = 16;
const int GOT_SLOT_SIZE = 8;

struct GlobalMetaData {
	// we need to know location of PLT
	uint64_t pltBeginAddr;
	uint64_t pltEndAddr;

	// got offsets for dlopen and dlsym
	uint64_t dlopenGOTOffset;
	uint64_t dlsymGOTOffset;

	// got base addr
	uint64_t gotBaseAddr;

	// list of all known dynsyms
	std::vector<std::string> dynFuncSymStrs;
	std::vector<uint64_t> knownFuncGOTOffsets;

	static GlobalMetaData& Instance() {
		static GlobalMetaData obj;
		return obj;
	}
private:
	GlobalMetaData() = default;
};

void onDynStr( ds::Region* rgn )
{
	auto sz = rgn->getDiskSize();
	const char* data = (const char*)rgn->getPtrToRawData();
	int offset = 0;
	int cnt = 1;
	while ( offset < sz ) {
		auto currStr = std::string(data+offset);
		GlobalMetaData::Instance().dynFuncSymStrs.push_back(currStr);
		offset += currStr.size() + 1;
	}
}

void onRelaPlt( ds::Region* rgn )
{
	auto sz = rgn->getDiskSize();
	const char* data = (const char*) rgn->getPtrToRawData();
	int offset = 0;
	while ( offset < sz ) {
		auto entry = *reinterpret_cast<const Elf64_Rela*>( data + offset );
		offset += sizeof(Elf64_Rela);
		auto idx = entry.r_info >> 32;
		if ( GlobalMetaData::Instance().dynFuncSymStrs.size() > idx ) {
			auto& gotOffVec = GlobalMetaData::Instance().knownFuncGOTOffsets;
			gotOffVec.resize( std::max(gotOffVec.size(), idx + 1) );
			gotOffVec[idx] = entry.r_offset;
		}
	}
}

int main()
{
	ds::Symtab* obj = nullptr;
	std::ignore = ds::Symtab::openFile( obj, "testbins/trydl" );

	// parse dynsyms
	std::vector<ds::Symbol*> syms;
	std::ignore = obj->getAllSymbolsByType(syms, ds::Symbol::SymbolType::ST_FUNCTION);
	for ( auto sym: syms ) {
		if ( sym->isInDynSymtab() ) {
			auto idx = sym->getIndex();
			if ( GlobalMetaData::Instance().dynFuncSymStrs.size() <= idx ) {
				GlobalMetaData::Instance().dynFuncSymStrs.resize( idx + 1 );
			}
			GlobalMetaData::Instance().dynFuncSymStrs[idx] = sym->getMangledName();
		}
	}

	// parse relocation entries, and populate GOT offsets for known symbols
	std::vector<ds::Region*> reg;
	std::ignore = obj->getDataRegions(reg);

	for ( const auto r: reg ) {
		auto rgnName = r->getRegionName();
		if ( rgnName == ".rela.plt" ) {
			onRelaPlt( r );
		} else if ( rgnName == ".got" ) { // we probably should also be handling .got.plt
			GlobalMetaData::Instance().gotBaseAddr = r->getMemOffset();
		}
	}

	std::ignore = obj->getCodeRegions(reg);

	for ( const auto r: reg ) {
	 	auto rgnName = r->getRegionName();
		if ( rgnName == ".plt" ) {
			GlobalMetaData::Instance().pltBeginAddr = r->getMemOffset();
			GlobalMetaData::Instance().pltEndAddr = r->getMemOffset() + r->getMemSize();
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
					if ( calltgt->start() >= GlobalMetaData::Instance().pltBeginAddr && calltgt->end() <= GlobalMetaData::Instance().pltEndAddr ) {
					
						auto pltEntryAddr = calltgt->start() - GlobalMetaData::Instance().pltBeginAddr - PLT_INIT_SIZE;
						if ( pltEntryAddr % PLT_SLOT_SIZE ) {
							std::cerr << "Unrecognised PLT Slot Offset" << std::endl;
							return 1;
						}	

						auto slotId = pltEntryAddr / PLT_SLOT_SIZE;
						// it seems for PLT slot N, we jump to GOT slot N+3
						auto gotAddr = GlobalMetaData::Instance().gotBaseAddr + (slotId + 3) * GOT_SLOT_SIZE;


						for ( int i = 0; i < GlobalMetaData::Instance().knownFuncGOTOffsets.size(); ++i ) {
							if ( GlobalMetaData::Instance().knownFuncGOTOffsets[i] == gotAddr ) {
								std::cout << "Called: " << GlobalMetaData::Instance().dynFuncSymStrs[i] << std::endl;
							}
						}					
					}
				}
			}
		}
	}

}
