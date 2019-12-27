#pragma once
#include "StackPoint.h"
#include "SymbolLookup.h"
#include "TFReaderWriter.h"
#include "SerializeTypes.h"
#include <sstream> 
#define DEBUG_STACKRECORD 1

typedef std::map<std::string, std::shared_ptr<SymbolLookup> > SymbolMap;

struct SyncRangeRecord {
	uint64_t start;
	uint64_t end;
	uint64_t id;
	SyncRangeRecord(uint64_t i) {
		start = i;
		end = i;
		id = 0;
	};

	SyncRangeRecord(uint64_t i, uint64_t ident) {
		start = i;
		end = i;
		id = ident;
	};

	bool FullCompare(SyncRangeRecord & other) {
		if (other.start == start && other.end == end && other.id == id)
			return true;
		return false;
	};

	uint64_t SerializeFP(FILE * fp) {
		fwrite(&start, 1, sizeof(uint64_t), fp);
		fwrite(&end, 1, sizeof(uint64_t), fp);
		fwrite(&id, 1, sizeof(uint64_t), fp);
		return sizeof(uint64_t) * 3;
	};

	void DeserializeFP(FILE * fp) {
		ReadUint64(fp, start);
		ReadUint64(fp, end);
		ReadUint64(fp, id);
	}

	bool ExtendRange(uint64_t i) {
		if (end + 1 == i){
			end = end + 1;
			return true;
		}
		return false;
	};
	bool InRange(uint64_t i) {
		if (i == start || i == end || (i > start && i < end))
			return true;
		return false;
	};
};

struct TimingData {
	uint64_t genId;
	uint64_t stackId;
	uint64_t count;
	double time;

	TimingData() {}
};


class StackRecord {
public:
	StackRecord();
	StackRecord(uint64_t id, std::vector<StackPoint> & points);
	void AddOccurance(uint64_t pos);
	std::vector<std::string> GetLibNames();
	void ChangePointAtPosition(StackPoint p, uint64_t pos);
	void GetStackSymbols(SymbolMap & m);
	void AddStackRecord(uint64_t pos);
	void PrintStack();
	void PrintEncodedStack(std::ofstream & outStream);
	void PrintStack(std::ofstream & outStream);
	void PrintStack(std::stringstream & outStream);
	//void AddTimingData(uint64_t start, uint64_t len, double time);
	StackPoint GetFirstCudaCall();
	uint64_t GetFirstLibDynRTPosition(std::string extraLib = std::string(""));
	bool IsEqual(StackRecord & other);
	std::vector<StackPoint> GetStackpoints();
	void ReturnPreCudaCalls(std::vector<StackPoint> & ret);

	bool ReplaceLibDynRT(StackPoint p, std::string extraLib);
	void DeserializeStack(FILE * fp);
	uint64_t SerializeStack(FILE * fp);

	bool FullCompare(StackRecord & other);

	uint64_t _id;
	std::vector<TF_Record> _timing;
	std::vector<StackPoint> _points;
	std::vector<SyncRangeRecord> _ranges;
	std::vector<uint64_t> _occurances;
	//std::vector<TimingData> _timingData;
};

class CudaCallMap {
public: 
	CudaCallMap();
	// ID for stack record containing the cuda call s.
	void InsertStackID(std::string s, uint64_t id);
	uint64_t StackIDToGeneral(uint64_t id);
	uint64_t NameToGeneral(std::string s);
	std::string GeneralToName(uint64_t id);
	uint64_t GeneralToStackID(uint64_t id);
	// // Takes timer ID and sees if matches those for the c
	// void DoesIDMatch(std::string & s, uint64_t id);
	// uint64_t GetCallId(std::string & v);
	// uint64_t GetCallId(uint64_t v);
	// std::string GetCallFromString()
private:
	std::map<uint64_t, uint64_t> _stackToGeneral;
	//std::map<uint64_t, uint64_t> _generalToStack;
	std::map<std::string, uint64_t > _nameToGeneralID;
	uint64_t _pos;
	// StackID -> GeneralID
	// GeneralID,time,count
};

// class AppVisibleStacks {
// public:
// 	AppVisibleStacks();
// 	std::vector<StackPoint> GetUniqueCudaCalls();
// 	std::vector<uint64_t> GetIDs();
// 	//void AddStackRecord(StackRecord & rec);
// 	bool IsMember(StackRecord & rec);
// 	void AddStackRecord(uint64_t pos);
// 	void CheckTimingData(uint64_t start, uint64_t len, double time);
// private:
// 	std::vector<SyncRangeRecord> _ranges;
// };
