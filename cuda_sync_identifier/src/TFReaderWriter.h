#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <iostream>


enum TF_MODE {
	TF_READ = 0,
	TF_WRITE,	
};

enum TF_RECORD_TYPE {
	TF_UNKNOWN = 0,
	TF_SYNCRECORD,
	TF_TRANSFERREC,
};

struct TF_SyncRecord {
	uint64_t dynId, stackId, count;
	double time;
	bool FullCompare(TF_SyncRecord & other) {
		if (dynId == other.dynId && stackId == other.stackId && count == other.count && time == other.time)
			return true;
		return false;
	};
	void Write(FILE * fp) {
		fwrite(&dynId, 1, sizeof(uint64_t), fp);
		fwrite(&stackId, 1, sizeof(uint64_t), fp);
		fwrite(&count, 1, sizeof(uint64_t), fp);
		fwrite(&time, 1, sizeof(double), fp);
	};
	void Read(FILE * fp) {
		fread(&dynId, 1, sizeof(uint64_t), fp);
		fread(&stackId, 1, sizeof(uint64_t), fp);
		fread(&count, 1, sizeof(uint64_t), fp);
		fread(&time, 1, sizeof(double), fp);		
	};
};

struct TF_TransferRec {
	uint64_t dynId, stackId;
	double time;
	bool FullCompare(TF_TransferRec & other) {
		if (dynId == other.dynId && stackId == other.stackId && time == other.time)
			return true;
		return false;
	};
	void Write(FILE * fp) {
		fwrite(&dynId, 1, sizeof(uint64_t), fp);
		fwrite(&stackId, 1, sizeof(uint64_t), fp);
		fwrite(&time, 1, sizeof(double), fp);
	};
	void Read(FILE * fp) {
		fread(&dynId, 1, sizeof(uint64_t), fp);
		fread(&stackId, 1, sizeof(uint64_t), fp);
		fread(&time, 1, sizeof(double), fp);		
	};
};

struct TF_UnknownRec {
	void Write(FILE * fp) {};
	void Read(FILE * fp) {};
};


struct TF_Record {
	TF_SyncRecord s;
	TF_TransferRec r;
	TF_RECORD_TYPE type;
	bool FullCompare(TF_Record & other) {
		if (other.type == type) {
			if (type == TF_SYNCRECORD && s.FullCompare(other.s))
				return true;
			if (type == TF_TRANSFERREC &&  r.FullCompare(other.r))
				return true;
		}
		return false;
	};
	void Write(FILE * fp) {
		int tmp = int(type);
		fwrite(&tmp, 1, sizeof(int), fp);
		switch (type) {
			case TF_SYNCRECORD:
				s.Write(fp);
				break;
			case TF_TRANSFERREC: 
				r.Write(fp);
				break;
			default:
				std::cerr << "[TFRECORD] Unknown record write type, doing nothing" << std::endl;
				break;
		}
	};
	bool Read(FILE * fp) {
		int tmp;
		if (fread(&tmp, 1, sizeof(int), fp) <= 0)
			return false;
		type = TF_RECORD_TYPE(tmp);
		switch (type) {
			case TF_SYNCRECORD:
				s.Read(fp);
				break;
			case TF_TRANSFERREC: 
				r.Read(fp);
				break;
			default:
				std::cerr << "[TFRECORD] Unknown record read type, doing nothing" << std::endl;
				break;
		}
		return true;
	};	
};

struct TFReaderWriter {
	FILE * _file;
	TFReaderWriter() : _file(NULL) {}
	bool Open(const char * name, TF_MODE mode) {
		if (mode == TF_READ)
			_file = fopen(name, "rb");
		else if (mode == TF_WRITE)
			_file = fopen(name, "wb");
		if (_file == NULL)
			return false;
		return true;
	};
	~TFReaderWriter() {
		if (_file != NULL)
			fclose(_file);
	};
	bool Write(TF_Record & rec) {
		rec.Write(_file);
		return true;
	};
	bool Read(TF_Record & rec) {
		return rec.Read(_file);
	};
};