#include "SerializeTypes.h"




uint64_t SerializeUint64(FILE * fp, uint64_t val) {
	fwrite(&val, 1, sizeof(uint64_t), fp);
	return sizeof(uint64_t);
};

void ReadUint64(FILE * fp, uint64_t & val) {
	fread(&val, 1, sizeof(uint64_t), fp);
	//return sizeof(uint64_t);
};


uint64_t SerializeSring(FILE * fp, std::string & str) {
	uint64_t size = str.size();
	fwrite(&size, 1, sizeof(uint64_t), fp);
	if (size > 0)
		fwrite(str.c_str(), sizeof(char), size, fp);
	return sizeof(uint64_t) + size;
};

void DeserializeString(FILE * fp, std::string & ret) {
	uint64_t size = 0;
	ReadUint64(fp, size);
	if (size > 0) {
		std::shared_ptr<char> tmp(new char[size+1]);
		fread(tmp.get(), sizeof(char), size, fp);
		ret = std::string(tmp.get(), size);
	}
};

uint64_t SerializeBool(FILE * fp, bool b) {
	uint8_t bt = 0;
	if(b)
		bt = 1;
	fwrite(&bt, 1, sizeof(uint8_t), fp);
	return sizeof(uint8_t);
};
void DeserializeBool(FILE * fp, bool & b) {
	uint8_t bt;
	fread(&bt, 1, sizeof(uint8_t), fp);
	if (bt == 1)
		b = true;
	else 
		b = false;
};

