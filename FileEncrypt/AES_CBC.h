#pragma once
#include<string>
using namespace std;

typedef unsigned char BYTE;
typedef unsigned short DBYTE;
typedef unsigned long DWORD;


#define MODE_ENCRYPT 0
#define MODE_DECRYPT 1

#define  ZeroPadding  0
#define  PKCS7Padding 1

const int AESkeyLen = 128;   // key length(nk words)
const int Nr = 10;		     // number of rounds
const int Nb = 4;		     // block size

const int blockSize = AESkeyLen / 8;

class AES {
private:
	const DBYTE PRIMITIVE = 0x011b;  //x^8+x^4+x^3+x+1

	bool mode;


	BYTE State[4][Nb] = { 0 };
	DWORD RoundKey[Nb * (Nr + 1)] = { 0 };

	BYTE BinaryToField(BYTE n);
	BYTE FieldToBinary(BYTE n);
	BYTE FieldInv(BYTE n);
	BYTE FieldMult(BYTE a, BYTE b);

	DWORD SubWord(DWORD b);
	DWORD RotWord(DWORD b);
	DWORD* KeyExpansion(BYTE* key);

	//AES的四个运算
	BYTE SubBytes(BYTE a);
	void ShiftRows();
	void MixColumns(BYTE state[4][4]);
	void AddRoundKey(int n);

	//逆运算
	BYTE InvSubBytes(BYTE b);
	void InvShiftRows();
	void InvMixColumns();
	void InvAddRoundKey(int n);

public:
	BYTE KEY[4 * Nb] = { 0 }; 
	void AES_SetKey(const BYTE* key);
	void AES_Encrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb]);
	void AES_Decrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb]);
};


class AES_CBC : public AES {
private:
	bool paddingMode;
	BYTE IV[blockSize];
	void XOR(BYTE cur[], BYTE pre[]);
	void setIV();
	void Padding(const string& str, BYTE block[], bool paddingMode, bool isLastBlock);
	void InvPadding(string& str, const BYTE block[], bool paddingMode, bool isLastBlock);
public:
	void setPaddingMode(bool mode);

	void AES_CBC_Encrypt(const string& input, string& output);
	void AES_CBC_Decrypt(const string& input, string& output);
	string AES_CBC_Encrypt(const string& input);
	string AES_CBC_Decrypt(const string& input);
};