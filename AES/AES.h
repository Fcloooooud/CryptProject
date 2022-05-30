#pragma once

typedef unsigned char  BYTE;
typedef unsigned short DBYTE;
typedef unsigned long  WORD;

const int sizeOfBYTE = 8; // size of byte
const int keyLen = 128;   // key length(nk words)
const int Nr = 10;		  // number of rounds
const int Nb = 4;		  // block size

class AES {
private:
	const DBYTE PRIMITIVE = 0x011b;  //x^8+x^4+x^3+x+1

	bool mode;

	BYTE KEY[4 * Nb] = { 0 };             // 密钥
	BYTE State[4][Nb] = { 0 };            // 存入的状态
	WORD RoundKey[Nb * (Nr + 1)] = { 0 }; // 轮密钥

	BYTE BinaryToField(BYTE n);
	BYTE FieldToBinary(BYTE n);
	BYTE FieldInv(BYTE n);
	BYTE FieldMult(BYTE a, BYTE b);

	WORD SubWord(WORD b);
	WORD RotWord(WORD b);
	WORD* KeyExpansion(BYTE* key);

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
	void AES_SetKey(const BYTE* key);
	void AES_Encrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb]);
	void AES_Decrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb]);
};
