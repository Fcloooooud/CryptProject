#include <iostream>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "AES_CBC.h"

const int sizeOfBYTE = 8;    // size of byte

DBYTE mul2(BYTE a, BYTE b)
{
	DBYTE b_ = b;
	DBYTE res = 0;
	for (int i = 0; i < 8; i++) {
		res = a & 1 ? res ^ b_ : res;
		a >>= 1;
		b_ <<= 1;
	}
	return res;
}

void div2(DBYTE a, DBYTE b, BYTE& q, BYTE& r)
{
	DBYTE tmp = 1 << 15;
	q = 0;
	int n;
	for (n = 0; n < 16; n++) {
		if (b & tmp) break;
		b <<= 1;
	}
	for (int i = 0; i <= n; i++) {
		q <<= 1;
		if (a & tmp) {
			a = a ^ b;
			q = q | 1;
		}
		b >>= 1;
		tmp >>= 1;
	}
	r = (BYTE)a;
}

//sa+tb=gcd(a, b)
void exgcd2(DBYTE a, DBYTE b, BYTE& s, BYTE& t) {
	if (a < b) {
		DBYTE tmp = a;
		a = b;
		b = tmp;
	}

	if (!b) {
		s = 1;
		t = 0;
		return;
	}

	BYTE q = 0, r = 0;
	div2(a, b, q, r);
	exgcd2(b, r, s, t);

	BYTE temp = s;
	s = t;
	t = temp ^ mul2(q, t);
}

BYTE AES::BinaryToField(BYTE n)
{
	BYTE q = 0, res = 0;
	div2(n, PRIMITIVE, q, res);
	return res;
}

BYTE AES::FieldToBinary(BYTE n)
{
	return n;
}

BYTE AES::FieldInv(BYTE n)
{
	BYTE s = 0, t = 0;
	exgcd2(PRIMITIVE, n, s, t);
	return t;
}

BYTE AES::FieldMult(BYTE a, BYTE b)
{
	DBYTE product = mul2(a, b);
	BYTE q = 0, r = 0;
	div2(product, PRIMITIVE, q, r);
	return r;
}

inline BYTE getBitPos(BYTE a, BYTE i)
{
	i = i % 8;
	a = a >> i;
	return a & 1;
}

BYTE AES::SubBytes(BYTE a)
{
	BYTE b = 0, z = 0;
	BYTE c = 0x63;
	z = BinaryToField(a);
	if (z)
		z = FieldInv(z);
	a = FieldToBinary(z);

	BYTE tmp = 0;

	// b ^= a>>4, a>>5, a>>6, a>>7, a>>8 (循环移位
	for (BYTE i = 0; i < 8; i++) {
		tmp = (getBitPos(a, i) ^ getBitPos(a, i + 4) ^ getBitPos(a, i + 5) ^ getBitPos(a, i + 6) ^ getBitPos(a, i + 7));
		b = b | (tmp << i);
	}

	b ^= c;

	return b;
}

BYTE AES::InvSubBytes(BYTE b)
{
	BYTE a = 0, z = 0;
	BYTE c = 0x63;
	b = b ^ c;

	BYTE tmp;
	// ai = b(i+2) ^ b(i+5) ^ b(i+7)
	for (BYTE i = 0; i < 8; i++) {
		tmp = (getBitPos(b, i + 2) ^ getBitPos(b, i + 5) ^ getBitPos(b, i + 7));
		a = a | (tmp << i);
	}

	z = BinaryToField(a);
	if (z)
		z = FieldInv(z);
	a = FieldToBinary(z);

	return a;
}

void AES::ShiftRows()
{
	BYTE tmp[4] = {};

	for (int c = 0; c < 4; c++) {
		for (int j = 0; j < 4; j++) {
			tmp[j] = State[j][c];
		}

		for (int r = 0; r < 4; r++) {
			State[r][c] = tmp[(r + c) % 4];
		}
	}
}

void AES::InvShiftRows()
{
	BYTE tmp[4] = {};

	for (int c = 0; c < 4; c++) {
		for (int j = 0; j < 4; j++) {
			tmp[j] = State[j][c];
		}

		for (int r = 0; r < 4; r++) {
			State[r][c] = tmp[(r - c + 4) % 4];
		}
	}

}

void AES::MixColumns(BYTE state[4][4])
{
	BYTE C[4][4] = { 0x02, 0x03, 0x01, 0x01,\
					 0x01, 0x02, 0x03, 0x01,
					 0x01, 0x01, 0x02, 0x03,
					 0x03, 0x01, 0x01, 0x02 };
	BYTE S_[4][4] = { 0 };

	DBYTE mulRes = 0;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			S_[i][j] = 0;
		}

		for (int j = 0; j < 4; j++) {
			for (int n = 0; n < 4; n++) {
				mulRes = FieldMult(C[j][n], state[i][n]);
				S_[i][j] ^= mulRes;
			}
		}
	}

	memcpy(state, S_, sizeof(S_));
}

void AES::InvMixColumns()
{
	BYTE C[4][4] = { 0x0e, 0x0b, 0x0d, 0x09,\
					 0x09, 0x0e, 0x0b, 0x0d,
					 0x0d, 0x09, 0x0e, 0x0b,
					 0x0b, 0x0d, 0x09, 0x0e };
	BYTE S_[4][4] = { 0 };

	DBYTE mulRes = 0;

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			S_[i][j] = 0;
		}

		for (int j = 0; j < 4; j++) {
			for (int n = 0; n < 4; n++) {
				mulRes = FieldMult(C[j][n], State[i][n]);
				S_[i][j] ^= mulRes;
			}
		}
	}

	memcpy(State, S_, sizeof(S_));
}

void AES::AddRoundKey(int n) //n:当前轮数
{
	DWORD S[4] = {};

	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			S[i] <<= sizeOfBYTE;
			S[i] |= State[i][j];
		}
	}

	for (int i = 0; i < 4; i++) {
		S[i] = S[i] ^ RoundKey[n * Nb + i];
	}

	for (int i = 0; i < 4; i++) {
		for (int j = 3; j >= 0; j--) {
			State[i][j] = S[i];
			S[i] >>= sizeOfBYTE;
		}
	}

}

void AES::InvAddRoundKey(int n)
{
	return AddRoundKey(n);  
}

DWORD AES::RotWord(DWORD b)
{
	DWORD tmp, res;
	tmp = b >> (3 * sizeOfBYTE);
	res = (b << sizeOfBYTE) ^ tmp;
	return res;
}

DWORD AES::SubWord(DWORD b)
{
	BYTE b0, b1, b2, b3;
	BYTE b0_, b1_, b2_, b3_;
	DWORD B_;
	b0 = (BYTE)(b >> (3 * sizeOfBYTE));
	b1 = (BYTE)(b >> (2 * sizeOfBYTE));
	b2 = (BYTE)(b >> (1 * sizeOfBYTE));
	b3 = (BYTE)b;
	//对b使用AES的S盒
	b0_ = SubBytes(b0);
	b1_ = SubBytes(b1);
	b2_ = SubBytes(b2);
	b3_ = SubBytes(b3);
	B_ = (b0_ << (3 * sizeOfBYTE)) ^ (b1_ << (2 * sizeOfBYTE)) ^ (b2_ << (1 * sizeOfBYTE)) ^ b3_;
	return B_;
}

DWORD* AES::KeyExpansion(BYTE* key)
{
	DWORD* w = new DWORD[Nb * (Nr + 1)]; 

	const DWORD RCon[Nr] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, \
							0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000 };
	int i;

	for (i = 0; i <= 3; i++) {
		w[i] = (key[4 * i] << (3 * sizeOfBYTE)) ^ (key[4 * i + 1] << (2 * sizeOfBYTE)) ^ \
			(key[4 * i + 2] << (1 * sizeOfBYTE)) ^ (key[4 * i + 3]);
	}
	DWORD temp = 0;
	for (i = 4; i <= 43; i++) {
		temp = w[i - 1];
		if (!(i % 4)) {
			temp = SubWord(RotWord(temp)) ^ RCon[i / 4 - 1];
		}
		w[i] = w[i - 4] ^ temp;
	}

	memcpy(RoundKey, w, sizeof(RoundKey));

	return w;
}

void AES::AES_SetKey(const BYTE* key)
{
	memcpy(KEY, key, sizeof(KEY));

}

void AES::AES_Encrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb])
{
	this->mode = MODE_ENCRYPT;
	KeyExpansion(this->KEY);

	//将State初始化为x

	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i][j] = in[i * 4 + j];


	//将RoundKey和State异或
	AddRoundKey(0);

	//前Nr-1轮
	for (int n = 1; n <= Nr - 1; n++) {

		//subbytes
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				State[i][j] = SubBytes(State[i][j]);

		//shiftrows
		ShiftRows();

		//mixcolumns
		MixColumns(State);

		//addroundkey
		AddRoundKey(n);

	}

	//第Nr轮
	//subbytes
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i][j] = SubBytes(State[i][j]);

	//shiftrows
	ShiftRows();

	//addroundkey
	AddRoundKey(Nr);

	// 输出
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			out[i * 4 + j] = State[i][j];

}

void AES::AES_Decrypt(const BYTE in[4 * Nb], BYTE out[4 * Nb])
{
	this->mode = MODE_DECRYPT;
	KeyExpansion(this->KEY);

	//将State初始化为x
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i][j] = in[i * 4 + j];


	//将RoundKey和State异或
	AddRoundKey(Nr);

	//前Nr-1轮
	for (int n = Nr - 1; n >= 1; n--) {
		// inv shiftrows
		InvShiftRows();

		//inv subbytes
		for (int i = 0; i < 4; i++)
			for (int j = 0; j < 4; j++)
				State[i][j] = InvSubBytes(State[i][j]);

		// addroundkey
		InvAddRoundKey(n);

		// inv mixcolumns
		InvMixColumns();

	}


	//第Nr轮
	//shiftrows
	InvShiftRows();

	//subbytes
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			State[i][j] = InvSubBytes(State[i][j]);


	//addroundkey
	InvAddRoundKey(0);


	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 4; j++)
			out[i * 4 + j] = State[i][j];

}


void AES_CBC::XOR(BYTE cur[], BYTE pre[])
{
	//blockSize
	for (int i = 0; i < blockSize; i++) {
		cur[i] = cur[i] ^ pre[i];
	}
}

void AES_CBC::setIV()
{
    // 将IV直接初始化为全0
	memset(IV, 0, sizeof(IV));
}

void AES_CBC::setPaddingMode(bool mode) {
	this->paddingMode = mode;
}

void AES_CBC::Padding(const string& str, BYTE block[], bool paddingMode, bool isLastBlock)
{
	int i;
	int len = str.length();


	for (i = 0; i < len; i++) {
		block[i] = str[i];
	}
	if (paddingMode == ZeroPadding) {
		for (i; i < blockSize; i++) {
			block[i] = 0x00;
		}
	}
	else if (paddingMode == PKCS7Padding) {
		BYTE pad = blockSize - len;
		for (i; i < blockSize; i++) {
			block[i] = pad;
		}
	}

	return;
}

void AES_CBC::InvPadding(string& str, const BYTE block[], bool paddingMode, bool isLastBlock)
{
	int i = blockSize - 1;

	str = "";
	if (isLastBlock) {
		if (paddingMode == ZeroPadding) {
			for (i = blockSize - 1; i >= 0; i--) {
				if (block[i] != 0x00)
					break;
			}
		}
		else if (paddingMode == PKCS7Padding) {
			//bool padFlag = 0;
			BYTE count = 0;
			int pad = block[blockSize - 1]; // 如果是00 不可能是pad 直接不考虑

			for (i = blockSize - 1; i >= blockSize - pad; i--) {
				if (block[i] != pad)
					break;
			}
		}
	}

	for (int j = 0; j <= i; j++) {
		str += block[j];
	}

	return;
}


//const int keyLen = 128;   // key length(nk words)

void AES_CBC::AES_CBC_Encrypt(const string& input, string& output)
{
	int fullLen = input.length();
	int blockNum = fullLen / blockSize + 1;
	string tmp = "";

	output = "";

	string tmpStr;
	BYTE* tmpInput = new BYTE[blockSize];
	BYTE* tmpOutput = new BYTE[blockSize];

	setIV();
	BYTE* prev = new BYTE[blockSize];
	memcpy(prev, IV, blockSize);

	for (int i = 0; i < blockNum; i++) {
		if (fullLen - i * blockSize < blockSize)
			tmpStr = input.substr(i * blockSize, fullLen - i * blockSize); 
		else
			tmpStr = input.substr(i * blockSize, blockSize); //需要padding
		Padding(tmpStr, tmpInput, paddingMode, (i == blockNum - 1));
		XOR(tmpInput, prev);
		AES_Encrypt(tmpInput, tmpOutput);


		tmpStr = "";
		for (int j = 0; j < blockSize; j++) {
			tmpStr += tmpOutput[j];
		}

		memcpy(prev, tmpOutput, blockSize);
		output += tmpStr;

	}
	return;
}

string AES_CBC::AES_CBC_Encrypt(const string& input)
{
	int fullLen = input.length();
	int blockNum = fullLen / blockSize + 1;
	string tmp = "";

	string output = "";


	string tmpStr;
	BYTE* tmpInput = new BYTE[blockSize];
	BYTE* tmpOutput = new BYTE[blockSize];

	setIV();
	BYTE* prev = new BYTE[blockSize];
	memcpy(prev, IV, blockSize);

	for (int i = 0; i < blockNum; i++) {
		if (fullLen - i * blockSize < blockSize)
			tmpStr = input.substr(i * blockSize, fullLen - i * blockSize);  
		else
			tmpStr = input.substr(i * blockSize, blockSize); //需要padding
		Padding(tmpStr, tmpInput, paddingMode, (i==blockNum-1));
		XOR(tmpInput, prev);
		AES_Encrypt(tmpInput, tmpOutput);

		tmpStr = "";
		
		for (int j = 0; j < blockSize; j++) {
			tmpStr += tmpOutput[j];
		}

		memcpy(prev, tmpOutput, blockSize);
		output += tmpStr;

	}

	return output;
}


void AES_CBC::AES_CBC_Decrypt(const string& input, string& output)
{
	int fullLen = input.length();
	int blockNum = fullLen / blockSize;
	string tmp = "";

	output = "";

	string tmpStr;
	BYTE* tmpInput = new BYTE[blockSize];
	BYTE* tmpOutput = new BYTE[blockSize];

	setIV();
	BYTE* prev = new BYTE[blockSize];
	memcpy(prev, IV, blockSize);

	for (int i = 0; i < blockNum; i++) {
		tmpStr = input.substr(i * blockSize, blockSize);
		for (int j = 0; j < blockSize; j++)
			tmpInput[j] = tmpStr[j];

		AES_Decrypt(tmpInput, tmpOutput);
		XOR(tmpOutput, prev);
		InvPadding(tmpStr, tmpOutput, paddingMode, (i == blockNum - 1));
		output += tmpStr;

		memcpy(prev, tmpInput, blockSize);
	}
	return;
}

string AES_CBC::AES_CBC_Decrypt(const string& input)
{
	int fullLen = input.length();
	int blockNum = fullLen / blockSize;
	string tmp = "";

	string output = "";

	string tmpStr;
	BYTE* tmpInput = new BYTE[blockSize];
	BYTE* tmpOutput = new BYTE[blockSize];

	setIV();
	BYTE* prev = new BYTE[blockSize];
	memcpy(prev, IV, blockSize);

	for (int i = 0; i < blockNum; i++) {

		tmpStr = input.substr(i * blockSize, blockSize);
		for (int j = 0; j < blockSize; j++) 
			tmpInput[j] = tmpStr[j];

		AES_Decrypt(tmpInput, tmpOutput);

		XOR(tmpOutput, prev);
		InvPadding(tmpStr, tmpOutput, paddingMode, (i == blockNum - 1));
		output += tmpStr;
		
		memcpy(prev, tmpInput, blockSize);
	}
	return output;
}
