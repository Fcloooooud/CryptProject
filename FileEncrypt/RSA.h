#pragma once

#include <string>
#include <NTL/ZZ.h>

using namespace std;
using namespace NTL;

#define RSA_NO_PADDING 0
#define RSA_PKCS1_PADDING 1

typedef unsigned char BYTE;

class RSA {
private:
	ZZ p, q;
	ZZ euler;
	ZZ a;

	void GenerateKey();
	void SquareMul(ZZ& res, const ZZ base, const ZZ exp, const ZZ mod);

	void RSA_Padding(string origin, BYTE res[], int mode);
	void RSA_InvPadding(const BYTE res[], string& text, int mode);

public:
	const int KEYLEN;
	ZZ n, b;  // ¹«Ô¿

	RSA(int keylen = 1024) : KEYLEN(keylen) {
		this->GenerateKey();
	}
	string RSA_Encrypt(string PlainText);
	string RSA_Decrypt(string CipherText);
	string RSA_Encrypt(string PlainText, ZZ& A, ZZ& N);
	string RSA_Decrypt(string PlainText, ZZ& B, ZZ& N);
	string RSA_EncryptPrivateKey(string PlainText);
};
