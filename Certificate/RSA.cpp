#include"RSA.h"

void RSA::GenerateKey()
{
	const int keyLen = KEYLEN;
	// 这里密钥长度是n的bit长度，所以p和q都取 keylen/2 位
	// 为了确保n一定是1024位（可能出现1023位的情况），需要判断位数并进行循环。
	do {
		RandomPrime(p, keyLen / 2, 10);
		RandomPrime(q, keyLen / 2, 10);
		n = p * q;
	} while (NumBits(n) != keyLen);

	cout << "numbits of n = " << NumBits(n) << endl;

	euler = (p - 1) * (q - 1);

	a = 3674911;
	ZZ d, t;
	XGCD(d, b, t, a, euler);

	if (b < 0) {
		b += euler;
	}

	ZZ tmp = MulMod(a, b, euler);
}



void RSA::SquareMul(ZZ& res, const ZZ base, const ZZ exp, const ZZ mod)
{
	int byteNum = NumBytes(exp);
	int bitNum = NumBits(exp);
	unsigned char* expBin = new unsigned char[byteNum + 1];
	BytesFromZZ(expBin, exp, byteNum);

	res = 1;
	for (int i = byteNum - 1; i >= 0; i--) {
		for (int n = min(8, bitNum - i * 8) - 1; n >= 0; n--) {
			SqrMod(res, res, mod);
			if ((expBin[i] >> n) & 0x01) {
				MulMod(res, res, base, mod);
			}
		}
	}

	delete[] expBin;
	return;
}

// zero padding
void RSA::PKCS1_Padding(string text, BYTE res[], int mode = RSA_NO_PADDING)
{
	int msgLen = text.length();

	int EBLen = KEYLEN / 8;
	int PSLen = EBLen - 3 - msgLen;
	memset(res, 0, EBLen); 

	ZZ paddingStr;
	RandomLen(paddingStr, PSLen * 8);
	BYTE* PS = new BYTE[PSLen];
	BytesFromZZ(PS, paddingStr, PSLen);

	int i = 0;

	switch (mode) {
		case RSA_PKCS1_PADDING:
			res[i++] = 0x00;
			res[i++] = 0x01; // sign
			for (i = 2; i < 2 + PSLen; i++)
				res[i] = PS[i - 2];
			res[i++] = 0x00;
			break;
		case RSA_NO_PADDING:
		default:
			for (i = 0; i < EBLen - msgLen; i++)
				res[i] = 0x00;
			break;
	}

	for (int j = 0; j < msgLen; j++) {
		res[i + j] = text[j];
	}

}

void RSA::PKCS1_InvPadding(const BYTE res[], string& text)
{
	int EBLen = KEYLEN / 8;

	text = "";

	int i;
	int index = 0;
	for (i = EBLen - 1; i >= 11 - 1; i--) {
		if (res[i] == 0x00)
			break;
	}
	i++;

	for (i; i < EBLen; i++) {
		text = text + (char)res[i];
	}

}

string RSA::RSA_Encrypt(string PlainText)
{
	int EBLen = KEYLEN / 8;
	string CipherText = "";

	int FullLen = PlainText.length();
	int BlockLen = (KEYLEN / 8) - 11;
	// blocknum 向上取整
	int BlockNum = (FullLen % BlockLen) == 0 ? FullLen / BlockLen : 1 + FullLen / BlockLen;
	//if (FullLen == 0)
	//	BlockNum = 1;
	// 不知道要不要考虑长度为0的情况，这里还是注释掉了。

	string tmpStr;
	BYTE* tmpByteArr = new BYTE[EBLen];
	char* tmpCharArr = new char[EBLen];
	ZZ tmpZZ, tmpResZZ;


	for (int i = 0; i < BlockNum; i++) {
		if (FullLen - i * BlockLen < BlockLen)
			tmpStr = PlainText.substr(i * BlockLen, FullLen - i * BlockLen);
		else
			tmpStr = PlainText.substr(i * BlockLen, BlockLen);


		PKCS1_Padding(tmpStr, tmpByteArr);

		ZZFromBytes(tmpZZ, tmpByteArr, EBLen);
		SquareMul(tmpResZZ, tmpZZ, a, n);
		BytesFromZZ(tmpByteArr, tmpResZZ, EBLen);

		tmpStr = "";
		for (int n = 0; n < EBLen; n++) {
			tmpStr = tmpStr + char(tmpByteArr[n]);
		}
		CipherText += tmpStr;
	}


	delete[] tmpByteArr;
	delete[] tmpCharArr;
	return CipherText;
}

string RSA::RSA_Decrypt(string CipherText)
{
	string PlainText = "";

	int FullLen = CipherText.length();
	int BlockLen = KEYLEN / 8;
	int BlockNum = FullLen / BlockLen;  // 一定是能整除的

	string tmpStr;
	BYTE* tmpByteArr = new BYTE[BlockLen];
	char* tmpCharArr = new char[BlockLen];

	ZZ tmpZZ, tmpResZZ;

	for (int i = 0; i < BlockNum; i++) {
		for (int n = 0; n < BlockLen; n++) {
			tmpByteArr[n] = CipherText[i * BlockLen + n];
		}

		ZZFromBytes(tmpZZ, tmpByteArr, BlockLen);
		SquareMul(tmpResZZ, tmpZZ, b, n);
		BytesFromZZ(tmpByteArr, tmpResZZ, BlockLen);

		PKCS1_InvPadding(tmpByteArr, tmpStr);
		PlainText += tmpStr;
	}

	return PlainText;
}
