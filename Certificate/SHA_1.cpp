#include"SHA_1.h"

// 规定x的长度是 512/8 的倍数
vector<DWORD> Byte2Word(vector<BYTE> x)
{
	DWORD byteLen = x.size();
	DWORD wordLen = byteLen / 4;
	vector<DWORD> res(wordLen, 0);
	DWORD tmp;
	for (DWORD i = 0; i < wordLen; i++) {
		tmp = 0;
		for (int n = 0; n < 4; n++) {
			tmp = tmp << sizeOfBYTE;
			tmp = tmp | x[i * 4 + n];
		}
		res[i] = tmp;
	}

	return res;
}

vector<vector<DWORD>> SHA_1::SHA_Pad(string x)
{
	const DWORD width = sizeOfBLOCK / sizeOfBYTE; //64;

	DWORD len = x.length();  //最多64位 但是vector大小有限 这里只记32位
	DWORD bitNum = len * sizeOfBYTE;
	DWORD blockNum;
	if ((len % width) != 0)
		blockNum = len / width + 1;
	else
		blockNum = len / width;

	DWORD byteNum = blockNum * width;
	vector<BYTE> temp(byteNum, 0); //字节数

	DWORD i, j;
	for (i = 0; i < len; i++)
		temp[i] = x[i];
	temp[i] = 0x80;
	for (j = 0; j < 4; j++)
		temp[byteNum - 1 - j] = (BYTE)(bitNum >> (j * sizeOfBYTE)); //低位赋值

	vector<DWORD> tempWord = Byte2Word(temp);

	vector<vector<DWORD>> y(blockNum, vector<DWORD>(sizeOfBLOCK / sizeOfDWORD));
	for (i = 0; i < blockNum; i++) {
		for (j = 0; j < sizeOfBLOCK / sizeOfDWORD; j++) {
			y[i][j] = tempWord[i * sizeOfBLOCK / sizeOfDWORD + j];
		}
	}

	return y;
}

//循环左移
DWORD SHA_1::ROTL(DWORD x, int s)
{
	return (x << s) | x >> (32 - s);
}

DWORD SHA_1::Kt(int t)
{
	if (t <= 19)
		return 0x5A827999;
	else if (t <= 39)
		return 0x6ED9EBA1;
	else if (t <= 59)
		return 0x8F1BBCDC;
	else
		return 0xCA62C1D6;
}

DWORD SHA_1::Ft(int t, DWORD B, DWORD C, DWORD D)
{
	if (t <= 19)
		return (B & C | ((~B) & D));
	else if (t <= 39)
		return (B ^ C ^ D);
	else if (t <= 59)
		return (B & C) | (B & D) | (C & D);
	else
		return (B ^ C ^ D);
}

void SHA_1::setW(vector<DWORD> m)
{
	for (int i = 0; i < 16; i++) {
		W[i] = m[i];
	}
}

vector<DWORD> SHA_1::SHA_Encrypt(string x)
{
	vector<vector<DWORD>> y = SHA_Pad(x);

	H0 = 0x67452301;
	H1 = 0xEFCDAB89;
	H2 = 0x98BADCFE;
	H3 = 0x10325476;
	H4 = 0xC3D2E1F0;


	int n = y.size();
	for (int i = 0; i < n; i++) {
		setW(y[i]);


		for (int t = 16; t <= 79; t++) {
			W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
		}

		A = H0;
		B = H1;
		C = H2;
		D = H3;
		E = H4;

		for (int t = 0; t <= 79; t++) {
			DWORD temp = ROTL(A, 5) + Ft(t, B, C, D) + E + W[t] + Kt(t);
			E = D;
			D = C;
			C = ROTL(B, 30);
			B = A;
			A = temp;
		}

		H0 = H0 + A;
		H1 = H1 + B;
		H2 = H2 + C;
		H3 = H3 + D;
		H4 = H4 + E;
	}

	vector<DWORD> res = { H0, H1, H2, H3, H4 };

	return res;
}