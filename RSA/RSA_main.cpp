#include <iostream>
#include <fstream>
#include "RSA.h"

using namespace std;
using namespace NTL;

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

	//cout << "numbits of n = " << NumBits(n) << endl;

	euler = (p - 1) * (q - 1);

	b = 3674911;
	ZZ d, t;
	XGCD(d, a, t, b, euler);

	if (a < 0) {
		a += euler;
	}
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

void RSA::PKCS1_Padding(string text, BYTE res[], int mode = RSA_PKCS1_PADDING)
{
	int msgLen = text.length();

	int EBLen = KEYLEN / 8;
	int PSLen = EBLen - 3 - msgLen;
	memset(res, 0, EBLen); //这里应该不会越界8

	ZZ paddingStr;
	RandomLen(paddingStr, PSLen * 8);
	BYTE* PS = new BYTE[PSLen];
	BytesFromZZ(PS, paddingStr, PSLen);

	int i = 0;

	for (i = 0; i < msgLen; i++) {
		res[i] = text[i];
	}

	switch (mode) {
		case RSA_PKCS1_PADDING:
			res[i++] = 0x00;
			res[i++] = 0x01; // sign
			for (int j = 0; j < PSLen; j++)
				res[i++] = PS[j];
			res[i++] = 0x00;
			break;
		case RSA_NO_PADDING:
		default:
			// 在后面用0x00填充
			for (i; i < EBLen; i++)
				res[i] = 0x00;
			break;
	}
}

void RSA::PKCS1_InvPadding(const BYTE res[], string& text, int mode = RSA_PKCS1_PADDING)
{
	int EBLen = KEYLEN / 8;

	text = "";
	
	int i;
	switch (mode) {
		case RSA_PKCS1_PADDING:
			for (i = 0; i < EBLen; i++)
				if (res[i] == 0x00)
					break;
			for (int j = 0; j < i; j++)
				text = text + (char)res[j];
			break;
		case RSA_NO_PADDING:
		default:
			// 在后面用0x00填充
			for (i = 0; i < EBLen; i++)
				if (res[i] == 0x00)
					break;
			for (int j = 0; j < i; j++)
				text = text + (char)res[j];
			break;
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

bool readFile(const string fileName, string& content)
{
	ifstream fin(fileName, ios::binary);        // 以二进制方式打开文件
	if (!fin) {				                    // 输出错误信息并退出
		cerr << "Can not open the input file!" << endl;
		return false;
	}
	istreambuf_iterator<char> beg(fin), end;   // 设置两个文件指针，指向开始和结束，以char(一字节)为步长
	string c(beg, end);                        // 将文件全部读入string字符串
	fin.close();                               // 关闭文件句柄
	content = c;
	return true;
}

bool writeFile(const string fileName, const string content)
{
	ofstream fout(fileName, ios::binary);  // 打开输出文件
	if (!fout) {					       // 输出错误信息并退出
		cerr << "Can not open the output file!" << endl;
		return false;
	}
	fout << content;                       // 直接将操作好的字符串进行输出
	fout.close();						   // 关闭文件
	return true;
}


int main()
{
	int kLen = 1024;
	cout << "请选择密钥长度：(1) 1024  (2) 2048" << endl;
	int sel;
	cin >> sel;
	kLen = (sel == 1) ? 1024 : 2048;

	RSA* rsa = new RSA(kLen);

	string in, out, de;
	cout << "请输入需要加密的文件名：" << endl;
	string fileName, eFileName, dFileName;
	cin >> fileName;
	if (!(readFile(fileName, in))) 
		return 0;

	eFileName = "encrypted.txt";
	dFileName = "decrypted.txt";

	out = rsa->RSA_Encrypt(in);
	cout << "加密结束 ! " << endl;
	if (writeFile(eFileName, out)) {
		cout << "加密结果已写入" << eFileName << endl;
	}
	de = rsa->RSA_Decrypt(out);
	cout << "解密结束 ! " << endl;
	if (writeFile(dFileName, de)) {
		cout << "解密结果已写入" << dFileName << endl;
	}
	delete rsa;
	system("pause");
	return 0;
}