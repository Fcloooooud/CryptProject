#include<iostream>
#include<fstream>
#include<string.h>
#include<stdio.h>
#include<string>
#include<stdlib.h>
#include<time.h>

#include "AES.h"

using namespace std;

#define  ZeroPadding  0
#define  PKCS7Padding 1

const int blockSize = keyLen / sizeOfBYTE;

class AES_CBC : public AES {
	bool paddingMode;   // paddingģʽ
	BYTE IV[blockSize]; // ��ʼ������
	void setIV();		// ���ó�ʼ������
	void XOR(BYTE cur[], BYTE pre[]); // block�и��ֽڰ�λ������
	void Padding(const string& str, BYTE block[], bool paddingMode, bool isLastBlock);
	void InvPadding(string& str, const BYTE block[], bool paddingMode, bool isLastBlock);
public:
	void setPaddingMode(bool mode);
	void AES_CBC_Encrypt(const string& input, string& output);
	void AES_CBC_Decrypt(const string& input, string& output);

};

void AES_CBC::XOR(BYTE cur[], BYTE pre[])
{
	//blockSize
	for (int i = 0; i < blockSize; i++){
		cur[i] = cur[i] ^ pre[i];
	}
}

void AES_CBC::setIV()
{
	srand(time(NULL));
	int r;
	for (int i = 0; i < blockSize; i += 2) {
		r = rand();
		IV[i] = r >> 8;
		IV[i + 1] = r;
	}
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
			int pad = block[blockSize - 1]; // �����00 ��������pad ֱ�Ӳ�����

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
			tmpStr = input.substr(i * blockSize, blockSize); //��Ҫpadding
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
	return;
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



bool readFile(const string fileName, string& content)
{
	ifstream fin(fileName, ios::binary);        // �Զ����Ʒ�ʽ���ļ�
	if (!fin) {				                    // ���������Ϣ���˳�
		cerr << "Can not open the input file!" << endl;
		return false;
	}
	istreambuf_iterator<char> beg(fin), end;   // ���������ļ�ָ�룬ָ��ʼ�ͽ�������char(һ�ֽ�)Ϊ����
	string c(beg, end);                        // ���ļ�ȫ������string�ַ���
	fin.close();                               // �ر��ļ����
	content = c;
	return true;
}

bool writeFile(const string fileName, const string content)
{
	ofstream fout(fileName, ios::binary);  // ������ļ�
	if (!fout) {					       // ���������Ϣ���˳�
		cerr << "Can not open the output file!" << endl;
		return false;
	}
	fout << content;                       // ֱ�ӽ������õ��ַ����������
	fout.close();						   // �ر��ļ�
	return true;
}


int main()
{
	AES_CBC* c = new AES_CBC;
	string in, out, de;
	cout << "��������Ҫ���ܵ��ļ�����" << endl;
	string fileName, eFileName, dFileName;
	cin >> fileName;
	if (!(readFile(fileName, in))) 
		return 0;

	int pos = fileName.find_last_of('.');
	string sub = fileName.substr(pos, fileName.length() - pos);
	eFileName = "encrypted.txt";
	dFileName = "decrypted" + sub;

	c->setPaddingMode(PKCS7Padding);
	c->AES_CBC_Encrypt(in, out);
	cout << "���ܽ��� !" << endl;
	if (writeFile(eFileName, out)) {
		cout << "���ܽ����д��" << eFileName << " !" << endl;
	}
	c->AES_CBC_Decrypt(out, de);
	cout << "���ܽ��� !" << endl;
	if (writeFile(dFileName, de)) {
		cout << "���ܽ����д��" << dFileName << " !" << endl;
	}

	system("pause");
	return 0;
}