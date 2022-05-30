#include<stdio.h>
#include<iostream>
#include<fstream>
#include "RSA.h"
#include "SHA_1.h"

using namespace std;

class RSA_Sign : public RSA, protected SHA_1 {
private:
	string ID;

public:
	RSA_Sign(int keylen = 1024) : RSA(keylen) {};

	void setId(const string& id) { ID = id; };
	void getId(string& id) { id = ID; };

	string Signature(const string& input);
	bool Verify(const string& input, string sign);
};

string RSA_Sign::Signature(const string& input)
{
	vector<DWORD> wr = this->SHA_Encrypt(input);
	string tmp = "";
	for (int i = 0; i < wr.size(); i++) {
		tmp += char(wr[i] >> 3 * sizeOfBYTE);
		tmp += char(wr[i] >> 2 * sizeOfBYTE);
		tmp += char(wr[i] >> 1 * sizeOfBYTE);
		tmp += char(wr[i]);
	}
	string sign = this->RSA_Encrypt(tmp);
	return sign;
}

bool RSA_Sign::Verify(const string& input, string sign)
{
	string deSign = this->RSA_Decrypt(sign);

	vector<DWORD> wr = this->SHA_Encrypt(input);
	string tmp = "";
	for (int i = 0; i < wr.size(); i++) {
		tmp += char(wr[i] >> 3 * sizeOfBYTE);
		tmp += char(wr[i] >> 2 * sizeOfBYTE);
		tmp += char(wr[i] >> 1 * sizeOfBYTE);
		tmp += char(wr[i]);
	}

	return (deSign == tmp);
}

void writeTA(const string file, RSA_Sign* TA)
{
	ofstream fout(file, ios::binary);    // ������ļ�
	if (!fout) {
		cerr << "Can not open the output file!" << endl;   // ���������Ϣ���˳�
		return;
	}

	string str = "";
	TA->getId(str);
	// �� id n b ��˳��д��

	int byteNum = NumBytes(TA->n);
	BYTE* tmp = new BYTE[byteNum];
	BytesFromZZ(tmp, TA->n, byteNum);
	for (int i = byteNum - 1; i >= 0; i--)
		str += tmp[i];

	BytesFromZZ(tmp, TA->b, byteNum);
	for (int i = byteNum - 1; i >= 0; i--)
		str += tmp[i];

	fout << str;
	fout.close();
	delete[] tmp;
}

void readTA(const string file, RSA_Sign*& TA)
{
	ifstream fin(file, ios::binary);               // �Զ����Ʒ�ʽ���ļ�
	if (!fin) {
		cerr << "Can not open the input file!" << endl;   // ���������Ϣ���˳�
		return;
	}

	istreambuf_iterator<char> beg(fin), end;              
	string content(beg, end);   // ���ļ�ȫ������string�ַ���
	fin.close();                                         

	int byteNum = 128;  // byte length of cipher key
	int len = content.length();
	string id = content.substr(0, len - byteNum*2);
	string nStr = content.substr(len - byteNum*2, byteNum);
	string bStr = content.substr(len - byteNum, byteNum);

	TA->setId(id);

	BYTE* tmp = new BYTE[byteNum];
	for (int i = byteNum - 1; i >= 0; i--)
		tmp[i] = nStr[byteNum - i - 1];
	ZZFromBytes(TA->n, tmp, byteNum);

	for (int i = byteNum - 1; i >= 0; i--)
		tmp[i] = bStr[byteNum - i - 1];
	ZZFromBytes(TA->b, tmp, byteNum);

	delete[] tmp;
}

void writeCert(const string file, const string& cert)
{
	ofstream fout(file, ios::binary);                      // ������ļ�
	if (!fout) {
		cerr << "Can not open the output file!" << endl;   // ���������Ϣ���˳�
		return;
	}
	fout << cert;                                          // ֱ�ӽ������õ��ַ����������
	fout.close();
}

void readCert(const string file, string& cert)
{
	ifstream fin(file, ios::binary);                      // �Զ����Ʒ�ʽ���ļ�
	if (!fin){
		cerr << "Can not open the input file!" << endl;   // ���������Ϣ���˳�
		return ;
	}

	istreambuf_iterator<char> beg(fin), end;              // ���������ļ�ָ�룬ָ��ʼ�ͽ�������char(һ�ֽ�)Ϊ����
	string content(beg, end);                             // ���ļ�ȫ������string�ַ���
	fin.close();                                          // �������ļ���ر��ļ������һ����ϰ��
	cert = content;
}

void Cert(RSA_Sign* TA, RSA* Alice, const string& Alice_ID, string& cert)
{
	string AliceInfo = "";
	AliceInfo += Alice_ID;

	int keyLen = Alice->KEYLEN;

	int byteNum = keyLen / 8;

	// ver_alice
	BYTE* tmp = new BYTE[byteNum];
	BytesFromZZ(tmp, Alice->n, byteNum);

	for (int i = byteNum - 1; i >= 0; i--){
		AliceInfo += tmp[i];
	}

	BytesFromZZ(tmp, Alice->b, byteNum);
	for (int i = byteNum - 1; i >= 0; i--) {
		AliceInfo += tmp[i];
	}

	string s = TA->Signature(AliceInfo);
	AliceInfo += s;
	

	// TA_id
	string TA_id;
	TA->getId(TA_id);
	AliceInfo += TA_id;

	// flag
	BYTE flag = 0;
	if (keyLen == 1024)
		flag = 0;
	else if (keyLen == 2048)
		flag = 1;
	AliceInfo += flag;

	cert = AliceInfo;

	delete[] tmp;
}

bool Verify(RSA_Sign* TA, const string& cert)
{
	string TA_id;
	TA->getId(TA_id);
	string cert_TA_id = cert.substr(cert.length() - 1 - TA_id.length(), TA_id.length());
	if (TA_id != cert_TA_id)
		return false;

	string c = cert.substr(0, cert.length() - 1 - TA_id.length());
	
	int sLen = 128;
	string s = c.substr(c.length() - sLen, sLen);
	string in = c.substr(0, c.length() - sLen);

	return TA->Verify(in, s);
}

void setTA(RSA_Sign*& TA)
{
	printf("������TA��ID:\n");
	string TA_ID;
	cin >> TA_ID;
	TA = new RSA_Sign;
	TA->setId(TA_ID);
	printf("��ȡTA�ɹ�! \n");
}

void menu()
{
	printf("--------------------֤�鷽��--------------------\n");
	RSA_Sign* TA = nullptr;
	setTA(TA);

	string Alice_ID;
	int choice;
	string cert;

	while (1) {
		printf("------------------------------------------------\n");
		printf("��������:\n");
		printf("1. ֤��䷢                    2. ֤����֤\n");
		printf("\n");
		printf("������ָ��: ��������������˳���\n");
		cin >> choice;

		if (choice == 1) {
			writeTA("TA.txt", TA);
			printf("������Alice��ID:\n");
			cin >> Alice_ID;
			printf("��ѡ��Alice����Կ����:\n");
			printf("1.1024      2.2048\n");
			int k, keyLen;
			cin >> k;
			keyLen = (k == 2) ? 2048 : 1024;
			RSA* Alice = new RSA(keyLen);
			Cert(TA, Alice, Alice_ID, cert);
			writeCert("cert.txt", cert);
			printf("֤�鷢�ųɹ���\n");
			delete Alice;
		}
		else if (choice == 2) {    // ����һ���ļ�loadTA����Ϣ
			readTA("TA.txt", TA);
			readCert("cert.txt", cert);
			bool ver = Verify(TA, cert);
			printf("��֤��������֤���Ϊ : ");
			if (ver)
				printf("true\n");
			else
				printf("false\n");
		}
		else
			break;
	}

	if(TA!=nullptr)
		delete TA;
}

int main(int argc, char* argv)
{
	menu();

	return 0;
}