#include<stdio.h>
#include<iostream>
#include "RSA.h"
#include "SHA_1.h"
using namespace std;

class RSA_Sign : protected RSA, protected SHA_1 {
private:
	string ID;

public:
	RSA_Sign(int keylen = 1024) : RSA(keylen) {};  // Ĭ����Կ����1024

	void setId(const string& id) { ID = id; };     // ��id
	void getId(string& id) { id = ID; };           // ȡid
	
	void printPublicKey();                         // ��ӡ��Կ
	string Signature(const string& input);         // ǩ��
	bool Verify(const string& input, string sign); // ��ǩ
};

void RSA_Sign::printPublicKey()
{
	cout << "RSA���ܵĹ�ԿΪ��" << endl;
	cout << hex << "n = " ;
	int byteNum = NumBytes(n);
	unsigned char* tmp = new unsigned char[byteNum];
	BytesFromZZ(tmp, n, byteNum);

	for (int i = byteNum - 1; i >= 0; i--) 
		cout << hex << int(tmp[i] & 0xff);
	cout << endl;

	cout << hex << "b = ";
	BytesFromZZ(tmp, b, byteNum);
	for (int i = byteNum - 1; i >= 0; i--)
		cout << hex << int(tmp[i] & 0xff);
	cout << endl;
}

string RSA_Sign::Signature(const string& input) 
{
	// ��hash�ټ���
	vector<DWORD> wr = this->SHA_Encrypt(input);
	string tmp = "";
	for (int i = 0; i < wr.size(); i++) {
		tmp += char(wr[i] >> 3 * sizeOfBYTE);
		tmp += char(wr[i] >> 2 * sizeOfBYTE);
		tmp += char(wr[i] >> 1 * sizeOfBYTE);
		tmp += char(wr[i]);
	}
	cout << endl;
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

int main()
{
	int kLen = 1024;
	cout << "��ѡ����Կ���ȣ�(1) 1024  (2) 2048" << endl;
	int sel;
	cin >> sel;
	kLen = (sel == 1) ? 1024 : 2048;

	string str, sign, noise;
	bool ver;
	printf("��������Ϣ�ַ���:\n");
	cin >> str;

	RSA_Sign* sgn = new RSA_Sign(kLen);
	sgn->printPublicKey();
	sign = sgn->Signature(str);
	printf("ǩ�����Ϊ:\n");
	for (int i = 0; i < sign.size(); i++)
		cout << hex << ((int)sign[i] & 0xff) ;// << endl;
	cout << endl;
	ver = sgn->Verify(str, sign);
	printf("��֤���Ϊ:");
	if (ver)
		printf("true!\n");
	else
		printf("false!\n");
	system("pause");
	return 0;
}