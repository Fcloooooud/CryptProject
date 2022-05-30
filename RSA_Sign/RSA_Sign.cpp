#include<stdio.h>
#include<iostream>
#include "RSA.h"
#include "SHA_1.h"
using namespace std;

class RSA_Sign : protected RSA, protected SHA_1 {
private:
	string ID;

public:
	RSA_Sign(int keylen = 1024) : RSA(keylen) {};  // 默认密钥长度1024

	void setId(const string& id) { ID = id; };     // 存id
	void getId(string& id) { id = ID; };           // 取id
	
	void printPublicKey();                         // 打印公钥
	string Signature(const string& input);         // 签名
	bool Verify(const string& input, string sign); // 验签
};

void RSA_Sign::printPublicKey()
{
	cout << "RSA加密的公钥为：" << endl;
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
	// 先hash再加密
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
	cout << "请选择密钥长度：(1) 1024  (2) 2048" << endl;
	int sel;
	cin >> sel;
	kLen = (sel == 1) ? 1024 : 2048;

	string str, sign, noise;
	bool ver;
	printf("请输入消息字符串:\n");
	cin >> str;

	RSA_Sign* sgn = new RSA_Sign(kLen);
	sgn->printPublicKey();
	sign = sgn->Signature(str);
	printf("签名结果为:\n");
	for (int i = 0; i < sign.size(); i++)
		cout << hex << ((int)sign[i] & 0xff) ;// << endl;
	cout << endl;
	ver = sgn->Verify(str, sign);
	printf("验证结果为:");
	if (ver)
		printf("true!\n");
	else
		printf("false!\n");
	system("pause");
	return 0;
}