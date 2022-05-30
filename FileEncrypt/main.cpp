#include<iostream>
#include<fstream>
#include "AES_CBC.h"
#include "RSA.h"
#include "SHA_1.h"
#include "User.h"

using namespace std;


int main()
{
	int kLen = 1024;
	cout << "请选择alice/bob的密钥长度：(1) 1024  (2) 2048" << endl;
	int sel;
	cin >> sel;
	kLen = (sel == 1) ? 1024 : 2048;
	string fileName = "";
	cout << "请输入待加密文件名：" << endl;
	cin >> fileName;
	int pos = fileName.find_last_of('.');
	string sub = fileName.substr(pos, fileName.length() - pos);
	string eFileName = "encrypted.txt";
	string dFileName = "decrypted" + sub;


	TA* ta = new TA("TA");
	Receiver* Alice = new Receiver(kLen, "Alice");
	Sender* Bob = new Sender(kLen, "Bob");

	Alice->ApplyCert(ta);
	Alice->WriteCertToFile("certAlice.txt");

	Bob->FileEncrypt(ta, "certAlice.txt", fileName, eFileName);

	Alice->FileDecrypt(ta, "Bob", eFileName, dFileName);

	system("pause");
	return 0;
}