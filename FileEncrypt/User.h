#pragma once
#include <string>
#include "AES_CBC.h"
#include "RSA.h"
#include "SHA_1.h"

const int sizeOfBYTE = 8; // size of byte
const int sizeOfDWORD = 32;
const int sizeOfBLOCK = 512; //512 bits

class TA : public SHA_1, public RSA {
private:
	string ID;
public:
	TA(string id = "null") : ID(id) {};  // TA��ǩ����Կ����Ĭ��Ϊ1024λ�������Ǹ���
	void setId(const string& id) { ID = id; };
	void getId(string& id) { id = ID; };
	string getId() { return this->ID; };

	string Signature(const string& input) {
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
	};
	bool Verify(const string& input, string sign) {
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
	};
};


class User : public AES_CBC, public SHA_1, public RSA {
private:
	string ID;
	string Cert;

public:
	User(int keylen = 1024, string id = "Anon") : RSA(keylen), ID(id) { setPaddingMode(PKCS7Padding); };
	void setID(string id) { ID = id; };

	bool readFile(const string fileName, string& content);         // ���ļ�
	bool writeFile(const string fileName, const string content);   // д�ļ�
	bool WriteCertToFile(const string fileName);                   // ��֤��д���ļ�
	bool ReadCertFromFile(const string fileName, string& content); // ���ļ��ж�ȡ֤��

	void ApplyCert(TA* TA);							               // ���ɰ����Լ���ID����Կ��֤��
	bool VerifyCert(TA* TA, const string& cert);                   // ��֤�Է���֤��
	void ParseCert(TA* TA, const string& cert, ZZ& r_n, ZZ& r_b);  // ��֤���л�ȡ��Կ
	string getCert() { return Cert; };
};


class Sender : public User {
private:
	void GenRandomKey(string& kStr);
	string RSA_Signature(const string input);
public:
	Sender(int keyLen = 1024, string id = "Anon") : User(keyLen, id) {};  // ���캯��
	bool FileEncrypt(TA* TA, const string rCert, const string srcFile, const string dstFile);
};

class Receiver : public User {
private:
	void ParseFile(const string file, string& c1, string& c2);
	bool DecryptC1(const string c1, const string s_id, string& ms, string& s_cert); 
	bool DecryptC2(const string c2);  // get aes key
public:
	Receiver(int keyLen = 1024, string id = "Anon") : User(keyLen, id) {}; // ���캯��
	bool VerifySign(string& fileContent, const string s_cert, ZZ& s_n, ZZ& s_b); // ʹ��b�Ĺ�Կ����֤�Ƿ�Ϊ��ȷǩ��
	bool FileDecrypt(TA* TA, const string s_id, const string srcFile, const string dstFile);
};
