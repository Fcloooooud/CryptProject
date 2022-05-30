#include<fstream>
#include "User.h"


bool User::readFile(const string fileName, string& content)
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

bool User::writeFile(const string fileName, const string content)
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

bool User::ReadCertFromFile(const string fileName, string& content)
{
	if (readFile(fileName, content)) {
		printf("��ȡ֤��ɹ���\n");
		return true;
	}
	else {
		printf("��ȡ֤��ʧ�ܣ�\n");
		return false;
	}
}

bool User::WriteCertToFile(const string fileName)
{
	if (writeFile(fileName, Cert)) {
		printf("����֤��ɹ���\n");
		return true;
	}
	else {
		printf("����֤��ʧ�ܣ�\n");
		return false;
	}
}

void User::ApplyCert(TA* TA)
{
	string info = "";
	info += this->ID;
	int keyLen = this->KEYLEN;
	int byteNum = keyLen / 8;

	// ��Կ
	BYTE* tmp = new BYTE[byteNum];
	BytesFromZZ(tmp, this->n, byteNum);
	for (int i = byteNum - 1; i >= 0; i--)
		info += tmp[i];
	BytesFromZZ(tmp, this->b, byteNum);
	for (int i = byteNum - 1; i >= 0; i--)
		info += tmp[i];

	// s
	string s = TA->Signature(info);
	info += s;

	string TA_id = TA->getId();
	info += TA_id;

	BYTE flag = (keyLen == 2048) ? 1 : 0;
	info += flag;

	this->Cert = info;
}

bool User::VerifyCert(TA* TA, const string& cert)
{
	int s_len = 128, len = cert.length();
	string TA_id = TA->getId();
	string input = cert.substr(0, len - 1 - TA_id.length() - s_len);
	string s = cert.substr(len - 1 - TA_id.length() - s_len, s_len);

	return TA->Verify(input, s);
}

void User::ParseCert(TA* TA, const string& cert, ZZ& r_n, ZZ& r_b)  // ��֤���л�ȡn��b
{
	int s_len = 128, len = cert.length();
	string TA_id = TA->getId();
	int bitNum = (cert[len - 1] == 1) ? 2048 : 1024;  
	int byteNum = bitNum / sizeOfBYTE;
	int endPos = len - 1 - TA_id.length() - s_len;
	string nStr = cert.substr(endPos - byteNum * 2, byteNum);
	string bStr = cert.substr(endPos - byteNum, byteNum);

	BYTE* tmp = new BYTE[byteNum];
	for (int i = byteNum - 1; i >= 0; i--)
		tmp[i] = nStr[byteNum - i - 1];
	ZZFromBytes(r_n, tmp, byteNum);

	for (int i = byteNum - 1; i >= 0; i--)
		tmp[i] = bStr[byteNum - i - 1];
	ZZFromBytes(r_b, tmp, byteNum);

	delete[] tmp;
}




void Sender::GenRandomKey(string& kStr)
{
	// ����128λ���AES��Կ
	// �����дע�Ᵽ��һ��
	ZZ key;
	RandomBits(key, 128);
	int byteNum = 128 / 8;
	BYTE* k = new BYTE[byteNum];
	BytesFromZZ(k, key, byteNum);
	for (int i = 0; i < byteNum; i++) {
		if (k[i] == 0x00)  // �����0x00��Ӱ�����
			k[i] = 0xE3;
	}

	ZZFromBytes(key, k, byteNum);

	this->AES_SetKey(k);
	kStr = "";
	for (int i = 0; i < byteNum; i++)
		kStr += k[i];
	delete[] k;

}

string Sender::RSA_Signature(const string input)
{
	// ������ɢ��ֵ �����
	vector<DWORD> wr = this->SHA_Encrypt(input);
	string tmp = "";
	for (int i = 0; i < wr.size(); i++) {
		tmp += char(wr[i] >> 3 * sizeOfBYTE);
		tmp += char(wr[i] >> 2 * sizeOfBYTE);
		tmp += char(wr[i] >> 1 * sizeOfBYTE);
		tmp += char(wr[i]);
	}
	string sign = this->RSA_EncryptPrivateKey(tmp);
	return sign;
}

bool Sender::FileEncrypt(TA* TA, const string rCertName, const string srcFile, const string dstFile)
{
	// ��Ȼ����������TA����������Կ ����KEY GENERATION����д�ڹ��캯�����ˡ�
	ApplyCert(TA);
	printf("֤�����ɳɹ���\n");

	string rCert = "";
	ReadCertFromFile(rCertName, rCert);

	// check cert of alice
	if (VerifyCert(TA, rCert)) {
		printf("֤����֤ͨ����\n");
	}
	else {
		printf("֤����֤δͨ����\n");
		return false;
	}

	string m;
	readFile(srcFile, m);
	string s = RSA_Signature(m);
	string cert = this->getCert();

	string in1 = m + s + cert;
	string k;
	GenRandomKey(k);

	cout << "kstr = ";
	for (int i = 0; i < k.length(); i++) {
		cout << hex << (int)(k[i] & 0xff) << " ";
	}
	cout << endl;

	string c1 = AES_CBC_Encrypt(in1);

	ZZ r_n, r_b;
	ParseCert(TA, rCert, r_n, r_b);

	string c2 = RSA_Encrypt(k, r_b, r_n);


	string c = c1 + c2;
	writeFile(dstFile, c);
	printf("�ļ����ܽ�����\n");

	return true;
}



void Receiver::ParseFile(const string file, string& c1, string& c2)
{
	// c2����alice����Կ���ܵģ�����ʵ���ϼ��ܺ���ļ����ȵ���alice����Կ(n)����
	int c2BitNum = this->KEYLEN;
	int c2ByteNum = c2BitNum / 8;

	int len = file.length();
	c1 = file.substr(0, len - c2ByteNum);
	c2 = file.substr(len - c2ByteNum, c2ByteNum);

}

bool Receiver::DecryptC2(const string c2)
{
	// ��Կ���� ˽Կ����
	string kStr = RSA_Decrypt(c2);

	if (kStr.length() != 16)
		return false;

	BYTE* key = new BYTE[16];
	for (int i = 0; i < 16; i++)
		key[i] = kStr[i];
	AES_SetKey(key);
	delete[] key;
	return true;
}

// Ӧ����Ҫͨ����λBOB��id������֤��Ŀ�ʼλ��
bool Receiver::DecryptC1(const string c1, const string s_id, string& ms, string& s_cert)
{
	string fullStr = AES_CBC_Decrypt(c1);

	int len = fullStr.length();
	int certPos = fullStr.find(s_id);
	if (certPos == -1)
		return false;

	int certLen = len - certPos;
	int sLen = 128;

	s_cert = fullStr.substr(certPos, certLen);
	ms = fullStr.substr(0, len - certLen);
	return true;
}


bool Receiver::VerifySign(string& fileContent, const string ms, ZZ& s_n, ZZ& s_b)
{
	int sLen = 128;
	int len = ms.length();
	string s = ms.substr(len - sLen, sLen);
	string m = ms.substr(0, len - sLen);

	vector<DWORD> hash = SHA_Encrypt(m);
	string hashStr = "";
	for (int i = 0; i < hash.size(); i++) {
		hashStr = hashStr \
			+ char(hash[i] >> 3 * sizeOfBYTE)\
			+ char(hash[i] >> 2 * sizeOfBYTE)\
			+ char(hash[i] >> 1 * sizeOfBYTE)\
			+ char(hash[i]);
	}

	string de = RSA_Decrypt(s, s_b, s_n);  // ˽Կ����


	if (hashStr == de) {
		fileContent = m;
		return true;
	}
	else {
		fileContent = "";
		return false;
	}

}

bool Receiver::FileDecrypt(TA* TA, const string s_id, const string srcFile, const string dstFile)
{
	string c1, c2;
	string content;
	readFile(srcFile, content);
	ParseFile(content, c1, c2);
	if (DecryptC2(c2)) {
		printf("C2���ܳɹ���\n");
	}
	else {
		printf("C2����ʧ�ܣ�\n");
		return false;
	}

	string ms, s_cert;
	if (DecryptC1(c1, s_id, ms, s_cert))
		printf("C1���ܳɹ���\n");
	else {
		printf("C1����ʧ�ܣ�\n");
		return false;
	}
	
	if (VerifyCert(TA, s_cert)) {
		printf("֤����֤ͨ����\n");
	}
	else {
		printf("֤����֤δͨ����\n");
		return false;
	}

	ZZ s_n, s_b;
	ParseCert(TA, s_cert, s_n, s_b);

	string m;
	if (VerifySign(m, ms, s_n, s_b)) {
		printf("ǩ����֤ͨ����\n");
	}
	else {
		printf("ǩ����֤δͨ����\n");
		return false;
	}

	this->writeFile(dstFile, m);
	return true;
}