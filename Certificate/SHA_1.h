#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include<Windows.h>
#include<stdio.h>
#include<vector>
#include<string>
#include<iostream>

using namespace std;

typedef unsigned char   BYTE;
typedef unsigned short  DBYTE;
typedef unsigned long   DWORD;

const int sizeOfBYTE = 8; // size of byte
const int sizeOfDWORD = 32;
const int sizeOfBLOCK = 512; //512 bits

class SHA_1 {

	DWORD A, B, C, D, E;
	DWORD H0, H1, H2, H3, H4; //buffer
	DWORD W[80];

	vector<vector<DWORD>> SHA_Pad(string x);

	DWORD Kt(int t);
	DWORD Ft(int t, DWORD B, DWORD C, DWORD D);
	DWORD ROTL(DWORD x, int s);

	void setW(vector<DWORD> m);

public:
	vector< DWORD> SHA_Encrypt(string x);
};