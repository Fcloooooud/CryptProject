#pragma once
#define _CRT_SECURE_NO_WARNINGS
//#define NOMINMAX

#include<Windows.h>
#include<stdio.h>
#include<vector>
#include<string>
#include<iostream>

using namespace std;

typedef unsigned char   BYTE;
typedef unsigned short  DBYTE;
typedef unsigned long   DWORD;


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