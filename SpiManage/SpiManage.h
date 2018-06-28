
// SpiManage.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
typedef struct
{
	CHAR		name[50];
	LONG64		crc32;
}PROCESSNAME;
typedef struct
{
	BOOL		type;//0,1:RANGE
	IN_ADDR		addr;
	IN_ADDR		addrStart;
	IN_ADDR		addrEnd;
}IPRANGE;
typedef struct
{
	DWORD								dLogProcessPID;
	DWORD								dDllCount;
	BYTE								bMainKey[16];
	BYTE								allConnect;
	BYTE								allAccept;
	BYTE								allCloseSocket;
	BYTE								allSend;
	BYTE								allRecv;

	BYTE								rein;
	BYTE								reinConnect;
	BYTE								reinAccept;
	BYTE								reinCloseSocket;
	BYTE								reinSend;
	BYTE								reinRecv;

	USHORT								reinProcessLen;
	PROCESSNAME							reinProcess[250];//������
	USHORT								reinProcessWhiteLen;
	PROCESSNAME							reinProcessWhite[250];//������������

	USHORT								reinPortLen;
	USHORT								reinPort[500];//�˿�
	USHORT								reinPortWhiteLen;
	USHORT								reinPortWhite[500];//�˿ڰ�����

	USHORT								reinLocalIPLen;
	IPRANGE								reinLocalIP[250];//����IP
	USHORT								reinLocalIPWhiteLen;
	IPRANGE								reinLocalIPWhite[250];//����IP������
	USHORT								reinRemoteIPLen;
	IPRANGE								reinRemoteIP[250];//Զ��IP
	USHORT								reinRemoteIPWhiteLen;
	IPRANGE								reinRemoteIPWhite[250];//Զ��IP������
}GLOBVAR, *PGLOBVAR;



// CSpiManageApp: 
// �йش����ʵ�֣������ SpiManage.cpp
//

class CSpiManageApp : public CWinApp
{
public:
	CSpiManageApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CSpiManageApp theApp;