
// SpiManage.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号
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
	PROCESSNAME							reinProcess[250];//进程名
	USHORT								reinProcessWhiteLen;
	PROCESSNAME							reinProcessWhite[250];//进程名白名单

	USHORT								reinPortLen;
	USHORT								reinPort[500];//端口
	USHORT								reinPortWhiteLen;
	USHORT								reinPortWhite[500];//端口白名单

	USHORT								reinLocalIPLen;
	IPRANGE								reinLocalIP[250];//本地IP
	USHORT								reinLocalIPWhiteLen;
	IPRANGE								reinLocalIPWhite[250];//本地IP白名单
	USHORT								reinRemoteIPLen;
	IPRANGE								reinRemoteIP[250];//远端IP
	USHORT								reinRemoteIPWhiteLen;
	IPRANGE								reinRemoteIPWhite[250];//远端IP白名单
}GLOBVAR, *PGLOBVAR;



// CSpiManageApp: 
// 有关此类的实现，请参阅 SpiManage.cpp
//

class CSpiManageApp : public CWinApp
{
public:
	CSpiManageApp();

// 重写
public:
	virtual BOOL InitInstance();

// 实现

	DECLARE_MESSAGE_MAP()
};

extern CSpiManageApp theApp;