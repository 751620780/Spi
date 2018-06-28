// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <ws2spi.h>
#include <queue>
#include "debug.h"
#include "dllmain.h"
#include "Aes.h"
#include <unordered_map>
#include <Tlhelp32.h>
#pragma comment(lib,"ws2_32.lib")
//#include "detours.h"
//#pragma comment(lib,"detours.lib")

using namespace std;
#define EXTENDDATALENGTH		20	//数据密操作中对数据进行扩展的长度
#define MAX_USEFULL_TIME		30	//每一个session的子密钥的最长持续时间
#define MAX_PACKET_LEN			2048//内存映射的最大分包数量
#define TIME_ERROR				10	//最大时间误差，超过它将认为非法
#define LOG_PAGE_COUNT			400	//log的内存映射页数量
#ifdef  _X86_
#define LOG_PAGE_SIZE			4096//log的一个页的大小
#else
#define LOG_PAGE_SIZE			8192//log的一个页的大小
#endif
#define	LOG_USEABLEBYTE			LOG_PAGE_COUNT * LOG_PAGE_SIZE - (MAX_PACKET_LEN + 3) * 4
/****************************************************************************日志等级宏定义***************************************************************************/
#define LOG_COMMENT				100
#define LOG_NORMAL				200
#define LOG_ALERT				300
#define LOG_ERROR				400

/******************************************************************************TypeDefine***************************************************************************/
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

//标记一个会话的信息，以Socket连接标志唯一标识每一个会话
typedef struct
{
	BYTE								bDirection;//连接方向,-1:未知，0：被外部连接，1：连接外部
	IN_ADDR								ulLocalIP;//本地IP地址
	USHORT								uiLocalPort;//本地端口
	IN_ADDR								ulRemoteIP;//远端IP地址
	USHORT								uiRemotePort;//远端端口
	DWORD								ulSendData;//当前发送数据总大小
	DWORD								ulRecvData;//当前接收数据总大小
	USHORT								uRandom;//建立身份验证时采用的随机数
	USHORT								dDuration;//至上次更新密钥后开始持续的时间
	BOOL								bEc;//是否加密通讯

	BOOL								bIsAlloc;//是否分配缓冲区
	PCHAR								buffer;//组包使用的缓冲区首地址
	DWORD								bufferLen;//组包中有效数据长度
	DWORD								buffOffset;//组包中有效数据的起始地址
	BYTE								key[4 * Nk];//本次会话的临时会话密钥
	DWORD								w[4 * (Nr + 1)];//会话密钥扩展产生的轮密钥，每次更新会话密钥key后都应该主动调用KeyExpansion来更新轮密钥
} SESSION, *PSESSION;

typedef struct
{
	BYTE								bDirection;//连接方向,-1:未知，0：被外部连接，1：连接外部
	IN_ADDR								ulLocalIP;//本地IP地址
	USHORT								uiLocalPort;//本地端口
	IN_ADDR								ulRemoteIP;//远端IP地址
	USHORT								uiRemotePort;//远端端口
	DWORD								ulSendData;//当前发送数据总大小
	DWORD								ulRecvData;//当前接收数据总大小
	USHORT								uRandom;//建立身份验证时采用的随机数
	USHORT								dDuration;//至上次更新密钥后开始持续的时间
	BOOL								bEc;//是否加密通讯
} LOGSESSION;

//将一个已经收发的数据包转发给主控程序时采用的消息包。
//该消息包应在条件允许时将每一个收到或发出的数据包进行分包后转发给主控程序。
typedef struct
{
	DWORD								packetLength;//packet的总大小
	SYSTEMTIME							time;//消息产生的时间
	DWORD								dIndex;//当前进程发送的条数
	DWORD								dkind;//日志等级
	DWORD								dDescriptionBytesLength;//描述信息字符串的字节长度
	LOGSESSION							logSession;//会话信息中log关注的部分
	BYTE								bDirect;//bit0：本次收(发)数据的方向0：接收，1：发出； bit1：0是密文,1是明文
	BYTE								hasLogSession;//是否有Session，为0的话则忽略logSession
	DWORD								iLengthSum;//本次收(发)数据的总长度
	TCHAR								szProcessName[MAX_PATH];//进程名
	DWORD								dCount;//本进程拥有的session总数
}PACKET, *PPACKET;

typedef struct
{
	DWORD								pos;//当前日志总条数
	DWORD								maxPos;//最大条数
	DWORD								useableBytes;//可以被记录Packet的字节数
	DWORD								packet[MAX_PACKET_LEN];//记录每一个packet开始处相对DATA的偏移量大小
	BYTE								data[LOG_USEABLEBYTE];//存储所有的packet的地方
}LOGGER, *PLOGGER;

struct SocketEqual {
public:

	bool operator()(const SOCKET& n1, const SOCKET& n2) const
	{
		return n1 == n2;
	}
};
typedef  std::unordered_map<SOCKET, PSESSION, std::hash<SOCKET>, SocketEqual> SESSION_MAP;

typedef struct
{
	SOCKET					s;//与该overlapped关联的socket
	LPWSABUF				lpBuffersSend;//替换后send使用的缓冲区，重叠结束时会释放
	DWORD					dwBufferCountSend;//缓冲区的数量
	PCOMPLETIONROUTINE		lpCompletionRoutineSend;//应用层提供的回调函数地址的备份
	DWORD					originalSendBytesLen;//应用层提交的原始发送的数据总长度
}OVERLAPPEDSESSIONSEND, *POVERLAPPEDSESSIONSEND;

struct OverlappedSendEqual {
public:
	bool operator()(const LPWSAOVERLAPPED& n1, const LPWSAOVERLAPPED& n2) const
	{
		return n1 == n2;
	}
};
typedef  std::unordered_map<LPWSAOVERLAPPED, POVERLAPPEDSESSIONSEND, std::hash<LPWSAOVERLAPPED>, OverlappedSendEqual> OVERLAPPED_MAPSEND;

typedef struct
{
	SOCKET					s;//与该overlapped关联的socket
	LPWSABUF				lpBuffersRecvBack;//应用层提供的数据缓冲区
	LPWSABUF				lpBuffersRecvTmp;//替换后recv使用的的缓冲区
	DWORD					dwBufferCountRecv;//缓冲区的数量
	PCOMPLETIONROUTINE		lpCompletionRoutineRecv;//应用层提供的回调函数地址的备份
	DWORD					dIsReinforce;//是否被加密传输
}OVERLAPPEDSESSIONRECV, *POVERLAPPEDSESSIONRECV;

struct OverlappedRecvEqual {
public:
	bool operator()(const LPWSAOVERLAPPED& n1, const LPWSAOVERLAPPED& n2) const
	{
		return n1 == n2;
	}
};
typedef  std::unordered_map<LPWSAOVERLAPPED, POVERLAPPEDSESSIONRECV, std::hash<LPWSAOVERLAPPED>, OverlappedRecvEqual> OVERLAPPED_MAPRECV;
/********************************************************************************全局变量****************************************************************************/
DWORD				m_CrcTable[256] = {
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};
SESSION_MAP			m_Session;//会话信息的哈希表
CRITICAL_SECTION	m_csSession;//会话信息哈希表的临街变量

OVERLAPPED_MAPSEND	m_OverlappedSessionSend;//重叠IO信息send的哈希表
CRITICAL_SECTION	m_csOverlappedSessionSend;//重叠IO信息sendd的哈希表的临界区变量
HANDLE				m_hHeapOverlappedSessionSend;//重叠IO信息sendd的哈希表的堆句柄

OVERLAPPED_MAPRECV	m_OverlappedSessionRecv;//重叠IO信息recv的哈希表
CRITICAL_SECTION	m_csOverlappedSessionRecv;//重叠IO信息recv的哈希表的临界区变量
HANDLE				m_hHeapOverlappedSessionRecv;//重叠IO信息recv的哈希表的堆句柄

TCHAR				m_sProcessName[MAX_PATH];//保存调用本dll的进程名
DWORD				m_crc32;//进程名(不含扩展名)的crc32值
TCHAR				m_sProcessFullPath[MAX_PATH];//调用本dll的本进程的完整路径
TCHAR				m_sLogFilePath[MAX_PATH];//日志文件的完整路径
TCHAR				m_sCfgFilePath[MAX_PATH];//配置文件的完整路径
DWORD				m_dwPid = NULL;//调用本dll的进程的PID

BOOL				m_IsFirstStarup = TRUE;//标记本进程第一次调用此dll
WSPPROC_TABLE		m_NextProcTable;//被Hook的dll的全部函数指针
WSPUPCALLTABLE		m_UpCallTable;

DWORD				m_dKeyExpand[44];//主密钥的扩展密钥

GLOBVAR				m_LocalGlobVar;//全局变量的本地副本
CRITICAL_SECTION	m_csLocalGlob;//访问本地的全局变量的关键段
PGLOBVAR			m_pGlobVar = NULL;//全局变量的内存映射指针
HANDLE				m_hGlobVarMutex = NULL;//访问全局变量内存映射的互斥锁
HANDLE				m_hGlobVarSemap = NULL;//所有进程全局变量的内存映射的信号量
HANDLE				m_hGlobThread = NULL;//全局变量的更新线程

//日志记录分为记录线程和写入文件线程
queue<PPACKET>		m_PacketQueue;//分包将数据包给主控界面使用的队列
CRITICAL_SECTION	m_csPacketQueue;//访问m_PacketQueue队列的关键段
HANDLE				m_hHeapPacketQueue;//分包将数据包给主控界面使用的队列的堆句柄
PLOGGER				m_pLogVar = NULL;//日志的内存映射文件的指针
HANDLE				m_hLogThread = NULL;//日志的更新线程
HANDLE				m_hLogRecordThread = NULL;//将日志写入到文件的线程句柄
HANDLE				m_hlogRecordMutex = NULL;//让日志写入到文件的线程工作的互斥锁
HANDLE				m_hLogMutex = NULL;//访问日志的内存映射的内存的互斥锁，进程间共享
HANDLE				m_hLogSemapLocal = NULL;//本进程内使用的让日志记录线程工作的信号量
HANDLE				m_hLogSemapShared = NULL;//向日志写入到文件的进程发送工作的信号量，进程间共享
DWORD				m_dLogCount = 0;//本进程当前记录日志的总条数

HANDLE				m_hTimerThread = NULL;//时间同步线程句柄
HANDLE				m_htTimer = NULL;//线程同步定时器句柄

LONG				m_isThreadRun = TRUE;//所有的线程是否继续运行
CRITICAL_SECTION	m_csThreadRun;//m_isThreadRun变量的关键段

/**************************************************************************************************************************************************************************/
void ReadCfg()
{
	if (_waccess(m_sCfgFilePath, 0) != -1)
	{
		FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"rb");
		if (pCfgFile != NULL)
		{
			if (fread(m_pGlobVar, sizeof(GLOBVAR), 1, pCfgFile) == 1)
			{
				fclose(pCfgFile);
			}
			else
			{
				fclose(pCfgFile);
				goto A;
			}

		}
	}
	else
	{
	A:
		FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"wb");
		char KeyDefault[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
		memcpy(m_pGlobVar->bMainKey, KeyDefault, 16);
		fwrite(m_pGlobVar, sizeof(GLOBVAR), 1, pCfgFile);
		fclose(pCfgFile);
	}
}

void SaveCfg()
{
	FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"wb");
	fwrite(m_pGlobVar, sizeof(GLOBVAR), 1, pCfgFile);
	fclose(pCfgFile);
}

DWORD crc32(BYTE *buffer, DWORD size)
{
	DWORD crc = 0;
	for (DWORD i = 0; i < size; i++)
	{
		crc = m_CrcTable[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	return crc;
}

BOOL WINAPI DllMain(
	HINSTANCE	hModule,
	DWORD ul_reason_for_call,
	LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)//dll被加载
	{
		TCHAR sProcessName[MAX_PATH];
		TCHAR sExtension[50];
		TCHAR drive[10];
		TCHAR dir[MAX_PATH];

		GetModuleFileNameW(NULL, m_sProcessFullPath, MAX_PATH);//获得加载本dll的应用程序完整路径
		m_dwPid = GetCurrentProcessId();
		_wsplitpath(m_sProcessFullPath, NULL, NULL, sProcessName, sExtension);
		_swprintf(m_sProcessName, _T("%s%s"), sProcessName, sExtension);
		m_crc32 = crc32((BYTE*)m_sProcessName, lstrlenW(m_sProcessName));

		GetModuleFileNameW(hModule, m_sLogFilePath, MAX_PATH);
		_wsplitpath(m_sLogFilePath, drive, dir, NULL, NULL);
		_swprintf(m_sLogFilePath, L"%s%s%s", drive, dir, L"log.log");
		_swprintf(m_sCfgFilePath, L"%s%s%s", drive, dir, L"cfg.cfg");

		InitializeCriticalSection(&m_csPacketQueue);//初始化关键段
		InitializeCriticalSection(&m_csSession);
		InitializeCriticalSection(&m_csOverlappedSessionSend);
		InitializeCriticalSection(&m_csOverlappedSessionRecv);
		InitializeCriticalSection(&m_csThreadRun);
		InitializeCriticalSection(&m_csLocalGlob);
		//全局变量的初始化操作
		m_hGlobVarMutex = CreateMutexW(NULL, FALSE, L"SpiMutexGlobVar");
		if (m_hGlobVarMutex == NULL)
		{
			DS2D1(m_sProcessName, L"CreateMutexW SpiMutexGlobVar ERROR CODE:", GetLastError());
		}
		HANDLE hMapFileGlob = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(GLOBVAR), L"SpiSharedMemaryGlobVar");
		if (hMapFileGlob == NULL)
		{
			DS2D1(m_sProcessName, L"CreateFileMappingW SpiSharedMemaryGlobVar ERROR CODE:", GetLastError());
		}
		m_pGlobVar = (PGLOBVAR)MapViewOfFile(hMapFileGlob, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GLOBVAR));
		if (m_pGlobVar == NULL)
		{
			DS2D1(m_sProcessName, L"MapViewOfFile ERROR CODE:", GetLastError());
		}
		m_hGlobVarSemap = CreateSemaphoreW(NULL, 0, 0x7fffffff, L"SpiGlobSemap");
		if (m_hGlobVarSemap == NULL)
		{
			DS2D1(m_sProcessName, L"CreateSemaphoreW SpiGlobSemap ERROR CODE:", GetLastError());
		}
		if (m_hGlobThread == NULL)
		{
			m_hGlobThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GlobThreadProc, NULL, 0, NULL);
		}
		if (NULL == m_hGlobThread)
		{
			DS2(m_sProcessName, _T("DllMain:生成子线程m_hGlobThread失败..."));
		}
		//日志初始化
		m_hLogSemapShared = CreateSemaphoreW(NULL, 0, 0x7fffffff, L"SpiSemmapLog");
		if (m_hLogSemapShared == NULL)
		{
			DS2D1(m_sProcessName, L"CreateSemaphoreW SpiSemmapLog ERROR CODE:", GetLastError());
		}
		m_hLogSemapLocal = CreateSemaphoreW(NULL, 0, 0x7fffffff, NULL);
		if (m_hLogSemapLocal == NULL)
		{
			DS2D1(m_sProcessName, L"CreateSemaphoreW NULL ERROR CODE:", GetLastError());
		}
		m_hLogMutex = CreateMutexW(NULL, FALSE, L"SpiMutexLog");
		if (m_hLogMutex == NULL)
		{
			DS2D1(m_sProcessName, L"CreateMutexW SpiMutexLog ERROR CODE:", GetLastError());
		}
		HANDLE hMapFileLog = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(LOGGER), L"SpiSharedMemaryLog");
		if (hMapFileLog == NULL)
		{
			DS2D1(m_sProcessName, L"CreateFileMappingW SpiSharedMemaryLog ERROR CODE:", GetLastError());
		}
		m_pLogVar = (PLOGGER)MapViewOfFile(hMapFileLog, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(LOGGER));
		if (m_pLogVar == NULL)
		{
			DS2D1(m_sProcessName, L"MapViewOfFile m_pLogVar ERROR CODE:", GetLastError());
		}
		WaitForSingleObject(m_hGlobVarMutex, INFINITE);
		{

			if (m_pGlobVar->dDllCount == 0)
			{
				WaitForSingleObject(m_hLogMutex, INFINITE);
				{
					//memset(m_pLogVar, 0, sizeof(LOGGER));
					m_pLogVar->maxPos = MAX_PACKET_LEN;
					m_pLogVar->useableBytes = LOG_USEABLEBYTE;
				}
				ReleaseMutex(m_hLogMutex);
				ReadCfg();
			}
			m_pGlobVar->dDllCount++;
			//必须更新一下全局变量到是私有内存中
			//EnterCriticalSection(&m_csLocalGlob);
			{
				memcpy(&m_LocalGlobVar, m_pGlobVar, sizeof(GLOBVAR));
				KeyExpansion(m_LocalGlobVar.bMainKey, m_dKeyExpand);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		ReleaseMutex(m_hGlobVarMutex);
		m_hlogRecordMutex = CreateMutexW(NULL, FALSE, L"SpiMutexLogRecord");
		if (m_hlogRecordMutex == NULL)
		{
			DS2D1(m_sProcessName, L"CreateMutexW SpiMutexLogRecord ERROR CODE:", GetLastError());
		}
		if (NULL == m_hLogThread)
			m_hLogThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LogThreadProc, NULL, 0, NULL);
		if (NULL == m_hLogThread)
		{
			DS2(m_sProcessName, _T("DllMain:生成子线程m_hLogThread失败..."));
		}
		if (NULL == m_hLogRecordThread)
			m_hLogRecordThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LogRecordThreadProc, NULL, 0, NULL);
		if (NULL == m_hLogRecordThread)
		{
			DS2(m_sProcessName, _T("DllMain:生成子线程m_hLogRecordThread失败..."));
		}

		//创建同步用的定时器
		m_htTimer = CreateWaitableTimerW(NULL, FALSE, NULL);
		if (m_htTimer == NULL)
		{
			DS2D1(m_sProcessName, L"CreateWaitableTimerW ERROR CODE:", GetLastError());
		}
		LARGE_INTEGER lt;
		lt.HighPart = 0;
		lt.LowPart = 0;
		SetWaitableTimer(m_htTimer, &lt, 1000, NULL, NULL, TRUE);//开启定时器
		if (m_hTimerThread == NULL)
			m_hTimerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerThreadProc, NULL, 0, NULL);
		if (NULL == m_hTimerThread)
		{
			DS2(m_sProcessName, _T("DllMain:生成子线程TimerThreadProc失败..."));
		}
		m_hHeapPacketQueue = HeapCreate(0, 0, 0);
		m_hHeapOverlappedSessionSend = HeapCreate(0, 0, 0);
		m_hHeapOverlappedSessionRecv = HeapCreate(0, 0, 0);
		DS2(m_sProcessName, _T("DllMain:主程序加载执行完毕！"));
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)//dll被卸载
	{

		//在这里保证所有线程都能正确的退出
		EnterCriticalSection(&m_csThreadRun);
		{
			m_isThreadRun = FALSE;
		}
		LeaveCriticalSection(&m_csThreadRun);
		WaitForSingleObject(m_hGlobVarMutex, INFINITE);
		{
			ReleaseSemaphore(m_hGlobVarSemap, m_pGlobVar->dDllCount * 2, NULL);
			m_pGlobVar->dDllCount--;
			if (m_pGlobVar->dDllCount == 0)
				SaveCfg();
		}
		ReleaseMutex(m_hGlobVarMutex);

		ReleaseSemaphore(m_hLogSemapLocal, 1, NULL);
		ReleaseSemaphore(m_hLogSemapShared, 1, NULL);
		HANDLE handles[4];
		handles[0] = m_hGlobThread;
		handles[1] = m_hLogThread;
		handles[2] = m_hTimerThread;
		handles[3] = m_hLogRecordThread;
		WaitForMultipleObjects(4, handles, TRUE, 400);
		//清理堆
		HeapDestroy(m_hHeapOverlappedSessionSend);
		HeapDestroy(m_hHeapOverlappedSessionRecv);
		HeapDestroy(m_hHeapPacketQueue);
		DS2(m_sProcessName, _T("DllMain:卸载完毕！"));
	}
	return TRUE;
}

int WSPAPI WSPStartup(
	WORD					wVersionRequested,
	LPWSPDATA				lpWSPData,
	LPWSAPROTOCOL_INFOW		lpProtocolInfo,
	WSPUPCALLTABLE			upcallTable,
	LPWSPPROC_TABLE			lpProcTable
)
{
	DS2(m_sProcessName, _T("WSPStartup：开始执行..."));
	if (!m_IsFirstStarup)//不是第一次启动，无需再hook
	{
		DS2(m_sProcessName, _T("WSPStartup：不是第一次启动！！！"));
		upcallTable = m_UpCallTable;
		memcpy(lpProcTable, &m_NextProcTable, sizeof(WSPPROC_TABLE));
		return 0;
	}
	TCHAR				sLibraryPath[512];
	LPWSPSTARTUP        WSPStartupFunc = NULL;//保存原先的SPI服务的StartUp函数地址
	HMODULE				hLibraryHandle = NULL;//保存备份的spi的dll文件的路径
	INT                 ErrorCode = 0;
	if (!GetHookProviderDllPath(lpProtocolInfo, sLibraryPath) || (hLibraryHandle = LoadLibrary(sLibraryPath)) == NULL || (WSPStartupFunc = (LPWSPSTARTUP)GetProcAddress(hLibraryHandle, "WSPStartup")) == NULL)
	{
		DS2(m_sProcessName, _T("WSPStartup：执行失败！"));
		return WSAEPROVIDERFAILEDINIT;
	}
	//执行被Hook的dll的StartUp
	if ((ErrorCode = WSPStartupFunc(wVersionRequested, lpWSPData, lpProtocolInfo, upcallTable, lpProcTable)) != ERROR_SUCCESS)
		return ErrorCode;
	//如果这些函数指针都被正确的加载，我们才可以开始Hook
	m_UpCallTable = upcallTable;
	m_NextProcTable = *lpProcTable;
	//进行Hook，只hook关心的函数，注意我们Hook的函数里面必须调用原始的函数。
	lpProcTable->lpWSPCloseSocket = WSPCloseSocket;
	lpProcTable->lpWSPConnect = WSPConnect;
	lpProcTable->lpWSPAccept = WSPAccept;
	lpProcTable->lpWSPSend = WSPSend;
	lpProcTable->lpWSPSendTo = WSPSendTo;
	lpProcTable->lpWSPRecv = WSPRecv;
	lpProcTable->lpWSPRecvFrom = WSPRecvFrom;
	lpProcTable->lpWSPGetOverlappedResult = WSPGetOverlappedResult;
	lpProcTable->lpWSPCleanup = WSPCleanup;
	m_IsFirstStarup = FALSE;
	DS2(m_sProcessName, _T("WSPStartup：执行成功..."));
	return 0;
}

void Debug(
	const char *format,
	...
)
{
	va_list vl;
	FILE *pf = NULL;
	char szLog[512] = { 0, };

	va_start(vl, format);
	wsprintfA(szLog, format, vl);
	va_end(vl);

	OutputDebugStringA(szLog);
}

//将ansi字符转化为Unicode字符
//lpChar			ansi字符串的起始地址
//lpTchar			转换后保存unicode字符的起始地址
//lengthTchar	保存unicode字符的最大长度
bool Char8ToUnicode16(
	char *lpChar,
	TCHAR *lpTchar,
	DWORD lengthTchar
)
{
	DWORD dLength = MultiByteToWideChar(CP_ACP, 0, lpChar, strlen(lpChar) + 1, NULL, 0);
	if (dLength >= lengthTchar)
		return false;
	MultiByteToWideChar(CP_ACP, 0, lpChar, strlen(lpChar) + 1, lpTchar, dLength);
	return true;
}

//将Unicode字符转化为ansi字符
//lpTchar		unicode字符串的起始地址
//lpAnsi		转换后保存ansi字符的起始地址
//lengthChar	保存ansi字符的最大长度
bool Unicode16ToChar8(
	TCHAR *lpTcharStr,
	char *lpAnsiStr,
	DWORD lengthChar
)
{
	DWORD dLength = WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, NULL, 0, NULL, NULL);
	if (dLength >= lengthChar)
		return false;
	if (WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, lpAnsiStr, dLength, NULL, NULL) == dLength)
		return true;
	return false;
}

//全局变量更新线程，几乎处于挂起状态
DWORD WINAPI GlobThreadProc(
	LPVOID lpParam
)
{
	DS2(m_sProcessName, _T("GlobThreadProc->:子线程成功的运行..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("GlobThreadProc->:停止！"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_hGlobVarSemap, INFINITE);//每次设置进程设置时才会执行下去

		WaitForSingleObject(m_hGlobVarMutex, INFINITE);
		{
			//EnterCriticalSection(&m_csLocalGlob);
			{
				memcpy(&m_LocalGlobVar, m_pGlobVar, sizeof(GLOBVAR));
				KeyExpansion(m_LocalGlobVar.bMainKey, m_dKeyExpand);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		ReleaseMutex(m_hGlobVarMutex);
		Sleep(20);
	}
	return 0;
}


//发送日志的线程，不定时会运行
DWORD WINAPI LogThreadProc(
	LPVOID lpParam
)
{
	PPACKET pPacket = NULL;
	DWORD offset = 0;
	//printf("LogThreadProc->:子线程成功的运行...");
	DS2(m_sProcessName, _T("LogThreadProc->:子线程成功的运行..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				//printf("LogThreadProc->:停止！");
				DS2(m_sProcessName, _T("LogThreadProc->:停止！"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_hLogSemapLocal, INFINITE);//存在信号量发出/无信号时才会执行下去

		WaitForSingleObject(m_hLogMutex, INFINITE);
		{
			EnterCriticalSection(&m_csPacketQueue);
			{
				while (!m_PacketQueue.empty())
				{
					pPacket = m_PacketQueue.front();
					if (m_pLogVar->pos < m_pLogVar->maxPos&& pPacket->packetLength < m_pLogVar->useableBytes)
					{
						if (m_pLogVar->pos == 0)
						{
							memcpy(m_pLogVar->data, pPacket, pPacket->packetLength);
							m_pLogVar->packet[m_pLogVar->pos] = 0;
						}
						else
						{
							// 写入起点偏移量为:	offset = 上一个记录的起始点 + 上一个记录的长度
							offset = m_pLogVar->packet[m_pLogVar->pos - 1] + ((PPACKET)(m_pLogVar->data + m_pLogVar->packet[m_pLogVar->pos - 1]))->packetLength;
							memcpy(m_pLogVar->data + offset, pPacket, pPacket->packetLength);
							m_pLogVar->packet[m_pLogVar->pos] = offset;
						}
						m_pLogVar->useableBytes -= pPacket->packetLength;
						m_pLogVar->pos++;
					}
					else
						break;
					m_PacketQueue.pop();
					HeapFree(m_hHeapPacketQueue, 0, pPacket);
					pPacket = NULL;
				}
			}
			LeaveCriticalSection(&m_csPacketQueue);
		}
		ReleaseMutex(m_hLogMutex);

		ReleaseSemaphore(m_hLogSemapShared, 1, NULL);
		Sleep(20);
	}
	return 0;
}

//记录日志到文件的线程，当收到记录信号时会继续执行
DWORD WINAPI LogRecordThreadProc(
	LPVOID lpParam
)
{
	//printf("LogRecordThreadProc->:子线程成功的运行...");
	DS2(m_sProcessName, _T("LogRecordThreadProc->:子线程成功的运行..."));
	PPACKET p = NULL;
	TCHAR strFormat[800];
	TCHAR Remote[30];
	TCHAR Local[30];
	TCHAR hex[6];
	FILE* plogFile = NULL;
	WaitForSingleObject(m_hlogRecordMutex, INFINITE);//只有等待成功的才能拥有记录日志的能力
	//printf("获得记录日志权限！");
	DS2(m_sProcessName, L"获得记录日志权限！");

	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("LogRecordThreadProc->:停止！"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);
		plogFile = _wfopen(m_sLogFilePath, L"a+,ccs=UTF-8");
		if (plogFile == NULL)
		{
			DS2D1(m_sProcessName, L"fopen ERROR CODE:", GetLastError());
			return -1;
		}
		WaitForSingleObject(m_hLogSemapShared, INFINITE);//等待所有进程发送些日志到文件的信号

		WaitForSingleObject(m_hLogMutex, INFINITE);//独占这块内存
		{
			for (int i = 0; i < m_pLogVar->pos; i++)
			{
				p = (PPACKET)(m_pLogVar->data + m_pLogVar->packet[i]);
				Char8ToUnicode16(inet_ntoa(p->logSession.ulLocalIP), Local, 30);
				Char8ToUnicode16(inet_ntoa(p->logSession.ulRemoteIP), Remote, 30);
				if (p->hasLogSession == TRUE)
				{
					fwprintf(plogFile,
						L"%04d-%02d-%02d Week%d %02d:%02d:%02d-%04d "
						L"%2sdump:(size=%-5d) "
						L"Kind:%d Local:%15s-%-5u Remote:%15s-%-5u "
						L"send bytes:%-5d recv bytes:%-5d "
						L"Token:%-5d Duration:%-6ds "
						L"Index:%-4d Rank:%04d:%s"
						, p->time.wYear, p->time.wMonth, p->time.wDay, p->time.wDayOfWeek, p->time.wHour, p->time.wMinute, p->time.wSecond, p->time.wMilliseconds
						,(((p->bDirect & 0x02) == 1) ? L"明文" : L"密文"), p->iLengthSum
						, p->logSession.bDirection, Local, ntohs(p->logSession.uiLocalPort), Remote, ntohs(p->logSession.uiRemotePort)
						, p->logSession.ulSendData, p->logSession.ulRecvData
						, p->logSession.uRandom, p->logSession.dDuration
						, p->dIndex, p->dkind, p->szProcessName
					);
				}
				else
				{
					fwprintf(plogFile,
						L"%04d-%02d-%02d Week%d %02d:%02d:%02d-%04d "
						L"%2sdump:(size=%-5d) "
						L"Index:%-4d Rank:%04d:%s"
						, p->time.wYear, p->time.wMonth, p->time.wDay, p->time.wDayOfWeek, p->time.wHour, p->time.wMinute, p->time.wSecond, p->time.wMilliseconds
						, (((p->bDirect & 0x02) == 1) ? L"明文" : L"密文"), p->iLengthSum
						, p->dIndex, p->dkind, p->szProcessName
					);
				}
				if (p->dDescriptionBytesLength == 0)
				{
					fwprintf(plogFile, L"\tDescription:\n");
				}
				else
				{
					fwprintf(plogFile, L"\tDescription:");
					Char8ToUnicode16((char*)p + sizeof(PACKET), strFormat, 800);
					wcscat(strFormat, L"\n");
					fwprintf(plogFile, strFormat);
				}
				//dump memory
				
				if (p->iLengthSum == 0)
				{
					continue;
				}
				DWORD count = p->iLengthSum / 32;
				DWORD offset = p->dDescriptionBytesLength + sizeof(PACKET);
				BYTE *c = (BYTE*)p + offset;
				for (DWORD i = 0; i < count; i++)
				{
					int k = i << 5;
					fwprintf(plogFile, L"\t\t%08x\t%02x %02x %02x %02x %02x %02x %02x %02x   %02x %02x %02x %02x %02x %02x %02x %02x "
						L"  %02x %02x %02x %02x %02x %02x %02x %02x   %02x %02x %02x %02x %02x %02x %02x %02x \n"
						, k
						, c[0 + k], c[1 + k], c[2 + k], c[3 + k], c[4 + k], c[5 + k], c[6 + k], c[7 + k], c[8 + k], c[9 + k], c[10 + k], c[11 + k], c[12 + k], c[13 + k], c[14 + k], c[15 + k]
						, c[16 + k], c[17 + k], c[18 + k], c[19 + k], c[20 + k], c[21 + k], c[22 + k], c[23 + k], c[24 + k], c[25 + k], c[26 + k], c[27 + k], c[28 + k], c[29 + k], c[30 + k], c[31 + k]
					);
				}
				if (p->iLengthSum % 32 > 0)
				{
					count = count << 5;
					swprintf(strFormat, L"\t\t%08x\t", count);
					for (int i = 0; i < p->iLengthSum % 32; i++)
					{
						if (i != 0 && i % 8 == 0)
							_swprintf(hex, L"  %02x ", c[count + i]);
						else
							_swprintf(hex, L"%02x ", c[count + i]);
						wcscat(strFormat, hex);
					}
					wcscat(strFormat, L"\n");
					fwprintf(plogFile, strFormat);
				}
			}
			m_pLogVar->pos = 0;
			m_pLogVar->useableBytes = LOG_PAGE_COUNT * LOG_PAGE_SIZE - (MAX_PACKET_LEN + 3) * 4;
			fflush(plogFile);
			fclose(plogFile);
		}
		ReleaseMutex(m_hLogMutex);
	}
	return 0;
}

//将日志添加到缓存中，并通知线程取出缓存。
//kind				日志类型		
//descript			描述
//session			会话的首地址，为NULL则忽略
//direct			方向，0接收，1发出
//plaintext			是否是明文
//buffer			数据的首地址，如果为NULL则不复制
//bufferLength		buffer中数据的长度,buffer为NULL，本参数自动忽略
//注意
//	本函数不使用m_csSession关键段
BOOL AddLogMsg(
	DWORD				kind,
	char				*descript,
	PSESSION			session,
	int					direct,
	BOOL				plaintext,
	char				*buffer,
	int					bufferLength
)
{
	DWORD descriptLen = 0;
	if (buffer == NULL)
		bufferLength = 0;
	if (descript != NULL)
		descriptLen = strlen(descript) + 1;
	DWORD count = sizeof(PACKET) + descriptLen + bufferLength;
	BYTE bDirext = 0;
	bDirext = direct&(plaintext << 1);
	PPACKET p = (PPACKET)HeapAlloc(m_hHeapPacketQueue, HEAP_ZERO_MEMORY, count);
	memcpy(p->szProcessName, m_sProcessName, MAX_PATH);
	p->bDirect = bDirext;
	GetLocalTime(&p->time);
	p->dIndex = ++m_dLogCount;
	p->dkind = kind;
	if (session != NULL)
	{
		memcpy(&p->logSession, session, sizeof(LOGSESSION));
		p->hasLogSession = TRUE;
	}
	p->dDescriptionBytesLength = descriptLen;
	if (descript != NULL)
		memcpy((char*)p + sizeof(PACKET), descript, descriptLen);
	p->iLengthSum = bufferLength;
	if (buffer != NULL)
		memcpy((char*)p + sizeof(PACKET) + descriptLen, buffer, bufferLength);
	p->packetLength = count;
	p->dCount = m_Session.size();
	//可以先获得map访问权后，判断可以否再。直接写入
	//如果不可以再加入队列
	EnterCriticalSection(&m_csPacketQueue);
	{
		m_PacketQueue.push(p);
	}
	LeaveCriticalSection(&m_csPacketQueue);

	ReleaseSemaphore(m_hLogSemapLocal, 1, NULL);
	return 1;
}


//同步时间线程，定时运行
DWORD WINAPI TimerThreadProc(
	LPVOID lpParam
)
{
	DS2(m_sProcessName, _T("TimerThreadProc->:子线程成功的运行..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("TimerThreadProc->:停止！"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_htTimer, INFINITE);//每当定时器触发时才会往下执行

		EnterCriticalSection(&m_csSession);
		{
			SESSION_MAP::iterator it = m_Session.begin();
			while (it != m_Session.end())
			{
				if (it->second->bEc != 0)
					it->second->dDuration++;
				it++;
			}
		}
		LeaveCriticalSection(&m_csSession);

		Sleep(20);
	}
	return 0;
}



//获得系统默认的spi服务提供者的dll路径
//由于在安装时替换了系统提供的默认的spi服务者的路径，并进行了备份。那么这里就获取备份的原始spi的dll路径
bool GetHookProviderDllPath(
	WSAPROTOCOL_INFOW *pProtocolInfo,
	TCHAR *sPathName
)
{
	HKEY	hKey = NULL;
	HKEY	hSubkey = NULL;
	DWORD	 index = 0;
	TCHAR	szSubkey[MAX_PATH];
	BYTE	ItemValue[sizeof(WSAPROTOCOL_INFOW) + MAX_PATH];
	DWORD	ItemSize = sizeof(WSAPROTOCOL_INFOW) + MAX_PATH;
	WSAPROTOCOL_INFOW *mProtocolInfo = NULL;
	TCHAR szTmp[MAX_PATH];
	//遍历备份的注册表，进行寻找
	//1.打开指定的注册表项，键不分大小写
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp"), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return false;
	//2.枚举指定的打开注册表项的子项。该函数每次调用时都会检索一个子项的名称
	while (RegEnumKey(hKey, index++, szSubkey, MAX_PATH) == ERROR_SUCCESS)
	{
		//3.打开子项
		if (RegOpenKeyEx(hKey, szSubkey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
			continue;
		//4.查询指定的键的值
		if (RegQueryValueEx(hSubkey, _T("PackedCatalogItem"), 0, NULL, ItemValue, &ItemSize) || !Char8ToUnicode16((char *)ItemValue, szTmp, MAX_PATH) || ExpandEnvironmentStrings(szTmp, sPathName, MAX_PATH) == 0)
			continue;
		mProtocolInfo = (WSAPROTOCOL_INFOW*)(ItemValue + MAX_PATH);
		//5.判断满足条件的
		if (pProtocolInfo->dwCatalogEntryId == mProtocolInfo->dwCatalogEntryId)
		{
			RegCloseKey(hSubkey);
			RegCloseKey(hKey);
			return true;
		}
		RegCloseKey(hSubkey);
		hSubkey = NULL;
	}
	RegCloseKey(hKey);
	DS2(m_sProcessName, _T("GetHookProviderDllPath：获得path失败！！！！"));
	return false;
}


//TCP的服务器每接收一个连接时调用该函数
//根据参数lpfnCondition指定的条件函数的返回值有条件的接受一个Socket连接,接收外部的连接，本地是服务器
//条件函数首先随意创建一个Socket，然后将socket加入socket组中并将它与请求者建立连接
//如果没有错误，返回接受的socket标志，否则返回INVALID_SOCKET,具体错误保存在参数lpErrno中
//注意：
//	TCP的服务器每接受一个连接时调用，而连接双方的信息保存在news中
SOCKET WSPAPI WSPAccept(
	_In_    SOCKET          s,
	_Out_   struct sockaddr *addr,
	_Inout_ LPINT           addrlen,
	_In_    LPCONDITIONPROC lpfnCondition,
	_In_    DWORD           dwCallbackData,
	_Out_   LPINT           lpErrno
)
{
	SOCKET newSocket = m_NextProcTable.lpWSPAccept(s, addr, addrlen, lpfnCondition, dwCallbackData, lpErrno);
	SessionTcp(newSocket, addr, 0);
	return newSocket;
}

//TCP的客户端连接服务器时一定会调用的函数,UDP的客户端可能会调用
//建立两个同等Socket之间的连接，然后交换连接数据，并根据所提供的流规格确定所需的服务质量
//操作成功返回0，否则返回SOCKET_ERROR,具体的错误代码保存在参数lpErrno中
//注意：
//	TCP的客户端连接服务器时一定会调用的函数,UDP的客户端可能会调用(客户端编写者犯懵的时候)
int WSPAPI WSPConnect(
	_In_  SOCKET                s,
	_In_  const struct sockaddr *name,
	_In_  int                   namelen,
	_In_  LPWSABUF              lpCallerData,
	_Out_ LPWSABUF              lpCalleeData,
	_In_  LPQOS                 lpSQOS,
	_In_  LPQOS                 lpGQOS,
	_Out_ LPINT                 lpErrno
)
{

	int ret = m_NextProcTable.lpWSPConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS, lpErrno);
	SessionTcp(s, name, 1);
	return ret;
}

//关闭一个Socket连接
//操作成功返回0，否则返回SOCKET_ERROR,具体的错误代码保存在参数lpErrno中
//注意：
//	无论是udp还是TCP，都可能会调用次函数，来关闭socket
int WSPAPI WSPCloseSocket(
	_In_  SOCKET s,
	_Out_ LPINT  lpErrno
)
{
	int ret = m_NextProcTable.lpWSPCloseSocket(s, lpErrno);
	EnterCriticalSection(&m_csSession);
	{
		if (m_Session.find(s) != m_Session.end())
		{
			if (m_Session[s]->bIsAlloc != 0)
				VirtualFree(m_Session[s]->buffer, 8 * LOG_PAGE_SIZE, MEM_RELEASE);
			//EnterCriticalSection(&m_csLocalGlob);
			{
				if ((m_Session[s]->bEc != 0 && m_LocalGlobVar.reinCloseSocket != 0) || (m_Session[s]->bEc == 0 && m_LocalGlobVar.allCloseSocket != 0))
					AddLogMsg(LOG_NORMAL, "CloseSocket session finished", m_Session[s], 0, 0, 0, 0);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
			free(m_Session[s]);
			m_Session.erase(s);
			DS2D1(m_sProcessName, _T("WSPCloseSocket:断开一个Socket，总共:"), (m_Session.size()));
		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}

//逆序一个DWORD
DWORD SwapDWORD(DWORD t)
{
	return t << 24 | ((t & 0x0000ff00) << 8) | ((t & 0x00ff0000) >> 8) | ((t & 0xff000000) >> 24);
}


//判断一个Socket是否是在加固的范围内
//是则返回1，否返回0
int WhetherToReinforce(
	PSESSION se
)
{
	DWORD k;
	USHORT r = ntohs(se->uiRemotePort), l = ntohs(se->uiLocalPort);
	//EnterCriticalSection(&m_csLocalGlob);
	{
		if (m_LocalGlobVar.rein == 0)
			return 0;
		for (DWORD i = 0; i < m_LocalGlobVar.reinProcessWhiteLen; i++)//进程名白名单
		{
			if (m_crc32 == m_LocalGlobVar.reinProcessWhite[i].crc32)
				return 0;
		}
		for (DWORD i = 0; i < m_LocalGlobVar.reinPortWhiteLen; i++)//本地端口白名单
		{
			if (r == m_LocalGlobVar.reinPortWhite[i] || l == m_LocalGlobVar.reinPortWhite[i])
				return 0;
		}
		k = SwapDWORD(*(DWORD*)&(se->ulLocalIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinLocalIPWhiteLen; i++)//本地ip白名单
		{
			if (m_LocalGlobVar.reinLocalIPWhite[i].type == 0)
			{
				if (k == *(DWORD*)&(m_LocalGlobVar.reinLocalIPWhite[i].addr))
					return 0;
			}
			else
			{
				if (k >= *(DWORD*)&(m_LocalGlobVar.reinLocalIPWhite[i].addrStart) && k <= *(DWORD*)&(m_LocalGlobVar.reinLocalIPWhite[i].addrEnd))
					return 0;
			}
		}
		k = SwapDWORD(*(DWORD*)&(se->ulRemoteIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinRemoteIPWhiteLen; i++)//远端ip白名单
		{
			if (m_LocalGlobVar.reinRemoteIPWhite[i].type == 0)
			{
				if (k == *(DWORD*)&(m_LocalGlobVar.reinRemoteIPWhite[i].addr))
					return 0;
			}
			else
			{
				if (k >= *(DWORD*)&(m_LocalGlobVar.reinRemoteIPWhite[i].addrStart) && k <= *(DWORD*)&(m_LocalGlobVar.reinRemoteIPWhite[i].addrEnd))
					return 0;
			}
		}

		for (DWORD i = 0; i < m_LocalGlobVar.reinProcessLen; i++)//进程名
		{
			if (m_crc32 == m_LocalGlobVar.reinProcess[i].crc32)
				return 1;
		}
		for (DWORD i = 0; i < m_LocalGlobVar.reinPortLen; i++)//端口
		{
			if (r == m_LocalGlobVar.reinPort[i] || l == m_LocalGlobVar.reinPort[i])
				return 1;
		}
		k = SwapDWORD(*(DWORD*)&(se->ulLocalIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinLocalIPLen; i++)//本地ip
		{
			if (m_LocalGlobVar.reinLocalIP[i].type == 0)
			{
				if (k == *(DWORD*)&(m_LocalGlobVar.reinLocalIP[i].addr))
					return 1;
			}
			else
			{
				if (k >= *(DWORD*)&(m_LocalGlobVar.reinLocalIP[i].addrStart) && k <= *(DWORD*)&(m_LocalGlobVar.reinLocalIP[i].addrEnd))
					return 1;
			}
		}
		k = SwapDWORD(*(DWORD*)&(se->ulRemoteIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinRemoteIPLen; i++)//远端ip
		{
			if (m_LocalGlobVar.reinRemoteIP[i].type == 0)
			{
				if (k == *(DWORD*)&(m_LocalGlobVar.reinRemoteIP[i].addr))
					return 1;
			}
			else
			{
				if (k >= *(DWORD*)&(m_LocalGlobVar.reinRemoteIP[i].addrStart) && k <= *(DWORD*)&(m_LocalGlobVar.reinRemoteIP[i].addrEnd))
					return 1;
			}
		}
	}
	//LeaveCriticalSection(&m_csLocalGlob);
	return 0;
}

/************************************************************************
*由于aes加密使用的是16字节为一组进行加密，因此进行如下设定
*数据加密格式
*	1字节			1字节				2字节			2字节				2字节			    n字节		m+n-8字节
*	1字节			 3+5				2字节			2字节				2字节			  n+m-7字节		   填充
*	 E9			标志位+扩展长度m			随机数		原始数据长度n				时间戳              原始数据			0
*													*****************************************************************
*																			加密区
*注意：
*		总长度是m+n，m+n-8即为被填充0的部分，这是为了能够满足AES加密需要
*而扩展长度m的计算方式如下：
*		如果n<12		m=12+8-n		即	m+n=20
*		如果n>=12	m=8
*如果加密区的不足16字节的地方将不能用aes加密，而用原始数据（第三个字节之后作为起始）与其异或来加密
*
*3个标志位的解释（按比特位）
*					5.更新随机数(更新会话密钥)
*					6.更新主密钥
*					7.保留
*************************************************************************/

//获得需要扩展的长度
//参数：
//	len		原始长度
BYTE GetExtenedLength(
	int len
)
{
	if (len < 12)
		return 12 + 8 - len;
	else
		return 8;
}


//对待加密的数据进行加密操作
//参数
//	s			被加密的socket，用来查询和修改会话信息
//	sendbuf		待加密的发送缓冲区首地址
//	sendbuflen	待加密的数据缓冲区的总长度(单位：字节)
//注意：
//	加密所扩展的长度由宏EXTENDDATALENGTH来确定
//返回：
//	如果进行了加密返回大于0，否则便是没有加密并返回0
int ReinforceSend(
	SOCKET s,
	BYTE  * sendbuf,
	int sendbuflen
)
{
	int ret = 0;
	EnterCriticalSection(&m_csSession);
	{
		if (m_Session.find(s) != m_Session.end())
		{
			ret = 1;
			if (m_Session[s]->dDuration > MAX_USEFULL_TIME)
			{
				m_Session[s]->dDuration = 0;
				m_Session[s]->uRandom = (rand() + rand()) / 2;
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, m_Session[s]->uRandom, m_Session[s]->key);//计算新的会话密钥
					KeyExpansion(m_Session[s]->key, m_Session[s]->w);//更新会话密钥的扩展密钥
				}
				//LeaveCriticalSection(&m_csLocalGlob);
				sendbuf[1] |= 0x20;//更新密钥
			}
			else if (m_Session[s]->uRandom == 0)
			{
				m_Session[s]->uRandom = (rand() + rand()) / 2;
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, m_Session[s]->uRandom, m_Session[s]->key);//计算新的会话密钥
					KeyExpansion(m_Session[s]->key, m_Session[s]->w);//更新会话密钥的扩展密钥
				}
				//LeaveCriticalSection(&m_csLocalGlob);
				sendbuf[1] |= 0x20;//更新密钥
			}
			else
			{
				sendbuf[1] |= 0x40;//保留上一次结果
			}
			//0ffset=6
			*(USHORT*)(sendbuf + 6) = m_Session[s]->dDuration;//时间戳
			DS2I1(m_sProcessName, _T("ReinforceSend生成的dDuration="), m_Session[s]->dDuration);
			//offset=2
			*(USHORT*)(sendbuf + 2) = m_Session[s]->uRandom;//随机数
			DS2I1(m_sProcessName, _T("ReinforceSend生成的random="), m_Session[s]->uRandom);
			//截断加密
			int Remainder = (sendbuflen - 4) % 16;//余数
			int mod = (sendbuflen - 4) / 16;//商
			for (int i = 0; i < Remainder; i++)//余下的部分加密
			{
				*(sendbuf + 4 + 16 * mod + i) ^= *(sendbuf + 4 + i);
			}
			for (int i = 0; i < mod; i++)//整齐部分加密
			{
				Encrypt(sendbuf + 4 + i * 16, m_Session[s]->w);
			}
			//EnterCriticalSection(&m_csLocalGlob);
			{
				if (m_LocalGlobVar.reinSend != 0)
					AddLogMsg(LOG_NORMAL, "Send data that has been encrypted", m_Session[s], 1, FALSE, (char*)sendbuf, sendbuflen);
			}
			//LeaveCriticalSection(&m_csLocalGlob);

		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}


//对从远端收到的数据进行数据解密操作并将解密后的数据复制到指定的缓冲区中
//参数：
//	s					被加密的socket，用来查询和修改会话信息
//	lpRecvbuf			待解密的数据缓冲区数据的信息
//	lpRealRecvBuf		解密后保存数据的缓存区信息
//	bufferCount			缓冲区的个数
//	recvBytesLen		接收的数据的字节数，解密完成后会修改其值为解密后的数据长度
//注意：
//	解密完成后，真实的数据将会存放在lpRealRecvBuf关联的缓冲区中
//	recvBytesLen的值将更新为lpRealRecvBuf结构体中保存的解密后的数据总
int ReinforceRecv(
	SOCKET				s,
	LPWSABUF			lpRecvbuf,
	LPWSABUF			lpRealRecvBuf,
	DWORD				bufferCount,
	DWORD				*recvBytesLen
)
{
	PSESSION pSession = NULL;
	EnterCriticalSection(&m_csSession);
	{
		if (m_Session.find(s) != m_Session.end())
		{
			pSession = m_Session[s];
		}
	}
	LeaveCriticalSection(&m_csSession);
	/*
	PBYTE	pBuff = pSession->buffer;//组包缓冲区
	DWORD	lenBuff = pSession->bufferLen;//待组包长度
	DWORD	buffOffest = pSession->buffOffset;//组包数据起始位置
	*/
	int ret = 0;//成功解密的次数
	int offSet = 0;//对recvbuf的偏移
	DWORD leftBytesLen = *recvBytesLen;//剩余待解密数据长度
	DWORD frameLength;//本帧待解密的数据长度
	int remainder;//本帧长度的余数
	int mod;//本帧长度的商
	int len;//原始数据长度
	*recvBytesLen = 0;
	int k = 0;
	if (leftBytesLen == 0)
		return 0;
	//记录到log
	DWORD transferRecode = leftBytesLen;
	DWORD lenRecode = 0;
	//EnterCriticalSection(&m_csLocalGlob);
	{
		if (m_LocalGlobVar.reinRecv != 0)
		{
			for (int i = 0; i < bufferCount; i++)
			{
				lenRecode = lpRecvbuf[i].len;
				AddLogMsg(LOG_COMMENT, "Recv encrypt data", pSession, 0, TRUE, lpRecvbuf[i].buf, transferRecode > lenRecode ? lenRecode : transferRecode);
				if (transferRecode > lenRecode)
					transferRecode -= lenRecode;
				else
					break;
			}
		}
	}
	//LeaveCriticalSection(&m_csLocalGlob);

	//解密
	BYTE *recvbuf = (BYTE*)lpRecvbuf[0].buf;
	if (bufferCount != 1)
	{
		if (pSession->bIsAlloc == 0)
		{
			//为该session分配组包使用的缓冲区，调拨8个页面
			pSession->buffer = (PCHAR)VirtualAlloc(NULL, 8 * LOG_PAGE_SIZE, MEM_COMMIT, PAGE_READWRITE);
			pSession->bIsAlloc = 1;
		}
		transferRecode = leftBytesLen;
		lenRecode = 0;
		DWORD alreadyRecode = 0;
		for (int i = 0; i < bufferCount; i++)
		{
			lenRecode = lpRecvbuf[i].len;
			memcpy((char*)(*pSession->buffer + alreadyRecode), lpRecvbuf[i].buf, (transferRecode > lenRecode ? lenRecode : transferRecode));
			if (transferRecode > lenRecode)
				transferRecode -= lenRecode;
			else
				break;
		}
		recvbuf = (BYTE*)pSession->buffer;
	}
	DWORD alreadyPadBytes = 0;
	while (leftBytesLen != 0 && recvbuf[offSet + 0] == 0xe9 && (recvbuf[offSet + 1] & 0xe0) != 0)
	{
		if (pSession->uRandom == 0)
		{
			pSession->uRandom = *(USHORT*)(recvbuf + offSet + 2);
			//EnterCriticalSection(&m_csLocalGlob);
			{
				MasterEncrypt(m_dKeyExpand, pSession->uRandom, pSession->key);//计算新的会话密钥
				KeyExpansion(pSession->key, pSession->w);//更新会话密钥的扩展密钥
				//AddLogMsg(LOG_COMMENT, "Recv data first time, updata session key", pSession, 0, FALSE, 0, 0);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		else if (pSession->uRandom != *(USHORT*)(recvbuf + offSet + 2))//随机数
		{
			pSession->uRandom = *(USHORT*)(recvbuf + offSet + 2);
			pSession->dDuration = 0;
			//EnterCriticalSection(&m_csLocalGlob);
			{
				MasterEncrypt(m_dKeyExpand, pSession->uRandom, pSession->key);//计算新的会话密钥
				KeyExpansion(pSession->key, pSession->w);//更新会话密钥的扩展密钥
				AddLogMsg(LOG_COMMENT, "Recv delay time out of range and updata session key", pSession, 0, FALSE, 0, 0);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		if (pSession->dDuration > MAX_USEFULL_TIME)
			pSession->dDuration = 0;
		if (leftBytesLen < 4 + 16)//剩下长度不足以解密
		{
			AddLogMsg(LOG_ERROR, "Recv length is not enough to be decrypt", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			LeaveCriticalSection(&m_csSession);
			goto RETURN;
		}
		//对加密的前16字节进行解密
		Decrypt(recvbuf + offSet + 4, pSession->w);
		len = *(USHORT*)(recvbuf + offSet + 4);
		frameLength = len + (recvbuf[offSet + 1] & 0x1f) - 4;//n+m-4
		int timeError = pSession->dDuration - (*(USHORT*)(recvbuf + offSet + 6));//计算时效性
		DS2I1(m_sProcessName, L"timeError=", timeError);
		if (timeError > TIME_ERROR || timeError < -TIME_ERROR)
		{
			DS2I1(m_sProcessName, L"timeError=", timeError);
			AddLogMsg(LOG_ALERT, "Received data cannot be decrypted because the time check is incorrect but 16 bytes have been decrypted", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			goto RETURN;//直接返回
		}
		if (frameLength > leftBytesLen)//数据长度错误，不通过
		{
			AddLogMsg(LOG_ERROR, "Received data cannot be decrypted because the data length is incorrect but 16 bytes have been decrypted", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			goto RETURN;//直接返回
		}
		remainder = frameLength % 16;//余数
		mod = frameLength / 16;//商
		for (int i = 1; i < mod; i++)
		{
			Decrypt(recvbuf + offSet + 4 + 16 * i, pSession->w);
		}
		for (int i = 0; i < remainder; i++)
		{
			*(recvbuf + offSet + 4 + 16 * mod + i) ^= *(recvbuf + offSet + 4 + i);
		}
		{
			*recvBytesLen += len;
			//解密完成，复制到接收区
			while (len != 0)
			{
				if (lpRealRecvBuf[k].len - alreadyPadBytes < len)
				{
					memcpy(lpRealRecvBuf[k].buf + alreadyPadBytes, recvbuf + offSet + 8, lpRealRecvBuf[k].len - alreadyPadBytes);
					len = len - lpRealRecvBuf[k].len + alreadyPadBytes;
					k++;
					alreadyPadBytes = 0;
				}
				else
				{
					memcpy(lpRealRecvBuf[k].buf + alreadyPadBytes, recvbuf + offSet + 8, len);
					len = 0;
					alreadyPadBytes += len;
				}
			}
		}
		//准备下一帧
		offSet += (frameLength + 4);
		leftBytesLen -= (frameLength + 4);
		ret++;
	}
RETURN:
	if (ret == 0)
	{
		AddLogMsg(LOG_ERROR, "Unable to decrypt the received data, because there is no valid data header", pSession, 0, FALSE, (char*)recvbuf, leftBytesLen);
	}
	return ret;
}


//TCP中使用，将更新远端和本地的ip和port等信息。Accept使用新产生的socket作为参数s，connect中使用s作为参数s
//direction参数：如果是accept则是0，表示本地是服务器，如果是connect则是1，表示本地是客户端
//返回值：
//		如果需要加固返回非0，不需要加固则返回0.
int SessionTcp(
	SOCKET							s,
	const struct sockaddr FAR		*name,
	BYTE							bDirection
)
{
	int ret = 0;
	if (s == INVALID_SOCKET)
		return ret;
	EnterCriticalSection(&m_csSession);
	{
		if (m_Session.find(s) != m_Session.end())
		{
			ret = m_Session[s]->bEc;
		}
		else
		{
			SOCKADDR_IN	LocalAddr;
			int			sizeLocalAddr = sizeof(SOCKADDR_IN);
			memset((char*)&LocalAddr, 0, sizeof(LocalAddr));
			getsockname(s, (SOCKADDR*)&LocalAddr, &sizeLocalAddr);

			SOCKADDR_IN RemoteAddr;
			int			sizeRemoteAddr = sizeof(SOCKADDR_IN);
			if (name != NULL)
			{
				memset((char*)&RemoteAddr, 0, sizeof(RemoteAddr));
				memcpy(&RemoteAddr, name, sizeof(RemoteAddr));
			}
			else
			{
				getpeername(s, (SOCKADDR*)&RemoteAddr, &sizeRemoteAddr);
			}
			PSESSION se = (PSESSION)malloc(sizeof(SESSION));
			memset((char*)se, 0, sizeof(SESSION));
			se->bDirection = bDirection;
			se->uiLocalPort = LocalAddr.sin_port;
			se->ulLocalIP = LocalAddr.sin_addr;
			se->uiRemotePort = RemoteAddr.sin_port;
			se->ulRemoteIP = RemoteAddr.sin_addr;
			if ((se->bEc = WhetherToReinforce(se)) > 0)
			{
				DS2D1(m_sProcessName, _T("SessionTcp增加一个加密Socket，总共:"), (m_Session.size()));
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, se->uRandom, se->key);//计算新的会话密钥
					KeyExpansion(se->key, se->w);//更新会话密钥的扩展密钥
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			m_Session.emplace(s, se);
			ret = se->bEc;
			DS2D1(m_sProcessName, _T("SessionTcp总共:"), (m_Session.size()));
			if (ret != 0)
			{
				//EnterCriticalSection(&m_csLocalGlob);
				{
					if (m_LocalGlobVar.reinAccept != 0 && bDirection == 0)
						AddLogMsg(LOG_NORMAL, "Accept a remote socket", se, 0, 0, 0, 0);
					else if (m_LocalGlobVar.reinConnect != 0 && bDirection != 0)
						AddLogMsg(LOG_NORMAL, "Connect to a remote server", se, 0, 0, 0, 0);
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			else
			{
				//EnterCriticalSection(&m_csLocalGlob);
				{
					if (m_LocalGlobVar.allAccept != 0 && bDirection == 0)
						AddLogMsg(LOG_NORMAL, "Accept a remote socket", se, 0, 0, 0, 0);
					else if (m_LocalGlobVar.allConnect != 0 && bDirection != 0)
						AddLogMsg(LOG_NORMAL, "Connect to a remote server", se, 0, 0, 0, 0);
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}

//UDP中sendto和recvfrom使用。
//流程：
//	判断是否已有session
//	若有
//		更新相关信息
//	若无
//		加入该Session，判断是否加密
//	返回是否加密
//注：s用于更新本地信息，name用于更新远端信息.UDP中无法判断direction
//返回值：
//		如果需要加固返回非0，不需要加固则返回0.
int SessionUdp(
	SOCKET							s,
	const struct sockaddr FAR		*name
)
{
	//注意UDP可以广播(INADDR_BROADCAST 255.255.255.255:XX)和群发(INADDR_ANY 0.0.0.0:XX,指选择可与外界交流的任意网卡的IP地址)
	int ret = 0;
	if (s == INVALID_SOCKET)
		return ret;
	EnterCriticalSection(&m_csSession);
	{
		if (m_Session.find(s) != m_Session.end())
		{
			ret = m_Session[s]->bEc;
		}
		else
		{
			SOCKADDR_IN	LocalAddr;
			int			sizeLocalAddr = sizeof(SOCKADDR_IN);
			memset((char*)&LocalAddr, 0, sizeof(LocalAddr));
			getsockname(s, (SOCKADDR*)&LocalAddr, &sizeLocalAddr);
			SOCKADDR_IN RemoteAddr;
			int			sizeRemoteAddr = sizeof(SOCKADDR_IN);
			if (name != NULL)
			{
				memset((char*)&RemoteAddr, 0, sizeof(RemoteAddr));
				memcpy(&RemoteAddr, name, sizeof(RemoteAddr));
			}
			else
			{
				getpeername(s, (SOCKADDR*)&RemoteAddr, &sizeRemoteAddr);
			}
			PSESSION se = (PSESSION)malloc(sizeof(SESSION));
			memset((char*)se, 0, sizeof(SESSION));
			se->uiLocalPort = LocalAddr.sin_port;
			se->ulLocalIP = LocalAddr.sin_addr;
			se->uiRemotePort = RemoteAddr.sin_port;
			se->ulRemoteIP = RemoteAddr.sin_addr;
			if ((se->bEc = WhetherToReinforce(se)) > 0)
			{
				DS2D1(m_sProcessName, _T("SessionUDP增加加密连接，总共:"), (m_Session.size()));
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, se->uRandom, se->key);
					KeyExpansion(se->key, se->w);
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			m_Session.emplace(s, se);
			DS2D1(m_sProcessName, _T("SessionUdp总共:"), (m_Session.size()));
			ret = m_Session[s]->bEc;
		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}


/*
如果发送操作立即完成将返回0,并且lpNumberOfBytesSent保存了实际发送的字节数
如果服务成功启动了重叠操作将立即返回SOCKET_ERROR,并且错误代码lpErrno=WSA_IO_PENDING,并且lpNumberOfBytesSent不会保存实际发送的字节数
	当异步操作完成后，系统自动调用WSPGetOverlappedResult函数来告知发送完毕，并通过参数lpcbTransfer告知实际发送的字节数,其返回true表明重叠发送成功，否则重叠发送失败！
具体理解如下：
	如果lpOverlapped==NULL，发送将以阻塞形式发送
	如果lpOverlapped!=NULL，发送将以重叠IO发送
		如果lpCompletionRoutine!=NULL，将忽略lpOverlapped->hEvent，当发送完毕后系统作如下操作
			先调用lpCompletionRoutine。应用程序可能会再调用WSPGetOverlappedResult
		如果lpCompletionRoutine==NULL，当发送完毕后将作如下操作
			向hEvent句柄发送事件，应用程序必须再调用WSPGetOverlappedResult
注意：
	以上是应用层与系统的调用约定，但是应用层可以不按照约定来，即不设定event对象且不调用getoverlappedresult也不设定完成实例。如果应用程序不再使用方发送缓冲区，这样是做不会产生问题。
	如果应用层在异步操作未完成继续使用或释放了发送缓冲区，将引发异常。因此严谨上操作用户应该按照调用约定来操作。
*/
int WSPAPI WSPSend(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	_In_  LPWSATHREADID                      lpThreadId,
	_Out_ LPINT                              lpErrno
)
{
	if (SessionTcp(s, NULL, 0) <= 0)
	{
		EnterCriticalSection(&m_csSession);
		{
			//EnterCriticalSection(&m_csLocalGlob);
			{
				if (m_LocalGlobVar.allSend != 0)
				{
					for (int i = 0; i < dwBufferCount; i++)
					{
						AddLogMsg(LOG_COMMENT, "Send data", m_Session[s], 0, TRUE, lpBuffers[i].buf, lpBuffers[i].len);
						m_Session[s]->ulSendData += lpBuffers[i].len;
					}
				}
			}
			//LeaveCriticalSection(&m_csLocalGlob);

		}
		LeaveCriticalSection(&m_csSession);
		return m_NextProcTable.lpWSPSend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	char *buff = NULL;
	LPWSABUF lpBuffersSendTmp = NULL;
	*lpErrno = 0;
	int originalSendBytesLen = 0;//用于欺骗上层应用
	lpBuffersSendTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
	for (DWORD i = 0; i < dwBufferCount; i++)
	{
		buff = (char*)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + GetExtenedLength(lpBuffers[i].len)));
		buff[0] = 0xe9;//标志
		buff[1] = GetExtenedLength(lpBuffers[i].len);//扩展长度
		*(USHORT*)(buff + 4) = (USHORT)lpBuffers[i].len;//原始长度
		originalSendBytesLen += lpBuffers[i].len;
		memcpy(buff + 8, lpBuffers[i].buf, lpBuffers[i].len);//原始数据
		lpBuffersSendTmp[i].buf = buff;
		lpBuffersSendTmp[i].len = buff[1] + lpBuffers[i].len;
		ReinforceSend(s, (BYTE*)buff, lpBuffersSendTmp[i].len);//加密
	}
	int ret = 0;
	if (lpCompletionRoutine != NULL)
		ret = m_NextProcTable.lpWSPSend(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, CompletionRoutineSend, lpThreadId, lpErrno);
	else
		ret = m_NextProcTable.lpWSPSend(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//使用了重叠I/O操作
	{
		POVERLAPPEDSESSIONSEND pOverlappedSession = (POVERLAPPEDSESSIONSEND)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONSEND));
		pOverlappedSession->dwBufferCountSend = dwBufferCount;
		pOverlappedSession->lpBuffersSend = lpBuffersSendTmp;
		pOverlappedSession->lpCompletionRoutineSend = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->originalSendBytesLen = originalSendBytesLen;
		EnterCriticalSection(&m_csOverlappedSessionSend);
		{
			if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())//已存在，删除之。标志用户主动放弃。若用户不按规定来程序将可能崩溃，因为发送未完成，缓冲区已释放
			{
				for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
				{
					HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
				}
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
				m_OverlappedSessionSend.erase(lpOverlapped);
			}
			m_OverlappedSessionSend.emplace(lpOverlapped, pOverlappedSession);
		}
		LeaveCriticalSection(&m_csOverlappedSessionSend);
		//记录传输数据量
		EnterCriticalSection(&m_csSession);
		{
			if (m_Session.find(s) != m_Session.end())
			{
				for (int i = 0; i < dwBufferCount; i++)
					m_Session[s]->ulSendData += lpBuffersSendTmp[i].len;
			}
		}
		LeaveCriticalSection(&m_csSession);

	}
	else//阻塞形式成功发送或者发送失败！
	{
		for (DWORD i = 0; i < dwBufferCount; i++)
			HeapFree(m_hHeapOverlappedSessionSend, 0, lpBuffersSendTmp[i].buf);
		if (ret == 0)
		{
			//记录传输数据量
			EnterCriticalSection(&m_csSession);
			{
				if (m_Session.find(s) != m_Session.end())
				{
					m_Session[s]->ulSendData += *lpNumberOfBytesSent;
				}
			}
			LeaveCriticalSection(&m_csSession);
		}
		*lpNumberOfBytesSent = originalSendBytesLen;
	}

	return ret;
}

int WSPAPI WSPSendTo(
	_In_  SOCKET                             s,
	_In_  LPWSABUF                           lpBuffers,
	_In_  DWORD                              dwBufferCount,
	_Out_ LPDWORD                            lpNumberOfBytesSent,
	_In_  DWORD                              dwFlags,
	_In_  const struct sockaddr              *lpTo,
	_In_  int                                iTolen,
	_In_  LPWSAOVERLAPPED                    lpOverlapped,
	_In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	_In_  LPWSATHREADID                      lpThreadId,
	_Out_ LPINT                              lpErrno
)
{
	if (SessionUdp(s, lpTo) <= 0)
	{
		EnterCriticalSection(&m_csSession);
		{
			//EnterCriticalSection(&m_csLocalGlob);
			{
				if (m_LocalGlobVar.allSend != 0)
				{
					for (int i = 0; i < dwBufferCount; i++)
					{
						AddLogMsg(LOG_COMMENT, "SendTo data", m_Session[s], 0, TRUE, lpBuffers[i].buf, lpBuffers[i].len);
						m_Session[s]->ulSendData += lpBuffers[i].len;
					}
				}
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		LeaveCriticalSection(&m_csSession);
		return m_NextProcTable.lpWSPSendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	char *buff = NULL;
	LPWSABUF lpBuffersSendTmp = NULL;
	*lpErrno = 0;
	int originalSendBytesLen = 0;//用于欺骗上层应用
	lpBuffersSendTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
	for (DWORD i = 0; i < dwBufferCount; i++)
	{
		buff = (char*)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + GetExtenedLength(lpBuffers[i].len)));
		buff[0] = 0xe9;//标志
		buff[1] = GetExtenedLength(lpBuffers[i].len);//扩展长度
		*(USHORT*)(buff + 4) = (USHORT)lpBuffers[i].len;//原始长度
		originalSendBytesLen += lpBuffers[i].len;
		memcpy(buff + 8, lpBuffers[i].buf, lpBuffers[i].len);//原始数据
		lpBuffersSendTmp[i].buf = buff;
		lpBuffersSendTmp[i].len = buff[1] + lpBuffers[i].len;
		ReinforceSend(s, (BYTE*)buff, lpBuffersSendTmp[i].len);//加密
	}
	int ret = 0;
	if (lpCompletionRoutine != NULL)
		ret = m_NextProcTable.lpWSPSendTo(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, CompletionRoutineSend, lpThreadId, lpErrno);
	else
		ret = m_NextProcTable.lpWSPSendTo(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//使用了重叠I/O操作
	{
		POVERLAPPEDSESSIONSEND pOverlappedSession = (POVERLAPPEDSESSIONSEND)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONSEND));
		pOverlappedSession->dwBufferCountSend = dwBufferCount;
		pOverlappedSession->lpBuffersSend = lpBuffersSendTmp;
		pOverlappedSession->lpCompletionRoutineSend = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->originalSendBytesLen = originalSendBytesLen;
		EnterCriticalSection(&m_csOverlappedSessionSend);
		{
			if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())//已存在，删除之.标志用户主动放弃。若用户不按规定来程序将可能崩溃，因为发送未完成，缓冲区已释放
			{
				for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
				{
					HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
				}
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
				m_OverlappedSessionSend.erase(lpOverlapped);
			}
			m_OverlappedSessionSend.emplace(lpOverlapped, pOverlappedSession);
		}
		LeaveCriticalSection(&m_csOverlappedSessionSend);
		//记录传输数据量
		EnterCriticalSection(&m_csSession);
		{
			if (m_Session.find(s) != m_Session.end())
			{
				for (int i = 0; i < dwBufferCount; i++)
					m_Session[s]->ulSendData += lpBuffersSendTmp[i].len;
			}
		}
		LeaveCriticalSection(&m_csSession);

	}
	else//阻塞形式成功发送或者发送失败！
	{
		for (DWORD i = 0; i < dwBufferCount; i++)
			HeapFree(m_hHeapOverlappedSessionSend, 0, lpBuffersSendTmp[i].buf);
		if (ret == 0)
		{
			//记录传输数据量
			EnterCriticalSection(&m_csSession);
			{
				if (m_Session.find(s) != m_Session.end())
				{
					m_Session[s]->ulSendData += *lpNumberOfBytesSent;
				}
			}
			LeaveCriticalSection(&m_csSession);
		}
		*lpNumberOfBytesSent = originalSendBytesLen;
	}

	return ret;
}

void CALLBACK CompletionRoutineSend(
	DWORD									 dwError,
	DWORD									 cbTransferred,
	LPWSAOVERLAPPED							 lpOverlapped,
	DWORD									 dwFlags
)
{
	EnterCriticalSection(&m_csOverlappedSessionSend);
	{
		if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())
		{
			EnterCriticalSection(&m_csSession);
			{
				if (m_Session.find(m_OverlappedSessionSend[lpOverlapped]->s) != m_Session.end())
				{
					cbTransferred = m_OverlappedSessionSend[lpOverlapped]->originalSendBytesLen;//欺骗上层应用
				}
			}
			LeaveCriticalSection(&m_csSession);

			//调用应用层所提供的默认重叠I/O函数
			if (m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend != NULL)
				m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend(dwError, cbTransferred, lpOverlapped, dwFlags);
			//释放缓冲区
			for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
			{
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
			m_OverlappedSessionSend.erase(lpOverlapped);
			DS2D1(m_sProcessName, _T("CompletionRoutineSend删除一个重叠信息，还有"), (m_OverlappedSessionSend.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionSend);
}


/*
说明：
如果是阻塞的接收，那么将阻塞到接收完毕才返回并且lpNumberOfBytesRecvd指示接收的字节数
如果是重叠方式接收(要使lpOverlapped!=NULL才会以重叠方式接收数据)
	如果重叠操作立即完成，则返回0，并更新lpNumberOfBytesRecvd
	如果操作无法立即完成，将启动重叠操作并返回error，lpNumberOfBytesRecvd的值无效！并且
		如果重叠操作启动失败，*leErron的值不是WSA_IO_PENDING，而且也不会有操作完成的通知
		如果重叠操作启动成功：*leErron==WSA_IO_PENDING
			如果lpCompletionRoutine!=NULL,此时当完成重叠操作后系统将调用lpCompletionRoutine，应用程序可以调用WSPGetOverlappedResult查询收到的字节数
			如果lpCompletionRoutine==NULL,此时lpOverlapped->hEvent应当是有效的事件内核对象，当系统完成recv请求后会通知该事件(此时应用层在waitforsingleobj)，
				应用收到该事件后方可继续执行，此时应用程序必须调用调用WSPGetOverlappedResult来查询具体收到的字节数
注：
	应用层调用WSARecv/WSARecvFrom时可采用异步方式，调用recv/recvfrom时将采用同步，详情可参考msdn
	WSPRecvFrom函数的用法与本函数相同。
*/
int WSPAPI WSPRecv(
	_In_    SOCKET                             s,
	_Inout_ LPWSABUF                           lpBuffers,
	_In_    DWORD                              dwBufferCount,
	_Out_   LPDWORD                            lpNumberOfBytesRecvd,
	_Inout_ LPDWORD                            lpFlags,
	_In_    LPWSAOVERLAPPED                    lpOverlapped,
	_In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	_In_    LPWSATHREADID                      lpThreadId,
	_Out_   LPINT                              lpErrno
)
{
	DWORD reinforince = SessionTcp(s, NULL, 0);
	int ret = 0;
	*lpErrno = 0;
	LPWSABUF lpBuffersRecvTmp = NULL;
	if (reinforince != 0)
	{
		lpBuffersRecvTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
		for (DWORD i = 0; i < dwBufferCount; i++)
		{
			lpBuffersRecvTmp[i].buf = (char*)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + EXTENDDATALENGTH));
			lpBuffersRecvTmp[i].len = lpBuffers[i].len + EXTENDDATALENGTH;
		}

		if (lpCompletionRoutine != NULL)
			ret = m_NextProcTable.lpWSPRecv(s, lpBuffersRecvTmp, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, CompletionRoutineRecv, lpThreadId, lpErrno);
		else
			ret = m_NextProcTable.lpWSPRecv(s, lpBuffersRecvTmp, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	else
	{
		if (lpCompletionRoutine != NULL)
			ret = m_NextProcTable.lpWSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, CompletionRoutineRecv, lpThreadId, lpErrno);
		else
			ret = m_NextProcTable.lpWSPRecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	/*	注意：查阅MSDN和做实验都验证了如下结论：
		接收到的数据按照顺序填充缓冲区数组的buff当中，因此上一个数组没有存满，下一个数组不会进行填充。上一个数组填满下一个数组才会继续填充。
		即先填充lpBuffers[0].buff,填充满了且存在lpBuffers[1].buff时继续填充lpBuffers[1].buff，直至两种情况发生：
			1.数据接收完毕，缓冲区没有用完,接收的数据认为是完整的。
			2.所有的缓冲区都用完了，系统还有一部分数据没有交给用户，用户获得数据很可能不完整。
		所以：应用层一般需要对recv的数据进行组包
	*/
	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)
	{
		POVERLAPPEDSESSIONRECV pOverlappedSession = (POVERLAPPEDSESSIONRECV)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONRECV));
		pOverlappedSession->dwBufferCountRecv = dwBufferCount;
		pOverlappedSession->lpBuffersRecvBack = lpBuffers;
		pOverlappedSession->lpBuffersRecvTmp = lpBuffersRecvTmp;
		pOverlappedSession->lpCompletionRoutineRecv = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->dIsReinforce = reinforince;
		EnterCriticalSection(&m_csOverlappedSessionRecv);
		{
			if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())//删除之前的记录，如果存在的话
			{
				if (m_OverlappedSessionRecv[lpOverlapped]->dIsReinforce != 0)
				{
					for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
					{
						HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf);
					}
					HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp);
				}
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			m_OverlappedSessionRecv.emplace(lpOverlapped, pOverlappedSession);
		}
		LeaveCriticalSection(&m_csOverlappedSessionRecv);
	}
	else//阻塞形式接收、重叠当时接收但立即完成 或者 接收出现错误
	{
		if (reinforince != 0)
		{
			if (ret == 0)
			{
				//加固的 记录传输的字节数
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
					}
				}
				LeaveCriticalSection(&m_csSession);
			}
			//释放多个缓冲区
			ReinforceRecv(s, lpBuffersRecvTmp, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd);
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp);
		}
		else if (ret == 0)//不加固，而且未出错
		{
			//记录日志
			EnterCriticalSection(&m_csSession);
			{
				m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
				DWORD transfer = *lpNumberOfBytesRecvd;
				DWORD len = 0;
				//EnterCriticalSection(&m_csLocalGlob);
				{
					if (m_LocalGlobVar.allRecv != 0)
					{
						for (int i = 0; i < dwBufferCount; i++)
						{
							len = lpBuffers[i].len;
							AddLogMsg(LOG_COMMENT, "Recv data", m_Session[s], 0, TRUE, lpBuffers[i].buf, transfer > len ? len : transfer);
							if (transfer > len)
								transfer -= len;
							else
								break;
						}
					}
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			LeaveCriticalSection(&m_csSession);
		}
	}
	return ret;
}


int WSPAPI WSPRecvFrom(
	_In_    SOCKET                             s,
	_Inout_ LPWSABUF                           lpBuffers,
	_In_    DWORD                              dwBufferCount,
	_Out_   LPDWORD                            lpNumberOfBytesRecvd,
	_Inout_ LPDWORD                            lpFlags,
	_Out_   struct sockaddr                    *lpFrom,
	_Inout_ LPINT                              lpFromlen,
	_In_    LPWSAOVERLAPPED                    lpOverlapped,
	_In_    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	_In_    LPWSATHREADID                      lpThreadId,
	_Inout_ LPINT                              lpErrno
)
{
	DWORD reinforince = SessionUdp(s, lpFrom);
	int ret = 0;
	*lpErrno = 0;
	LPWSABUF lpBuffersRecvTmp = NULL;
	if (reinforince != 0)
	{
		lpBuffersRecvTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
		for (DWORD i = 0; i < dwBufferCount; i++)
		{
			lpBuffersRecvTmp[i].buf = (char*)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + EXTENDDATALENGTH));
			lpBuffersRecvTmp[i].len = lpBuffers[i].len + EXTENDDATALENGTH;
		}
		if (lpCompletionRoutine != NULL)
			ret = m_NextProcTable.lpWSPRecvFrom(s, lpBuffersRecvTmp, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, CompletionRoutineRecv, lpThreadId, lpErrno);
		else
			ret = m_NextProcTable.lpWSPRecvFrom(s, lpBuffersRecvTmp, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}
	else
	{
		if (lpCompletionRoutine != NULL)
			ret = m_NextProcTable.lpWSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, CompletionRoutineRecv, lpThreadId, lpErrno);
		else
			ret = m_NextProcTable.lpWSPRecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	}

	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//异步模式
	{
		POVERLAPPEDSESSIONRECV pOverlappedSession = (POVERLAPPEDSESSIONRECV)HeapAlloc(m_hHeapOverlappedSessionRecv, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONRECV));
		pOverlappedSession->dwBufferCountRecv = dwBufferCount;
		pOverlappedSession->lpBuffersRecvBack = lpBuffers;
		pOverlappedSession->lpBuffersRecvTmp = lpBuffersRecvTmp;
		pOverlappedSession->lpCompletionRoutineRecv = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->dIsReinforce = reinforince;
		EnterCriticalSection(&m_csOverlappedSessionRecv);
		{
			if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())//删除之前的记录，如果存在的话
			{
				if (m_OverlappedSessionRecv[lpOverlapped]->dIsReinforce != 0)
				{
					for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
					{
						HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf);
					}
					HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp);
				}
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			m_OverlappedSessionRecv.emplace(lpOverlapped, pOverlappedSession);
		}
		LeaveCriticalSection(&m_csOverlappedSessionRecv);
	}
	else//阻塞形式接收、重叠当时接收但立即完成 或者 接收出现错误
	{
		if (reinforince != 0)
		{
			if (ret == 0)
			{
				//加固的 记录传输的字节数
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
					}
				}
				LeaveCriticalSection(&m_csSession);
			}
			//释放多个缓冲区
			ReinforceRecv(s, lpBuffersRecvTmp, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd);
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp);
		}
		else if (ret == 0)//不加固，而且未出错
		{
			//记录日志
			EnterCriticalSection(&m_csSession);
			{
				m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
				DWORD transfer = *lpNumberOfBytesRecvd;
				DWORD len = 0;
				//EnterCriticalSection(&m_csLocalGlob);
				{
					if (m_LocalGlobVar.allRecv != 0)
					{
						for (int i = 0; i < dwBufferCount; i++)
						{
							len = lpBuffers[i].len;
							AddLogMsg(LOG_COMMENT, "RecvFrom data", m_Session[s], 0, TRUE, lpBuffers[i].buf, transfer > len ? len : transfer);
							if (transfer > len)
								transfer -= len;
							else
								break;
						}
					}
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			LeaveCriticalSection(&m_csSession);
		}
	}
	return ret;
}


//异步recv的完成操作时可选的回调函数(如果应用程序选择了完成实例这种方式来查询完成情况的话）。
//考虑到本函数以多线程方式通知应用层，因此应用层需要考虑同步问题，使得编程难度加大，故很少会使用此方法。
void CALLBACK CompletionRoutineRecv(
	DWORD										dwError,
	DWORD										cbTransferred,
	LPWSAOVERLAPPED								lpOverlapped,
	DWORD										dwFlags
)
{
	EnterCriticalSection(&m_csOverlappedSessionRecv);
	{
		if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())
		{
			if (m_OverlappedSessionRecv[lpOverlapped]->dIsReinforce != 0)
			{
				//记录传输数据量
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(m_OverlappedSessionRecv[lpOverlapped]->s) != m_Session.end())
					{
						m_Session[m_OverlappedSessionRecv[lpOverlapped]->s]->ulRecvData += cbTransferred;
					}
				}
				LeaveCriticalSection(&m_csSession);
				//解密并拷贝数据
				ReinforceRecv(m_OverlappedSessionRecv[lpOverlapped]->s, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack, m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv, &cbTransferred);
				//for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
				//{
				//	ReinforceRecv(m_OverlappedSessionRecv[lpOverlapped]->s,
				//		(BYTE*)m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf,
				//		&cbTransferred,
				//		(BYTE*)m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].buf,
				//		m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].len);
				//}
				//调用应用层所提供的默认重叠I/O函数
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(dwError, cbTransferred, lpOverlapped, dwFlags);
				//释放缓存
				for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
				{
					HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf);
				}
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp);
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			else
			{
				//调用应用层所提供的默认重叠I/O函数
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(dwError, cbTransferred, lpOverlapped, dwFlags);
				//记录日志
				EnterCriticalSection(&m_csSession);
				{
					m_Session[m_OverlappedSessionRecv[lpOverlapped]->s]->ulRecvData += cbTransferred;
					DWORD transfer = cbTransferred;
					DWORD len = 0;
					//EnterCriticalSection(&m_csLocalGlob);
					{
						if (m_LocalGlobVar.allRecv != 0)
						{
							for (int i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
							{
								len = m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].len;
								AddLogMsg(LOG_COMMENT, "Recv(From) data", m_Session[m_OverlappedSessionRecv[lpOverlapped]->s], 0, TRUE
									, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].buf
									, transfer > len ? len : transfer);
								if (transfer > len)
									transfer -= len;
								else
									break;
							}
						}
					}
					//LeaveCriticalSection(&m_csLocalGlob);
				}
				LeaveCriticalSection(&m_csSession);
				//释放重叠结构体
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			DS2D1(m_sProcessName, _T("CompletionRoutineRecv删除一个重叠信息，还有"), (m_OverlappedSessionRecv.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionRecv);
}

//使用了异步套接字的应用程序通常会调用此函数查询异步操作结果，来判断异步IO是否已完成
//应用程序在使用了重叠I/O时其中一种方式便是通过调用此函数来查询异步操作是否完成。
BOOL WSPAPI WSPGetOverlappedResult(
	_In_  SOCKET          s,
	_In_  LPWSAOVERLAPPED lpOverlapped,
	_Out_ LPDWORD         lpcbTransfer,
	_In_  BOOL            fWait,
	_Out_ LPDWORD         lpdwFlags,
	_Out_ LPINT           lpErrno
)
{
	DS2(m_sProcessName, _T("WSPGetOverlappedResult函数执行..."));
	BOOL ret = m_NextProcTable.lpWSPGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags, lpErrno);
	if (ret == FALSE)
		return ret;

	EnterCriticalSection(&m_csOverlappedSessionSend);
	{
		if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())
		{
			//记录传输数据量
			EnterCriticalSection(&m_csSession);
			{
				if (m_Session.find(s) != m_Session.end())
				{
					*lpcbTransfer = m_OverlappedSessionSend[lpOverlapped]->originalSendBytesLen;
				}
			}
			LeaveCriticalSection(&m_csSession);
			//调用应用层可能提供的默认重叠I/O的回调函数
			if (m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend != NULL)
				m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
			//释放缓冲区
			for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
			{
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
			m_OverlappedSessionSend.erase(lpOverlapped);
			DS2D1(m_sProcessName, _T("WSPGetOverlappedResult删除一个send重叠信息，还有"), (m_OverlappedSessionSend.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionSend);


	EnterCriticalSection(&m_csOverlappedSessionRecv);
	{
		if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())
		{
			if (m_OverlappedSessionRecv[lpOverlapped]->dIsReinforce != 0)
			{
				//记录传输数据量
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpcbTransfer;
					}
				}
				LeaveCriticalSection(&m_csSession);
				//解密并拷贝数据
				ReinforceRecv(s, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack, m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv, lpcbTransfer);
				//调用应用层可能提供的默认重叠I/O的回调函数
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
				//释放缓冲区
				for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
				{
					HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf);
				}
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp);
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			else
			{
				//调用应用层可能提供的默认重叠I/O的回调函数
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
				//记录日志
				EnterCriticalSection(&m_csSession);
				{
					m_Session[s]->ulRecvData += *lpcbTransfer;
					DWORD transfer = *lpcbTransfer;
					DWORD len = 0;
					//EnterCriticalSection(&m_csLocalGlob);
					{
						if (m_LocalGlobVar.allRecv != 0)
						{
							for (int i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
							{
								len = m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].len;
								AddLogMsg(LOG_COMMENT, "Recv(From) data", m_Session[s], 0, TRUE
									, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].buf
									, transfer > len ? len : transfer);
								if (transfer > len)
									transfer -= len;
								else
									break;
							}
						}
					}
					//LeaveCriticalSection(&m_csLocalGlob);
				}
				LeaveCriticalSection(&m_csSession);
				//释放重叠结构体
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			DS2D1(m_sProcessName, _T("WSPGetOverlappedResult删除一个recv重叠信息，还有"), (m_OverlappedSessionRecv.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionRecv);

	return ret;
}

int WSPAPI WSPCleanup(
	LPINT										lpErrno
)
{
	EnterCriticalSection(&m_csSession);
	{
		//释放所有的session
		SESSION_MAP::iterator it = m_Session.begin();
		while (it != m_Session.end())
		{
			if (it->second->bIsAlloc != 0)
				VirtualFree(it->second->buffer, 8 * LOG_PAGE_SIZE, MEM_RELEASE);
			free(it->second);
			it++;
		}
		m_Session.clear();
	}
	LeaveCriticalSection(&m_csSession);

	EnterCriticalSection(&m_csOverlappedSessionRecv);
	{
		//释放所有的重叠I/O Recv
		OVERLAPPED_MAPRECV::iterator it = m_OverlappedSessionRecv.begin();
		while (it != m_OverlappedSessionRecv.end())
		{

			//释放缓冲区
			for (DWORD i = 0; i < it->second->dwBufferCountRecv; i++)
			{
				HeapFree(m_hHeapOverlappedSessionRecv, 0, it->second->lpBuffersRecvTmp[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionRecv, 0, it->second->lpBuffersRecvTmp);
			HeapFree(m_hHeapOverlappedSessionRecv, 0, it->second);
			it++;
		}
		m_OverlappedSessionRecv.clear();
	}
	LeaveCriticalSection(&m_csOverlappedSessionRecv);

	EnterCriticalSection(&m_csOverlappedSessionSend);
	{
		//释放所有的重叠I/O Send
		OVERLAPPED_MAPSEND::iterator it = m_OverlappedSessionSend.begin();
		while (it != m_OverlappedSessionSend.end())
		{
			//释放缓冲区
			for (DWORD i = 0; i < it->second->dwBufferCountSend; i++)
			{
				HeapFree(m_hHeapOverlappedSessionSend, 0, it->second->lpBuffersSend[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionSend, 0, it->second->lpBuffersSend);
			HeapFree(m_hHeapOverlappedSessionSend, 0, it->second);
			it++;
		}
		m_OverlappedSessionSend.clear();
	}
	LeaveCriticalSection(&m_csOverlappedSessionSend);

	return m_NextProcTable.lpWSPCleanup(lpErrno);
}
