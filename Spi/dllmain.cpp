// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
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
#define EXTENDDATALENGTH		20	//�����ܲ����ж����ݽ�����չ�ĳ���
#define MAX_USEFULL_TIME		30	//ÿһ��session������Կ�������ʱ��
#define MAX_PACKET_LEN			2048//�ڴ�ӳ������ְ�����
#define TIME_ERROR				10	//���ʱ��������������Ϊ�Ƿ�
#define LOG_PAGE_COUNT			400	//log���ڴ�ӳ��ҳ����
#ifdef  _X86_
#define LOG_PAGE_SIZE			4096//log��һ��ҳ�Ĵ�С
#else
#define LOG_PAGE_SIZE			8192//log��һ��ҳ�Ĵ�С
#endif
#define	LOG_USEABLEBYTE			LOG_PAGE_COUNT * LOG_PAGE_SIZE - (MAX_PACKET_LEN + 3) * 4
/****************************************************************************��־�ȼ��궨��***************************************************************************/
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

//���һ���Ự����Ϣ����Socket���ӱ�־Ψһ��ʶÿһ���Ự
typedef struct
{
	BYTE								bDirection;//���ӷ���,-1:δ֪��0�����ⲿ���ӣ�1�������ⲿ
	IN_ADDR								ulLocalIP;//����IP��ַ
	USHORT								uiLocalPort;//���ض˿�
	IN_ADDR								ulRemoteIP;//Զ��IP��ַ
	USHORT								uiRemotePort;//Զ�˶˿�
	DWORD								ulSendData;//��ǰ���������ܴ�С
	DWORD								ulRecvData;//��ǰ���������ܴ�С
	USHORT								uRandom;//���������֤ʱ���õ������
	USHORT								dDuration;//���ϴθ�����Կ��ʼ������ʱ��
	BOOL								bEc;//�Ƿ����ͨѶ

	BOOL								bIsAlloc;//�Ƿ���仺����
	PCHAR								buffer;//���ʹ�õĻ������׵�ַ
	DWORD								bufferLen;//�������Ч���ݳ���
	DWORD								buffOffset;//�������Ч���ݵ���ʼ��ַ
	BYTE								key[4 * Nk];//���λỰ����ʱ�Ự��Կ
	DWORD								w[4 * (Nr + 1)];//�Ự��Կ��չ����������Կ��ÿ�θ��»Ự��Կkey��Ӧ����������KeyExpansion����������Կ
} SESSION, *PSESSION;

typedef struct
{
	BYTE								bDirection;//���ӷ���,-1:δ֪��0�����ⲿ���ӣ�1�������ⲿ
	IN_ADDR								ulLocalIP;//����IP��ַ
	USHORT								uiLocalPort;//���ض˿�
	IN_ADDR								ulRemoteIP;//Զ��IP��ַ
	USHORT								uiRemotePort;//Զ�˶˿�
	DWORD								ulSendData;//��ǰ���������ܴ�С
	DWORD								ulRecvData;//��ǰ���������ܴ�С
	USHORT								uRandom;//���������֤ʱ���õ������
	USHORT								dDuration;//���ϴθ�����Կ��ʼ������ʱ��
	BOOL								bEc;//�Ƿ����ͨѶ
} LOGSESSION;

//��һ���Ѿ��շ������ݰ�ת�������س���ʱ���õ���Ϣ����
//����Ϣ��Ӧ����������ʱ��ÿһ���յ��򷢳������ݰ����зְ���ת�������س���
typedef struct
{
	DWORD								packetLength;//packet���ܴ�С
	SYSTEMTIME							time;//��Ϣ������ʱ��
	DWORD								dIndex;//��ǰ���̷��͵�����
	DWORD								dkind;//��־�ȼ�
	DWORD								dDescriptionBytesLength;//������Ϣ�ַ������ֽڳ���
	LOGSESSION							logSession;//�Ự��Ϣ��log��ע�Ĳ���
	BYTE								bDirect;//bit0��������(��)���ݵķ���0�����գ�1�������� bit1��0������,1������
	BYTE								hasLogSession;//�Ƿ���Session��Ϊ0�Ļ������logSession
	DWORD								iLengthSum;//������(��)���ݵ��ܳ���
	TCHAR								szProcessName[MAX_PATH];//������
	DWORD								dCount;//������ӵ�е�session����
}PACKET, *PPACKET;

typedef struct
{
	DWORD								pos;//��ǰ��־������
	DWORD								maxPos;//�������
	DWORD								useableBytes;//���Ա���¼Packet���ֽ���
	DWORD								packet[MAX_PACKET_LEN];//��¼ÿһ��packet��ʼ�����DATA��ƫ������С
	BYTE								data[LOG_USEABLEBYTE];//�洢���е�packet�ĵط�
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
	SOCKET					s;//���overlapped������socket
	LPWSABUF				lpBuffersSend;//�滻��sendʹ�õĻ��������ص�����ʱ���ͷ�
	DWORD					dwBufferCountSend;//������������
	PCOMPLETIONROUTINE		lpCompletionRoutineSend;//Ӧ�ò��ṩ�Ļص�������ַ�ı���
	DWORD					originalSendBytesLen;//Ӧ�ò��ύ��ԭʼ���͵������ܳ���
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
	SOCKET					s;//���overlapped������socket
	LPWSABUF				lpBuffersRecvBack;//Ӧ�ò��ṩ�����ݻ�����
	LPWSABUF				lpBuffersRecvTmp;//�滻��recvʹ�õĵĻ�����
	DWORD					dwBufferCountRecv;//������������
	PCOMPLETIONROUTINE		lpCompletionRoutineRecv;//Ӧ�ò��ṩ�Ļص�������ַ�ı���
	DWORD					dIsReinforce;//�Ƿ񱻼��ܴ���
}OVERLAPPEDSESSIONRECV, *POVERLAPPEDSESSIONRECV;

struct OverlappedRecvEqual {
public:
	bool operator()(const LPWSAOVERLAPPED& n1, const LPWSAOVERLAPPED& n2) const
	{
		return n1 == n2;
	}
};
typedef  std::unordered_map<LPWSAOVERLAPPED, POVERLAPPEDSESSIONRECV, std::hash<LPWSAOVERLAPPED>, OverlappedRecvEqual> OVERLAPPED_MAPRECV;
/********************************************************************************ȫ�ֱ���****************************************************************************/
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
SESSION_MAP			m_Session;//�Ự��Ϣ�Ĺ�ϣ��
CRITICAL_SECTION	m_csSession;//�Ự��Ϣ��ϣ����ٽֱ���

OVERLAPPED_MAPSEND	m_OverlappedSessionSend;//�ص�IO��Ϣsend�Ĺ�ϣ��
CRITICAL_SECTION	m_csOverlappedSessionSend;//�ص�IO��Ϣsendd�Ĺ�ϣ����ٽ�������
HANDLE				m_hHeapOverlappedSessionSend;//�ص�IO��Ϣsendd�Ĺ�ϣ��ĶѾ��

OVERLAPPED_MAPRECV	m_OverlappedSessionRecv;//�ص�IO��Ϣrecv�Ĺ�ϣ��
CRITICAL_SECTION	m_csOverlappedSessionRecv;//�ص�IO��Ϣrecv�Ĺ�ϣ����ٽ�������
HANDLE				m_hHeapOverlappedSessionRecv;//�ص�IO��Ϣrecv�Ĺ�ϣ��ĶѾ��

TCHAR				m_sProcessName[MAX_PATH];//������ñ�dll�Ľ�����
DWORD				m_crc32;//������(������չ��)��crc32ֵ
TCHAR				m_sProcessFullPath[MAX_PATH];//���ñ�dll�ı����̵�����·��
TCHAR				m_sLogFilePath[MAX_PATH];//��־�ļ�������·��
TCHAR				m_sCfgFilePath[MAX_PATH];//�����ļ�������·��
DWORD				m_dwPid = NULL;//���ñ�dll�Ľ��̵�PID

BOOL				m_IsFirstStarup = TRUE;//��Ǳ����̵�һ�ε��ô�dll
WSPPROC_TABLE		m_NextProcTable;//��Hook��dll��ȫ������ָ��
WSPUPCALLTABLE		m_UpCallTable;

DWORD				m_dKeyExpand[44];//����Կ����չ��Կ

GLOBVAR				m_LocalGlobVar;//ȫ�ֱ����ı��ظ���
CRITICAL_SECTION	m_csLocalGlob;//���ʱ��ص�ȫ�ֱ����Ĺؼ���
PGLOBVAR			m_pGlobVar = NULL;//ȫ�ֱ������ڴ�ӳ��ָ��
HANDLE				m_hGlobVarMutex = NULL;//����ȫ�ֱ����ڴ�ӳ��Ļ�����
HANDLE				m_hGlobVarSemap = NULL;//���н���ȫ�ֱ������ڴ�ӳ����ź���
HANDLE				m_hGlobThread = NULL;//ȫ�ֱ����ĸ����߳�

//��־��¼��Ϊ��¼�̺߳�д���ļ��߳�
queue<PPACKET>		m_PacketQueue;//�ְ������ݰ������ؽ���ʹ�õĶ���
CRITICAL_SECTION	m_csPacketQueue;//����m_PacketQueue���еĹؼ���
HANDLE				m_hHeapPacketQueue;//�ְ������ݰ������ؽ���ʹ�õĶ��еĶѾ��
PLOGGER				m_pLogVar = NULL;//��־���ڴ�ӳ���ļ���ָ��
HANDLE				m_hLogThread = NULL;//��־�ĸ����߳�
HANDLE				m_hLogRecordThread = NULL;//����־д�뵽�ļ����߳̾��
HANDLE				m_hlogRecordMutex = NULL;//����־д�뵽�ļ����̹߳����Ļ�����
HANDLE				m_hLogMutex = NULL;//������־���ڴ�ӳ����ڴ�Ļ����������̼乲��
HANDLE				m_hLogSemapLocal = NULL;//��������ʹ�õ�����־��¼�̹߳������ź���
HANDLE				m_hLogSemapShared = NULL;//����־д�뵽�ļ��Ľ��̷��͹������ź��������̼乲��
DWORD				m_dLogCount = 0;//�����̵�ǰ��¼��־��������

HANDLE				m_hTimerThread = NULL;//ʱ��ͬ���߳̾��
HANDLE				m_htTimer = NULL;//�߳�ͬ����ʱ�����

LONG				m_isThreadRun = TRUE;//���е��߳��Ƿ��������
CRITICAL_SECTION	m_csThreadRun;//m_isThreadRun�����Ĺؼ���

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
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)//dll������
	{
		TCHAR sProcessName[MAX_PATH];
		TCHAR sExtension[50];
		TCHAR drive[10];
		TCHAR dir[MAX_PATH];

		GetModuleFileNameW(NULL, m_sProcessFullPath, MAX_PATH);//��ü��ر�dll��Ӧ�ó�������·��
		m_dwPid = GetCurrentProcessId();
		_wsplitpath(m_sProcessFullPath, NULL, NULL, sProcessName, sExtension);
		_swprintf(m_sProcessName, _T("%s%s"), sProcessName, sExtension);
		m_crc32 = crc32((BYTE*)m_sProcessName, lstrlenW(m_sProcessName));

		GetModuleFileNameW(hModule, m_sLogFilePath, MAX_PATH);
		_wsplitpath(m_sLogFilePath, drive, dir, NULL, NULL);
		_swprintf(m_sLogFilePath, L"%s%s%s", drive, dir, L"log.log");
		_swprintf(m_sCfgFilePath, L"%s%s%s", drive, dir, L"cfg.cfg");

		InitializeCriticalSection(&m_csPacketQueue);//��ʼ���ؼ���
		InitializeCriticalSection(&m_csSession);
		InitializeCriticalSection(&m_csOverlappedSessionSend);
		InitializeCriticalSection(&m_csOverlappedSessionRecv);
		InitializeCriticalSection(&m_csThreadRun);
		InitializeCriticalSection(&m_csLocalGlob);
		//ȫ�ֱ����ĳ�ʼ������
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
			DS2(m_sProcessName, _T("DllMain:�������߳�m_hGlobThreadʧ��..."));
		}
		//��־��ʼ��
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
			//�������һ��ȫ�ֱ�������˽���ڴ���
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
			DS2(m_sProcessName, _T("DllMain:�������߳�m_hLogThreadʧ��..."));
		}
		if (NULL == m_hLogRecordThread)
			m_hLogRecordThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LogRecordThreadProc, NULL, 0, NULL);
		if (NULL == m_hLogRecordThread)
		{
			DS2(m_sProcessName, _T("DllMain:�������߳�m_hLogRecordThreadʧ��..."));
		}

		//����ͬ���õĶ�ʱ��
		m_htTimer = CreateWaitableTimerW(NULL, FALSE, NULL);
		if (m_htTimer == NULL)
		{
			DS2D1(m_sProcessName, L"CreateWaitableTimerW ERROR CODE:", GetLastError());
		}
		LARGE_INTEGER lt;
		lt.HighPart = 0;
		lt.LowPart = 0;
		SetWaitableTimer(m_htTimer, &lt, 1000, NULL, NULL, TRUE);//������ʱ��
		if (m_hTimerThread == NULL)
			m_hTimerThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TimerThreadProc, NULL, 0, NULL);
		if (NULL == m_hTimerThread)
		{
			DS2(m_sProcessName, _T("DllMain:�������߳�TimerThreadProcʧ��..."));
		}
		m_hHeapPacketQueue = HeapCreate(0, 0, 0);
		m_hHeapOverlappedSessionSend = HeapCreate(0, 0, 0);
		m_hHeapOverlappedSessionRecv = HeapCreate(0, 0, 0);
		DS2(m_sProcessName, _T("DllMain:���������ִ����ϣ�"));
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH)//dll��ж��
	{

		//�����ﱣ֤�����̶߳�����ȷ���˳�
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
		//�����
		HeapDestroy(m_hHeapOverlappedSessionSend);
		HeapDestroy(m_hHeapOverlappedSessionRecv);
		HeapDestroy(m_hHeapPacketQueue);
		DS2(m_sProcessName, _T("DllMain:ж����ϣ�"));
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
	DS2(m_sProcessName, _T("WSPStartup����ʼִ��..."));
	if (!m_IsFirstStarup)//���ǵ�һ��������������hook
	{
		DS2(m_sProcessName, _T("WSPStartup�����ǵ�һ������������"));
		upcallTable = m_UpCallTable;
		memcpy(lpProcTable, &m_NextProcTable, sizeof(WSPPROC_TABLE));
		return 0;
	}
	TCHAR				sLibraryPath[512];
	LPWSPSTARTUP        WSPStartupFunc = NULL;//����ԭ�ȵ�SPI�����StartUp������ַ
	HMODULE				hLibraryHandle = NULL;//���汸�ݵ�spi��dll�ļ���·��
	INT                 ErrorCode = 0;
	if (!GetHookProviderDllPath(lpProtocolInfo, sLibraryPath) || (hLibraryHandle = LoadLibrary(sLibraryPath)) == NULL || (WSPStartupFunc = (LPWSPSTARTUP)GetProcAddress(hLibraryHandle, "WSPStartup")) == NULL)
	{
		DS2(m_sProcessName, _T("WSPStartup��ִ��ʧ�ܣ�"));
		return WSAEPROVIDERFAILEDINIT;
	}
	//ִ�б�Hook��dll��StartUp
	if ((ErrorCode = WSPStartupFunc(wVersionRequested, lpWSPData, lpProtocolInfo, upcallTable, lpProcTable)) != ERROR_SUCCESS)
		return ErrorCode;
	//�����Щ����ָ�붼����ȷ�ļ��أ����ǲſ��Կ�ʼHook
	m_UpCallTable = upcallTable;
	m_NextProcTable = *lpProcTable;
	//����Hook��ֻhook���ĵĺ�����ע������Hook�ĺ�������������ԭʼ�ĺ�����
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
	DS2(m_sProcessName, _T("WSPStartup��ִ�гɹ�..."));
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

//��ansi�ַ�ת��ΪUnicode�ַ�
//lpChar			ansi�ַ�������ʼ��ַ
//lpTchar			ת���󱣴�unicode�ַ�����ʼ��ַ
//lengthTchar	����unicode�ַ�����󳤶�
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

//��Unicode�ַ�ת��Ϊansi�ַ�
//lpTchar		unicode�ַ�������ʼ��ַ
//lpAnsi		ת���󱣴�ansi�ַ�����ʼ��ַ
//lengthChar	����ansi�ַ�����󳤶�
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

//ȫ�ֱ��������̣߳��������ڹ���״̬
DWORD WINAPI GlobThreadProc(
	LPVOID lpParam
)
{
	DS2(m_sProcessName, _T("GlobThreadProc->:���̳߳ɹ�������..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("GlobThreadProc->:ֹͣ��"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_hGlobVarSemap, INFINITE);//ÿ�����ý�������ʱ�Ż�ִ����ȥ

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


//������־���̣߳�����ʱ������
DWORD WINAPI LogThreadProc(
	LPVOID lpParam
)
{
	PPACKET pPacket = NULL;
	DWORD offset = 0;
	//printf("LogThreadProc->:���̳߳ɹ�������...");
	DS2(m_sProcessName, _T("LogThreadProc->:���̳߳ɹ�������..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				//printf("LogThreadProc->:ֹͣ��");
				DS2(m_sProcessName, _T("LogThreadProc->:ֹͣ��"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_hLogSemapLocal, INFINITE);//�����ź�������/���ź�ʱ�Ż�ִ����ȥ

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
							// д�����ƫ����Ϊ:	offset = ��һ����¼����ʼ�� + ��һ����¼�ĳ���
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

//��¼��־���ļ����̣߳����յ���¼�ź�ʱ�����ִ��
DWORD WINAPI LogRecordThreadProc(
	LPVOID lpParam
)
{
	//printf("LogRecordThreadProc->:���̳߳ɹ�������...");
	DS2(m_sProcessName, _T("LogRecordThreadProc->:���̳߳ɹ�������..."));
	PPACKET p = NULL;
	TCHAR strFormat[800];
	TCHAR Remote[30];
	TCHAR Local[30];
	TCHAR hex[6];
	FILE* plogFile = NULL;
	WaitForSingleObject(m_hlogRecordMutex, INFINITE);//ֻ�еȴ��ɹ��Ĳ���ӵ�м�¼��־������
	//printf("��ü�¼��־Ȩ�ޣ�");
	DS2(m_sProcessName, L"��ü�¼��־Ȩ�ޣ�");

	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("LogRecordThreadProc->:ֹͣ��"));
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
		WaitForSingleObject(m_hLogSemapShared, INFINITE);//�ȴ����н��̷���Щ��־���ļ����ź�

		WaitForSingleObject(m_hLogMutex, INFINITE);//��ռ����ڴ�
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
						,(((p->bDirect & 0x02) == 1) ? L"����" : L"����"), p->iLengthSum
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
						, (((p->bDirect & 0x02) == 1) ? L"����" : L"����"), p->iLengthSum
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

//����־��ӵ������У���֪ͨ�߳�ȡ�����档
//kind				��־����		
//descript			����
//session			�Ự���׵�ַ��ΪNULL�����
//direct			����0���գ�1����
//plaintext			�Ƿ�������
//buffer			���ݵ��׵�ַ�����ΪNULL�򲻸���
//bufferLength		buffer�����ݵĳ���,bufferΪNULL���������Զ�����
//ע��
//	��������ʹ��m_csSession�ؼ���
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
	//�����Ȼ��map����Ȩ���жϿ��Է��١�ֱ��д��
	//����������ټ������
	EnterCriticalSection(&m_csPacketQueue);
	{
		m_PacketQueue.push(p);
	}
	LeaveCriticalSection(&m_csPacketQueue);

	ReleaseSemaphore(m_hLogSemapLocal, 1, NULL);
	return 1;
}


//ͬ��ʱ���̣߳���ʱ����
DWORD WINAPI TimerThreadProc(
	LPVOID lpParam
)
{
	DS2(m_sProcessName, _T("TimerThreadProc->:���̳߳ɹ�������..."));
	while (1)
	{
		EnterCriticalSection(&m_csThreadRun);
		{
			if (m_isThreadRun == FALSE)
			{
				DS2(m_sProcessName, _T("TimerThreadProc->:ֹͣ��"));
				LeaveCriticalSection(&m_csThreadRun);
				return 0;
			}
		}
		LeaveCriticalSection(&m_csThreadRun);

		WaitForSingleObject(m_htTimer, INFINITE);//ÿ����ʱ������ʱ�Ż�����ִ��

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



//���ϵͳĬ�ϵ�spi�����ṩ�ߵ�dll·��
//�����ڰ�װʱ�滻��ϵͳ�ṩ��Ĭ�ϵ�spi�����ߵ�·�����������˱��ݡ���ô����ͻ�ȡ���ݵ�ԭʼspi��dll·��
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
	//�������ݵ�ע�������Ѱ��
	//1.��ָ����ע���������ִ�Сд
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp"), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return false;
	//2.ö��ָ���Ĵ�ע����������ú���ÿ�ε���ʱ�������һ�����������
	while (RegEnumKey(hKey, index++, szSubkey, MAX_PATH) == ERROR_SUCCESS)
	{
		//3.������
		if (RegOpenKeyEx(hKey, szSubkey, 0, KEY_READ, &hSubkey) != ERROR_SUCCESS)
			continue;
		//4.��ѯָ���ļ���ֵ
		if (RegQueryValueEx(hSubkey, _T("PackedCatalogItem"), 0, NULL, ItemValue, &ItemSize) || !Char8ToUnicode16((char *)ItemValue, szTmp, MAX_PATH) || ExpandEnvironmentStrings(szTmp, sPathName, MAX_PATH) == 0)
			continue;
		mProtocolInfo = (WSAPROTOCOL_INFOW*)(ItemValue + MAX_PATH);
		//5.�ж�����������
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
	DS2(m_sProcessName, _T("GetHookProviderDllPath�����pathʧ�ܣ�������"));
	return false;
}


//TCP�ķ�����ÿ����һ������ʱ���øú���
//���ݲ���lpfnConditionָ�������������ķ���ֵ�������Ľ���һ��Socket����,�����ⲿ�����ӣ������Ƿ�����
//���������������ⴴ��һ��Socket��Ȼ��socket����socket���в������������߽�������
//���û�д��󣬷��ؽ��ܵ�socket��־�����򷵻�INVALID_SOCKET,������󱣴��ڲ���lpErrno��
//ע�⣺
//	TCP�ķ�����ÿ����һ������ʱ���ã�������˫������Ϣ������news��
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

//TCP�Ŀͻ������ӷ�����ʱһ������õĺ���,UDP�Ŀͻ��˿��ܻ����
//��������ͬ��Socket֮������ӣ�Ȼ�󽻻��������ݣ����������ṩ�������ȷ������ķ�������
//�����ɹ�����0�����򷵻�SOCKET_ERROR,����Ĵ�����뱣���ڲ���lpErrno��
//ע�⣺
//	TCP�Ŀͻ������ӷ�����ʱһ������õĺ���,UDP�Ŀͻ��˿��ܻ����(�ͻ��˱�д�߷��µ�ʱ��)
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

//�ر�һ��Socket����
//�����ɹ�����0�����򷵻�SOCKET_ERROR,����Ĵ�����뱣���ڲ���lpErrno��
//ע�⣺
//	������udp����TCP�������ܻ���ôκ��������ر�socket
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
			DS2D1(m_sProcessName, _T("WSPCloseSocket:�Ͽ�һ��Socket���ܹ�:"), (m_Session.size()));
		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}

//����һ��DWORD
DWORD SwapDWORD(DWORD t)
{
	return t << 24 | ((t & 0x0000ff00) << 8) | ((t & 0x00ff0000) >> 8) | ((t & 0xff000000) >> 24);
}


//�ж�һ��Socket�Ƿ����ڼӹ̵ķ�Χ��
//���򷵻�1���񷵻�0
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
		for (DWORD i = 0; i < m_LocalGlobVar.reinProcessWhiteLen; i++)//������������
		{
			if (m_crc32 == m_LocalGlobVar.reinProcessWhite[i].crc32)
				return 0;
		}
		for (DWORD i = 0; i < m_LocalGlobVar.reinPortWhiteLen; i++)//���ض˿ڰ�����
		{
			if (r == m_LocalGlobVar.reinPortWhite[i] || l == m_LocalGlobVar.reinPortWhite[i])
				return 0;
		}
		k = SwapDWORD(*(DWORD*)&(se->ulLocalIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinLocalIPWhiteLen; i++)//����ip������
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
		for (DWORD i = 0; i < m_LocalGlobVar.reinRemoteIPWhiteLen; i++)//Զ��ip������
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

		for (DWORD i = 0; i < m_LocalGlobVar.reinProcessLen; i++)//������
		{
			if (m_crc32 == m_LocalGlobVar.reinProcess[i].crc32)
				return 1;
		}
		for (DWORD i = 0; i < m_LocalGlobVar.reinPortLen; i++)//�˿�
		{
			if (r == m_LocalGlobVar.reinPort[i] || l == m_LocalGlobVar.reinPort[i])
				return 1;
		}
		k = SwapDWORD(*(DWORD*)&(se->ulLocalIP));
		for (DWORD i = 0; i < m_LocalGlobVar.reinLocalIPLen; i++)//����ip
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
		for (DWORD i = 0; i < m_LocalGlobVar.reinRemoteIPLen; i++)//Զ��ip
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
*����aes����ʹ�õ���16�ֽ�Ϊһ����м��ܣ���˽��������趨
*���ݼ��ܸ�ʽ
*	1�ֽ�			1�ֽ�				2�ֽ�			2�ֽ�				2�ֽ�			    n�ֽ�		m+n-8�ֽ�
*	1�ֽ�			 3+5				2�ֽ�			2�ֽ�				2�ֽ�			  n+m-7�ֽ�		   ���
*	 E9			��־λ+��չ����m			�����		ԭʼ���ݳ���n				ʱ���              ԭʼ����			0
*													*****************************************************************
*																			������
*ע�⣺
*		�ܳ�����m+n��m+n-8��Ϊ�����0�Ĳ��֣�����Ϊ���ܹ�����AES������Ҫ
*����չ����m�ļ��㷽ʽ���£�
*		���n<12		m=12+8-n		��	m+n=20
*		���n>=12	m=8
*����������Ĳ���16�ֽڵĵط���������aes���ܣ�����ԭʼ���ݣ��������ֽ�֮����Ϊ��ʼ���������������
*
*3����־λ�Ľ��ͣ�������λ��
*					5.���������(���»Ự��Կ)
*					6.��������Կ
*					7.����
*************************************************************************/

//�����Ҫ��չ�ĳ���
//������
//	len		ԭʼ����
BYTE GetExtenedLength(
	int len
)
{
	if (len < 12)
		return 12 + 8 - len;
	else
		return 8;
}


//�Դ����ܵ����ݽ��м��ܲ���
//����
//	s			�����ܵ�socket��������ѯ���޸ĻỰ��Ϣ
//	sendbuf		�����ܵķ��ͻ������׵�ַ
//	sendbuflen	�����ܵ����ݻ��������ܳ���(��λ���ֽ�)
//ע�⣺
//	��������չ�ĳ����ɺ�EXTENDDATALENGTH��ȷ��
//���أ�
//	��������˼��ܷ��ش���0���������û�м��ܲ�����0
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
					MasterEncrypt(m_dKeyExpand, m_Session[s]->uRandom, m_Session[s]->key);//�����µĻỰ��Կ
					KeyExpansion(m_Session[s]->key, m_Session[s]->w);//���»Ự��Կ����չ��Կ
				}
				//LeaveCriticalSection(&m_csLocalGlob);
				sendbuf[1] |= 0x20;//������Կ
			}
			else if (m_Session[s]->uRandom == 0)
			{
				m_Session[s]->uRandom = (rand() + rand()) / 2;
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, m_Session[s]->uRandom, m_Session[s]->key);//�����µĻỰ��Կ
					KeyExpansion(m_Session[s]->key, m_Session[s]->w);//���»Ự��Կ����չ��Կ
				}
				//LeaveCriticalSection(&m_csLocalGlob);
				sendbuf[1] |= 0x20;//������Կ
			}
			else
			{
				sendbuf[1] |= 0x40;//������һ�ν��
			}
			//0ffset=6
			*(USHORT*)(sendbuf + 6) = m_Session[s]->dDuration;//ʱ���
			DS2I1(m_sProcessName, _T("ReinforceSend���ɵ�dDuration="), m_Session[s]->dDuration);
			//offset=2
			*(USHORT*)(sendbuf + 2) = m_Session[s]->uRandom;//�����
			DS2I1(m_sProcessName, _T("ReinforceSend���ɵ�random="), m_Session[s]->uRandom);
			//�ضϼ���
			int Remainder = (sendbuflen - 4) % 16;//����
			int mod = (sendbuflen - 4) / 16;//��
			for (int i = 0; i < Remainder; i++)//���µĲ��ּ���
			{
				*(sendbuf + 4 + 16 * mod + i) ^= *(sendbuf + 4 + i);
			}
			for (int i = 0; i < mod; i++)//���벿�ּ���
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


//�Դ�Զ���յ������ݽ������ݽ��ܲ����������ܺ�����ݸ��Ƶ�ָ���Ļ�������
//������
//	s					�����ܵ�socket��������ѯ���޸ĻỰ��Ϣ
//	lpRecvbuf			�����ܵ����ݻ��������ݵ���Ϣ
//	lpRealRecvBuf		���ܺ󱣴����ݵĻ�������Ϣ
//	bufferCount			�������ĸ���
//	recvBytesLen		���յ����ݵ��ֽ�����������ɺ���޸���ֵΪ���ܺ�����ݳ���
//ע�⣺
//	������ɺ���ʵ�����ݽ�������lpRealRecvBuf�����Ļ�������
//	recvBytesLen��ֵ������ΪlpRealRecvBuf�ṹ���б���Ľ��ܺ��������
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
	PBYTE	pBuff = pSession->buffer;//���������
	DWORD	lenBuff = pSession->bufferLen;//���������
	DWORD	buffOffest = pSession->buffOffset;//���������ʼλ��
	*/
	int ret = 0;//�ɹ����ܵĴ���
	int offSet = 0;//��recvbuf��ƫ��
	DWORD leftBytesLen = *recvBytesLen;//ʣ����������ݳ���
	DWORD frameLength;//��֡�����ܵ����ݳ���
	int remainder;//��֡���ȵ�����
	int mod;//��֡���ȵ���
	int len;//ԭʼ���ݳ���
	*recvBytesLen = 0;
	int k = 0;
	if (leftBytesLen == 0)
		return 0;
	//��¼��log
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

	//����
	BYTE *recvbuf = (BYTE*)lpRecvbuf[0].buf;
	if (bufferCount != 1)
	{
		if (pSession->bIsAlloc == 0)
		{
			//Ϊ��session�������ʹ�õĻ�����������8��ҳ��
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
				MasterEncrypt(m_dKeyExpand, pSession->uRandom, pSession->key);//�����µĻỰ��Կ
				KeyExpansion(pSession->key, pSession->w);//���»Ự��Կ����չ��Կ
				//AddLogMsg(LOG_COMMENT, "Recv data first time, updata session key", pSession, 0, FALSE, 0, 0);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		else if (pSession->uRandom != *(USHORT*)(recvbuf + offSet + 2))//�����
		{
			pSession->uRandom = *(USHORT*)(recvbuf + offSet + 2);
			pSession->dDuration = 0;
			//EnterCriticalSection(&m_csLocalGlob);
			{
				MasterEncrypt(m_dKeyExpand, pSession->uRandom, pSession->key);//�����µĻỰ��Կ
				KeyExpansion(pSession->key, pSession->w);//���»Ự��Կ����չ��Կ
				AddLogMsg(LOG_COMMENT, "Recv delay time out of range and updata session key", pSession, 0, FALSE, 0, 0);
			}
			//LeaveCriticalSection(&m_csLocalGlob);
		}
		if (pSession->dDuration > MAX_USEFULL_TIME)
			pSession->dDuration = 0;
		if (leftBytesLen < 4 + 16)//ʣ�³��Ȳ����Խ���
		{
			AddLogMsg(LOG_ERROR, "Recv length is not enough to be decrypt", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			LeaveCriticalSection(&m_csSession);
			goto RETURN;
		}
		//�Լ��ܵ�ǰ16�ֽڽ��н���
		Decrypt(recvbuf + offSet + 4, pSession->w);
		len = *(USHORT*)(recvbuf + offSet + 4);
		frameLength = len + (recvbuf[offSet + 1] & 0x1f) - 4;//n+m-4
		int timeError = pSession->dDuration - (*(USHORT*)(recvbuf + offSet + 6));//����ʱЧ��
		DS2I1(m_sProcessName, L"timeError=", timeError);
		if (timeError > TIME_ERROR || timeError < -TIME_ERROR)
		{
			DS2I1(m_sProcessName, L"timeError=", timeError);
			AddLogMsg(LOG_ALERT, "Received data cannot be decrypted because the time check is incorrect but 16 bytes have been decrypted", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			goto RETURN;//ֱ�ӷ���
		}
		if (frameLength > leftBytesLen)//���ݳ��ȴ��󣬲�ͨ��
		{
			AddLogMsg(LOG_ERROR, "Received data cannot be decrypted because the data length is incorrect but 16 bytes have been decrypted", pSession, 0, FALSE, (char*)(recvbuf + offSet), leftBytesLen);
			goto RETURN;//ֱ�ӷ���
		}
		remainder = frameLength % 16;//����
		mod = frameLength / 16;//��
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
			//������ɣ����Ƶ�������
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
		//׼����һ֡
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


//TCP��ʹ�ã�������Զ�˺ͱ��ص�ip��port����Ϣ��Acceptʹ���²�����socket��Ϊ����s��connect��ʹ��s��Ϊ����s
//direction�����������accept����0����ʾ�����Ƿ������������connect����1����ʾ�����ǿͻ���
//����ֵ��
//		�����Ҫ�ӹ̷��ط�0������Ҫ�ӹ��򷵻�0.
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
				DS2D1(m_sProcessName, _T("SessionTcp����һ������Socket���ܹ�:"), (m_Session.size()));
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, se->uRandom, se->key);//�����µĻỰ��Կ
					KeyExpansion(se->key, se->w);//���»Ự��Կ����չ��Կ
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			m_Session.emplace(s, se);
			ret = se->bEc;
			DS2D1(m_sProcessName, _T("SessionTcp�ܹ�:"), (m_Session.size()));
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

//UDP��sendto��recvfromʹ�á�
//���̣�
//	�ж��Ƿ�����session
//	����
//		���������Ϣ
//	����
//		�����Session���ж��Ƿ����
//	�����Ƿ����
//ע��s���ڸ��±�����Ϣ��name���ڸ���Զ����Ϣ.UDP���޷��ж�direction
//����ֵ��
//		�����Ҫ�ӹ̷��ط�0������Ҫ�ӹ��򷵻�0.
int SessionUdp(
	SOCKET							s,
	const struct sockaddr FAR		*name
)
{
	//ע��UDP���Թ㲥(INADDR_BROADCAST 255.255.255.255:XX)��Ⱥ��(INADDR_ANY 0.0.0.0:XX,ָѡ�������罻��������������IP��ַ)
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
				DS2D1(m_sProcessName, _T("SessionUDP���Ӽ������ӣ��ܹ�:"), (m_Session.size()));
				//EnterCriticalSection(&m_csLocalGlob);
				{
					MasterEncrypt(m_dKeyExpand, se->uRandom, se->key);
					KeyExpansion(se->key, se->w);
				}
				//LeaveCriticalSection(&m_csLocalGlob);
			}
			m_Session.emplace(s, se);
			DS2D1(m_sProcessName, _T("SessionUdp�ܹ�:"), (m_Session.size()));
			ret = m_Session[s]->bEc;
		}
	}
	LeaveCriticalSection(&m_csSession);
	return ret;
}


/*
������Ͳ���������ɽ�����0,����lpNumberOfBytesSent������ʵ�ʷ��͵��ֽ���
�������ɹ��������ص���������������SOCKET_ERROR,���Ҵ������lpErrno=WSA_IO_PENDING,����lpNumberOfBytesSent���ᱣ��ʵ�ʷ��͵��ֽ���
	���첽������ɺ�ϵͳ�Զ�����WSPGetOverlappedResult��������֪������ϣ���ͨ������lpcbTransfer��֪ʵ�ʷ��͵��ֽ���,�䷵��true�����ص����ͳɹ��������ص�����ʧ�ܣ�
����������£�
	���lpOverlapped==NULL�����ͽ���������ʽ����
	���lpOverlapped!=NULL�����ͽ����ص�IO����
		���lpCompletionRoutine!=NULL��������lpOverlapped->hEvent����������Ϻ�ϵͳ�����²���
			�ȵ���lpCompletionRoutine��Ӧ�ó�����ܻ��ٵ���WSPGetOverlappedResult
		���lpCompletionRoutine==NULL����������Ϻ������²���
			��hEvent��������¼���Ӧ�ó�������ٵ���WSPGetOverlappedResult
ע�⣺
	������Ӧ�ò���ϵͳ�ĵ���Լ��������Ӧ�ò���Բ�����Լ�����������趨event�����Ҳ�����getoverlappedresultҲ���趨���ʵ�������Ӧ�ó�����ʹ�÷����ͻ�������������������������⡣
	���Ӧ�ò����첽����δ��ɼ���ʹ�û��ͷ��˷��ͻ��������������쳣������Ͻ��ϲ����û�Ӧ�ð��յ���Լ����������
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
	int originalSendBytesLen = 0;//������ƭ�ϲ�Ӧ��
	lpBuffersSendTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
	for (DWORD i = 0; i < dwBufferCount; i++)
	{
		buff = (char*)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + GetExtenedLength(lpBuffers[i].len)));
		buff[0] = 0xe9;//��־
		buff[1] = GetExtenedLength(lpBuffers[i].len);//��չ����
		*(USHORT*)(buff + 4) = (USHORT)lpBuffers[i].len;//ԭʼ����
		originalSendBytesLen += lpBuffers[i].len;
		memcpy(buff + 8, lpBuffers[i].buf, lpBuffers[i].len);//ԭʼ����
		lpBuffersSendTmp[i].buf = buff;
		lpBuffersSendTmp[i].len = buff[1] + lpBuffers[i].len;
		ReinforceSend(s, (BYTE*)buff, lpBuffersSendTmp[i].len);//����
	}
	int ret = 0;
	if (lpCompletionRoutine != NULL)
		ret = m_NextProcTable.lpWSPSend(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, CompletionRoutineSend, lpThreadId, lpErrno);
	else
		ret = m_NextProcTable.lpWSPSend(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//ʹ�����ص�I/O����
	{
		POVERLAPPEDSESSIONSEND pOverlappedSession = (POVERLAPPEDSESSIONSEND)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONSEND));
		pOverlappedSession->dwBufferCountSend = dwBufferCount;
		pOverlappedSession->lpBuffersSend = lpBuffersSendTmp;
		pOverlappedSession->lpCompletionRoutineSend = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->originalSendBytesLen = originalSendBytesLen;
		EnterCriticalSection(&m_csOverlappedSessionSend);
		{
			if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())//�Ѵ��ڣ�ɾ��֮����־�û��������������û������涨�����򽫿��ܱ�������Ϊ����δ��ɣ����������ͷ�
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
		//��¼����������
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
	else//������ʽ�ɹ����ͻ��߷���ʧ�ܣ�
	{
		for (DWORD i = 0; i < dwBufferCount; i++)
			HeapFree(m_hHeapOverlappedSessionSend, 0, lpBuffersSendTmp[i].buf);
		if (ret == 0)
		{
			//��¼����������
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
	int originalSendBytesLen = 0;//������ƭ�ϲ�Ӧ��
	lpBuffersSendTmp = (LPWSABUF)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(WSABUF)*dwBufferCount);
	for (DWORD i = 0; i < dwBufferCount; i++)
	{
		buff = (char*)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(char)*(lpBuffers[i].len + GetExtenedLength(lpBuffers[i].len)));
		buff[0] = 0xe9;//��־
		buff[1] = GetExtenedLength(lpBuffers[i].len);//��չ����
		*(USHORT*)(buff + 4) = (USHORT)lpBuffers[i].len;//ԭʼ����
		originalSendBytesLen += lpBuffers[i].len;
		memcpy(buff + 8, lpBuffers[i].buf, lpBuffers[i].len);//ԭʼ����
		lpBuffersSendTmp[i].buf = buff;
		lpBuffersSendTmp[i].len = buff[1] + lpBuffers[i].len;
		ReinforceSend(s, (BYTE*)buff, lpBuffersSendTmp[i].len);//����
	}
	int ret = 0;
	if (lpCompletionRoutine != NULL)
		ret = m_NextProcTable.lpWSPSendTo(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, CompletionRoutineSend, lpThreadId, lpErrno);
	else
		ret = m_NextProcTable.lpWSPSendTo(s, lpBuffersSendTmp, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine, lpThreadId, lpErrno);
	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//ʹ�����ص�I/O����
	{
		POVERLAPPEDSESSIONSEND pOverlappedSession = (POVERLAPPEDSESSIONSEND)HeapAlloc(m_hHeapOverlappedSessionSend, HEAP_ZERO_MEMORY, sizeof(OVERLAPPEDSESSIONSEND));
		pOverlappedSession->dwBufferCountSend = dwBufferCount;
		pOverlappedSession->lpBuffersSend = lpBuffersSendTmp;
		pOverlappedSession->lpCompletionRoutineSend = lpCompletionRoutine;
		pOverlappedSession->s = s;
		pOverlappedSession->originalSendBytesLen = originalSendBytesLen;
		EnterCriticalSection(&m_csOverlappedSessionSend);
		{
			if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())//�Ѵ��ڣ�ɾ��֮.��־�û��������������û������涨�����򽫿��ܱ�������Ϊ����δ��ɣ����������ͷ�
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
		//��¼����������
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
	else//������ʽ�ɹ����ͻ��߷���ʧ�ܣ�
	{
		for (DWORD i = 0; i < dwBufferCount; i++)
			HeapFree(m_hHeapOverlappedSessionSend, 0, lpBuffersSendTmp[i].buf);
		if (ret == 0)
		{
			//��¼����������
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
					cbTransferred = m_OverlappedSessionSend[lpOverlapped]->originalSendBytesLen;//��ƭ�ϲ�Ӧ��
				}
			}
			LeaveCriticalSection(&m_csSession);

			//����Ӧ�ò����ṩ��Ĭ���ص�I/O����
			if (m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend != NULL)
				m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend(dwError, cbTransferred, lpOverlapped, dwFlags);
			//�ͷŻ�����
			for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
			{
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
			m_OverlappedSessionSend.erase(lpOverlapped);
			DS2D1(m_sProcessName, _T("CompletionRoutineSendɾ��һ���ص���Ϣ������"), (m_OverlappedSessionSend.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionSend);
}


/*
˵����
����������Ľ��գ���ô��������������ϲŷ��ز���lpNumberOfBytesRecvdָʾ���յ��ֽ���
������ص���ʽ����(ҪʹlpOverlapped!=NULL�Ż����ص���ʽ��������)
	����ص�����������ɣ��򷵻�0��������lpNumberOfBytesRecvd
	��������޷�������ɣ��������ص�����������error��lpNumberOfBytesRecvd��ֵ��Ч������
		����ص���������ʧ�ܣ�*leErron��ֵ����WSA_IO_PENDING������Ҳ�����в�����ɵ�֪ͨ
		����ص����������ɹ���*leErron==WSA_IO_PENDING
			���lpCompletionRoutine!=NULL,��ʱ������ص�������ϵͳ������lpCompletionRoutine��Ӧ�ó�����Ե���WSPGetOverlappedResult��ѯ�յ����ֽ���
			���lpCompletionRoutine==NULL,��ʱlpOverlapped->hEventӦ������Ч���¼��ں˶��󣬵�ϵͳ���recv������֪ͨ���¼�(��ʱӦ�ò���waitforsingleobj)��
				Ӧ���յ����¼��󷽿ɼ���ִ�У���ʱӦ�ó��������õ���WSPGetOverlappedResult����ѯ�����յ����ֽ���
ע��
	Ӧ�ò����WSARecv/WSARecvFromʱ�ɲ����첽��ʽ������recv/recvfromʱ������ͬ��������ɲο�msdn
	WSPRecvFrom�������÷��뱾������ͬ��
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
	/*	ע�⣺����MSDN����ʵ�鶼��֤�����½��ۣ�
		���յ������ݰ���˳����仺���������buff���У������һ������û�д�������һ�����鲻�������䡣��һ������������һ������Ż������䡣
		�������lpBuffers[0].buff,��������Ҵ���lpBuffers[1].buffʱ�������lpBuffers[1].buff��ֱ���������������
			1.���ݽ�����ϣ�������û������,���յ�������Ϊ�������ġ�
			2.���еĻ������������ˣ�ϵͳ����һ��������û�н����û����û�������ݺܿ��ܲ�������
		���ԣ�Ӧ�ò�һ����Ҫ��recv�����ݽ������
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
			if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())//ɾ��֮ǰ�ļ�¼��������ڵĻ�
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
	else//������ʽ���ա��ص���ʱ���յ�������� ���� ���ճ��ִ���
	{
		if (reinforince != 0)
		{
			if (ret == 0)
			{
				//�ӹ̵� ��¼������ֽ���
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
					}
				}
				LeaveCriticalSection(&m_csSession);
			}
			//�ͷŶ��������
			ReinforceRecv(s, lpBuffersRecvTmp, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd);
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp);
		}
		else if (ret == 0)//���ӹ̣�����δ����
		{
			//��¼��־
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

	if (*lpErrno == WSA_IO_PENDING && ret == SOCKET_ERROR)//�첽ģʽ
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
			if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())//ɾ��֮ǰ�ļ�¼��������ڵĻ�
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
	else//������ʽ���ա��ص���ʱ���յ�������� ���� ���ճ��ִ���
	{
		if (reinforince != 0)
		{
			if (ret == 0)
			{
				//�ӹ̵� ��¼������ֽ���
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpNumberOfBytesRecvd;
					}
				}
				LeaveCriticalSection(&m_csSession);
			}
			//�ͷŶ��������
			ReinforceRecv(s, lpBuffersRecvTmp, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd);
			for (DWORD i = 0; i < dwBufferCount; i++)
			{
				HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionRecv, 0, lpBuffersRecvTmp);
		}
		else if (ret == 0)//���ӹ̣�����δ����
		{
			//��¼��־
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


//�첽recv����ɲ���ʱ��ѡ�Ļص�����(���Ӧ�ó���ѡ�������ʵ�����ַ�ʽ����ѯ�������Ļ�����
//���ǵ��������Զ��̷߳�ʽ֪ͨӦ�ò㣬���Ӧ�ò���Ҫ����ͬ�����⣬ʹ�ñ���ѶȼӴ󣬹ʺ��ٻ�ʹ�ô˷�����
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
				//��¼����������
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(m_OverlappedSessionRecv[lpOverlapped]->s) != m_Session.end())
					{
						m_Session[m_OverlappedSessionRecv[lpOverlapped]->s]->ulRecvData += cbTransferred;
					}
				}
				LeaveCriticalSection(&m_csSession);
				//���ܲ���������
				ReinforceRecv(m_OverlappedSessionRecv[lpOverlapped]->s, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack, m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv, &cbTransferred);
				//for (DWORD i = 0; i < m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv; i++)
				//{
				//	ReinforceRecv(m_OverlappedSessionRecv[lpOverlapped]->s,
				//		(BYTE*)m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp[i].buf,
				//		&cbTransferred,
				//		(BYTE*)m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].buf,
				//		m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack[i].len);
				//}
				//����Ӧ�ò����ṩ��Ĭ���ص�I/O����
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(dwError, cbTransferred, lpOverlapped, dwFlags);
				//�ͷŻ���
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
				//����Ӧ�ò����ṩ��Ĭ���ص�I/O����
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(dwError, cbTransferred, lpOverlapped, dwFlags);
				//��¼��־
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
				//�ͷ��ص��ṹ��
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			DS2D1(m_sProcessName, _T("CompletionRoutineRecvɾ��һ���ص���Ϣ������"), (m_OverlappedSessionRecv.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionRecv);
}

//ʹ�����첽�׽��ֵ�Ӧ�ó���ͨ������ô˺�����ѯ�첽������������ж��첽IO�Ƿ������
//Ӧ�ó�����ʹ�����ص�I/Oʱ����һ�ַ�ʽ����ͨ�����ô˺�������ѯ�첽�����Ƿ���ɡ�
BOOL WSPAPI WSPGetOverlappedResult(
	_In_  SOCKET          s,
	_In_  LPWSAOVERLAPPED lpOverlapped,
	_Out_ LPDWORD         lpcbTransfer,
	_In_  BOOL            fWait,
	_Out_ LPDWORD         lpdwFlags,
	_Out_ LPINT           lpErrno
)
{
	DS2(m_sProcessName, _T("WSPGetOverlappedResult����ִ��..."));
	BOOL ret = m_NextProcTable.lpWSPGetOverlappedResult(s, lpOverlapped, lpcbTransfer, fWait, lpdwFlags, lpErrno);
	if (ret == FALSE)
		return ret;

	EnterCriticalSection(&m_csOverlappedSessionSend);
	{
		if (m_OverlappedSessionSend.find(lpOverlapped) != m_OverlappedSessionSend.end())
		{
			//��¼����������
			EnterCriticalSection(&m_csSession);
			{
				if (m_Session.find(s) != m_Session.end())
				{
					*lpcbTransfer = m_OverlappedSessionSend[lpOverlapped]->originalSendBytesLen;
				}
			}
			LeaveCriticalSection(&m_csSession);
			//����Ӧ�ò�����ṩ��Ĭ���ص�I/O�Ļص�����
			if (m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend != NULL)
				m_OverlappedSessionSend[lpOverlapped]->lpCompletionRoutineSend(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
			//�ͷŻ�����
			for (DWORD i = 0; i < m_OverlappedSessionSend[lpOverlapped]->dwBufferCountSend; i++)
			{
				HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend[i].buf);
			}
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]->lpBuffersSend);
			HeapFree(m_hHeapOverlappedSessionSend, 0, m_OverlappedSessionSend[lpOverlapped]);
			m_OverlappedSessionSend.erase(lpOverlapped);
			DS2D1(m_sProcessName, _T("WSPGetOverlappedResultɾ��һ��send�ص���Ϣ������"), (m_OverlappedSessionSend.size()));
		}
	}
	LeaveCriticalSection(&m_csOverlappedSessionSend);


	EnterCriticalSection(&m_csOverlappedSessionRecv);
	{
		if (m_OverlappedSessionRecv.find(lpOverlapped) != m_OverlappedSessionRecv.end())
		{
			if (m_OverlappedSessionRecv[lpOverlapped]->dIsReinforce != 0)
			{
				//��¼����������
				EnterCriticalSection(&m_csSession);
				{
					if (m_Session.find(s) != m_Session.end())
					{
						m_Session[s]->ulRecvData += *lpcbTransfer;
					}
				}
				LeaveCriticalSection(&m_csSession);
				//���ܲ���������
				ReinforceRecv(s, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvTmp, m_OverlappedSessionRecv[lpOverlapped]->lpBuffersRecvBack, m_OverlappedSessionRecv[lpOverlapped]->dwBufferCountRecv, lpcbTransfer);
				//����Ӧ�ò�����ṩ��Ĭ���ص�I/O�Ļص�����
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
				//�ͷŻ�����
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
				//����Ӧ�ò�����ṩ��Ĭ���ص�I/O�Ļص�����
				if (m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv != NULL)
					m_OverlappedSessionRecv[lpOverlapped]->lpCompletionRoutineRecv(*lpErrno, *lpcbTransfer, lpOverlapped, *lpdwFlags);
				//��¼��־
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
				//�ͷ��ص��ṹ��
				HeapFree(m_hHeapOverlappedSessionRecv, 0, m_OverlappedSessionRecv[lpOverlapped]);
				m_OverlappedSessionRecv.erase(lpOverlapped);
			}
			DS2D1(m_sProcessName, _T("WSPGetOverlappedResultɾ��һ��recv�ص���Ϣ������"), (m_OverlappedSessionRecv.size()));
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
		//�ͷ����е�session
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
		//�ͷ����е��ص�I/O Recv
		OVERLAPPED_MAPRECV::iterator it = m_OverlappedSessionRecv.begin();
		while (it != m_OverlappedSessionRecv.end())
		{

			//�ͷŻ�����
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
		//�ͷ����е��ص�I/O Send
		OVERLAPPED_MAPSEND::iterator it = m_OverlappedSessionSend.begin();
		while (it != m_OverlappedSessionSend.end())
		{
			//�ͷŻ�����
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
