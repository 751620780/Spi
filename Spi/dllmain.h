/***************************************************************************************结构体等定义***************************************************************************/
typedef void (CALLBACK *PCOMPLETIONROUTINE)(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags
	);
/**********************************************************************************导出函数参见Spi.def文件**********************************************************************************/
BOOL WINAPI DllMain(
	HINSTANCE	hModule,
	DWORD		ul_reason_for_call,
	LPVOID		lpReserved
);

int WSPAPI WSPStartup(
	WORD				wVersionRequested,
	LPWSPDATA			lpWSPData,
	LPWSAPROTOCOL_INFOW lpProtocolInfo,
	WSPUPCALLTABLE		UpcallTable,
	LPWSPPROC_TABLE		lpProcTable
);

bool GetHookProviderDllPath(
	WSAPROTOCOL_INFOW	*pProtocolInfo,
	TCHAR				*sPathName
);

int WSPAPI WSPCloseSocket(
	SOCKET s,
	LPINT  lpErrno
);

int WSPAPI WSPConnect(
	SOCKET                s,
	const struct sockaddr *name,
	int                   namelen,
	LPWSABUF              lpCallerData,
	LPWSABUF              lpCalleeData,
	LPQOS                 lpSQOS,
	LPQOS                 lpGQOS,
	LPINT                 lpErrno
);

SOCKET WSPAPI WSPAccept(
	SOCKET          s,
	struct sockaddr *addr,
	LPINT           addrlen,
	LPCONDITIONPROC lpfnCondition,
	DWORD           dwCallbackData,
	LPINT           lpErrno
);

DWORD WINAPI LogThreadProc(LPVOID lpParam);
DWORD WINAPI GlobThreadProc(LPVOID lpParam);
DWORD WINAPI LogRecordThreadProc(LPVOID lpParam);
DWORD  WINAPI TimerThreadProc(LPVOID lpParam);
bool  Char8ToUnicode16(char *lpChar, TCHAR *lpTchar, DWORD lengthTchar);
bool Unicode16ToChar8(TCHAR *lpTchar, char *lpAnsi, DWORD lengthChar);
void Debug(const char *format, ...);

/***********************************************************************对Hook的WSP进行加固***************************************************************************/
int WSPAPI WSPSend(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesSent,
	DWORD                              dwFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID                      lpThreadId,
	LPINT                              lpErrno
);

int WSPAPI WSPSendTo(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesSent,
	DWORD                              dwFlags,
	const struct sockaddr              *lpTo,
	int                                iTolen,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID                      lpThreadId,
	LPINT                              lpErrno
);

int WSPAPI WSPRecv(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesRecvd,
	LPDWORD                            lpFlags,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID                      lpThreadId,
	LPINT                              lpErrno
);


int WSPAPI WSPRecvFrom(
	SOCKET                             s,
	LPWSABUF                           lpBuffers,
	DWORD                              dwBufferCount,
	LPDWORD                            lpNumberOfBytesRecvd,
	LPDWORD                            lpFlags,
	struct sockaddr                    *lpFrom,
	LPINT                              lpFromlen,
	LPWSAOVERLAPPED                    lpOverlapped,
	LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine,
	LPWSATHREADID                      lpThreadId,
	LPINT                              lpErrno
);

BOOL WSPAPI WSPGetOverlappedResult(
	SOCKET          s,
	LPWSAOVERLAPPED lpOverlapped,
	LPDWORD         lpcbTransfer,
	BOOL            fWait,
	LPDWORD         lpdwFlags,
	LPINT           lpErrno
);
int WSPAPI WSPCleanup(
	LPINT			lpErrno
);

void CALLBACK CompletionRoutineSend(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags
);
void CALLBACK CompletionRoutineRecv(
	DWORD dwError,
	DWORD cbTransferred,
	LPWSAOVERLAPPED lpOverlapped,
	DWORD dwFlags
);

/************************************************************************************加固函数*************************************************************************/

int		ReinforceSend(SOCKET s, BYTE  * sendbuf, int sendbuflen);
int		ReinforceRecv(SOCKET s, LPWSABUF lpRecvbuf, LPWSABUF lpRealRecvBuf, DWORD bufferCount, DWORD *recvBytesLen);
BYTE	GetExtenedLength(int len);
int		SessionTcp(SOCKET s, const struct sockaddr FAR *name, BYTE bDirection);
int		SessionUdp(SOCKET s, const struct sockaddr FAR *name);

