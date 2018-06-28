// Install.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <ws2spi.h>
#include <Winsock2.h>
#include <windows.h>
#include <io.h>
#include <stdio.h>
#include <tchar.h>
#pragma comment(lib, "ws2_32.lib" )
#pragma comment (lib,"Advapi32.lib")
#pragma warning(disable : 4996)

bool Unicode16ToChar8(TCHAR *lpTcharStr, char *lpAnsiStr, DWORD cbAnsiStr)
{
	//��ȡ�ֽڳ���   
	DWORD dLength = WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, NULL, 0, NULL, NULL);
	if (dLength > cbAnsiStr)
		return false;
	//��tcharֵ����_char
	if (WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, lpAnsiStr, dLength, NULL, NULL) == dLength)
		return true;
	return false;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		printf("OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))         // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("ERROR! The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

bool SaveReg(
	HKEY	hkey,//һ������ע�����ľ��������ע����һ�����ڵ�
	TCHAR	*sSubKey,//ע������������
	TCHAR	*lpSubKey,//��������������
	TCHAR	*sKey,//���������µļ���
	BYTE	*pBuffer,//��ֵ�����ݣ���������ָ��
	DWORD	dwBufSize,//��������С
	DWORD	ulType//��ֵ���ݵ�����
)
{
	HKEY	hKey;
	HKEY	hSubkey;
	DWORD	dwDisposition;

	if (RegCreateKeyEx(//����ָ����ע��������ü��Ѿ����ڣ��ù��ܽ���������ע�⣬���������ִ�Сд��
		hkey//һ���Ѿ��򿪵�ע�����ľ����
		, sSubKey//�˺����򿪻򴴽�����������ơ�
		, 0//�ò������������ұ���Ϊ��
		, NULL//�ò���������NULL
		, REG_OPTION_NON_VOLATILE//REG_OPTION_NON_VOLATILE��������ױ仯; ����Ĭ��ֵ����Ϣ�洢���ļ��У�����ϵͳ��������ʱ������
		, KEY_ALL_ACCESS//Ȩ��
		, NULL//
		, &hKey//�� or ������ľ��
		, &dwDisposition//���ز�����Ϣ�������Ǳ��������Ǳ���
	) != ERROR_SUCCESS)
		return false;
	if (RegCreateKeyEx(//����ָ����ע��������ü��Ѿ����ڣ��ù��ܽ���������ע�⣬���������ִ�Сд��
		hKey//һ���Ѿ��򿪵�ע�����ľ����
		, lpSubKey//�˺����򿪻򴴽�����������ơ�
		, 0//�ò������������ұ���Ϊ��
		, NULL//�ò���������NULL
		, REG_OPTION_NON_VOLATILE//REG_OPTION_NON_VOLATILE��������ױ仯; ����Ĭ��ֵ����Ϣ�洢���ļ��У�����ϵͳ��������ʱ������
		, KEY_ALL_ACCESS//Ȩ��
		, NULL//
		, &hSubkey//�� or ������ľ��
		, &dwDisposition//���ز�����Ϣ�������Ǳ��������Ǳ���
	) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return false;
	}

	if (RegSetValueEx(hSubkey, sKey, 0, ulType, pBuffer, dwBufSize) != ERROR_SUCCESS)
	{
		RegCloseKey(hSubkey);
		RegCloseKey(hKey);
		return false;
	}
	RegCloseKey(hSubkey);
	RegCloseKey(hKey);
	return true;
}

bool Install(TCHAR *path)
{
	//�ж���û�а�װ����
	HKEY hKeyBackup = NULL;
	if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
		HKEY_LOCAL_MACHINE//һ������ע�����ľ��������ע����һ�����ڵ�
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//ע������������
		, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
		, KEY_READ//�������Ȩ��
		, &hKeyBackup//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
	) == ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
	{
		printf("�Ѿ���װ��������ɾ����\n");
		RegCloseKey(hKeyBackup);
		return false;
	}
	CHAR szPath[MAX_PATH];
	Unicode16ToChar8(path, szPath, MAX_PATH);
	HKEY hkey = NULL;
	HKEY hsubKey = NULL;
	DWORD index = 0;
	TCHAR subKey[MAX_PATH];
	BYTE	ItemValue[sizeof(WSAPROTOCOL_INFOW) + MAX_PATH];
	DWORD	ItemSize = sizeof(WSAPROTOCOL_INFOW) + MAX_PATH;
	WSAPROTOCOL_INFOW *mProtocolInfo = NULL;
	__try {
		//��ע���
		if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
			HKEY_LOCAL_MACHINE//һ������ע�����ľ��������ע����һ�����ڵ�
			, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries")//ע������������
			, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
			, KEY_READ//�������Ȩ��
			, &hkey//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
		) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
		{
			printf("Error! Open reg error.\n");
			return false;
		}
		while (RegEnumKey(//ö��ָ���Ĵ�ע����������ú���ÿ�ε���ʱ�������һ�����������
			hkey//һ������ע�����ľ��
			, index++//Ҫ������hKey���Ӽ��������������״ε���RegEnumKey��������ֵӦΪ�� ��Ȼ��Ժ�����������
			, subKey//�û�������������Կ�����ƣ�������ֹ�Ŀ��ַ����ù���ֻ������Կ�����ƶ�������������Կ��θ��Ƶ���������
			, MAX_PATH//lpName����ָ��Ļ������Ĵ�С
		) == ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
		{
			if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
				hkey//һ������ע�����ľ��������ע����һ�����ڵ�
				, subKey//ע������������
				, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
				, KEY_ALL_ACCESS//�������Ȩ��
				, &hsubKey//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
			) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
			{
				printf("Error! Open sub reg error.\n");
				return false;
			}
			if (RegQueryValueEx(//������򿪵�ע����������ָ��ֵ���Ƶ����ͺ�����
				hsubKey//һ������ע�����ľ��
				, _T("PackedCatalogItem")//ע���ֵ�����ơ�
				, 0//ΪNULL
				, NULL//ʾ�洢��ָ��ֵ�е��������͵Ĵ��룬NULLΪ��ָ������
				, ItemValue//����ֵ���ݵĻ�������ָ�룬��ΪNULL
				, &ItemSize//lpData����ָ��Ļ������Ĵ�С�����ֽ�Ϊ��λ����������ɻ�ָʾʵ�ʳ���
			) != ERROR_SUCCESS)
			{
				printf("Error! Query sub reg error.\n");
				return false;
			}
			mProtocolInfo = (WSAPROTOCOL_INFOW*)(ItemValue + MAX_PATH);
			if (mProtocolInfo->ProtocolChain.ChainLen == 1 && mProtocolInfo->iAddressFamily == AF_INET)//ChainLen=1��ʾ�ǻ��������ṩ�ߣ�AF_INET��IPV4��ַ��
			{
				char subkeychar[MAX_PATH];
				Unicode16ToChar8(subKey, subkeychar ,MAX_PATH);
				printf("���ڶ�ע���%s������%s����...\n", "SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",subkeychar);
				//�Ƚ�һ����������·���Ƿ������ǵ�һ������һ���ͱ��ݣ�Ȼ����д��
				if (strcmp(szPath, (char*)ItemValue) != 0)
				{
					if (!SaveReg(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp"), subKey, _T("PackedCatalogItem"), ItemValue, sizeof(WSAPROTOCOL_INFOW) + MAX_PATH, REG_BINARY))
						printf("��������ʱ���ִ���\n");
					//д��
					memset(ItemValue, '\0', MAX_PATH);
					memcpy(ItemValue, szPath, strlen(szPath));
					if (RegSetValueEx(hsubKey, _T("PackedCatalogItem"), 0, REG_BINARY, ItemValue, ItemSize) != ERROR_SUCCESS)
						printf("�޸�ע����ֵʱ���ִ����޸�ʧ�ܣ�\n");
				}
			}
			RegCloseKey(hsubKey);
		}
	}
	__finally
	{
		if (NULL != hkey)
			RegCloseKey(hkey);
		return true;
	}

}
bool DeleteSubKeyTree(HKEY hKey, TCHAR *lpSubKey)
{
	HKEY hSubKey;
	TCHAR   szSubKey[MAX_PATH];
	if (RegOpenKeyEx(hKey, lpSubKey, 0, KEY_ALL_ACCESS, &hSubKey) != ERROR_SUCCESS)
	{
		printf("DeleteSubKeyTree->open reg error!\n");
		RegCloseKey(hSubKey);
		return false;
	}
	while (ERROR_SUCCESS == RegEnumKey(hSubKey, 0, szSubKey,MAX_PATH))
	{
		DeleteSubKeyTree(hSubKey, szSubKey);
	}
	
	if (ERROR_SUCCESS != RegDeleteKey(hKey, lpSubKey))
	{
		printf("DeleteSubKeyTree->delet reg error!\n");
		RegCloseKey(hSubKey);
		return false;
	}
	
	return true;
}
bool Remove()
{
	//�ж���û�а�װ����
	HKEY hKey = NULL;
	if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
		HKEY_LOCAL_MACHINE//һ������ע�����ľ��������ע����һ�����ڵ�
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//ע������������
		, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
		, KEY_READ//�������Ȩ��
		, &hKey//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
	) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
	{
		printf("û�а�װ�����޷���ԭ��\n");
		return false;
	}
	RegCloseKey(hKey);
	//��ʼ��ԭ
	HKEY hkeyBackUp = NULL;
	HKEY hSubkeyBackUp = NULL;
	//�򿪱��ݵ�ע�����
	if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
		HKEY_LOCAL_MACHINE//һ������ע�����ľ��������ע����һ�����ڵ�
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//ע������������
		, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
		, KEY_READ//�������Ȩ��
		, &hkeyBackUp//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
	) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
	{
		printf("�򿪱��ݵ�ע���ʱʧ�ܣ�\n");
		return false;
	}

	DWORD index = 0;
	TCHAR subKey[MAX_PATH];
	BYTE	ItemValue[sizeof(WSAPROTOCOL_INFOW) + MAX_PATH];
	DWORD	ItemSize = sizeof(WSAPROTOCOL_INFOW) + MAX_PATH;

	while (RegEnumKey(hkeyBackUp, index++, subKey, MAX_PATH) == ERROR_SUCCESS)
	{
		if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
			hkeyBackUp//һ������ע�����ľ��������ע����һ�����ڵ�
			, subKey//ע������������
			, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
			, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_READ//�������Ȩ��
			, &hSubkeyBackUp//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
		) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
		{
			RegCloseKey(hkeyBackUp);
			printf("�򿪱��ݵ�ע�������ʱʧ�ܣ�\n");
			return false;
		}
		if (RegQueryValueEx(hSubkeyBackUp, _T("PackedCatalogItem"), 0, NULL, ItemValue, &ItemSize) != ERROR_SUCCESS)
		{
			RegCloseKey(hSubkeyBackUp);
			RegCloseKey(hkeyBackUp);
			printf("��ѯ���ݵ�ע�������ʱʧ�ܣ�\n");
			return false;
		}
		if (!SaveReg(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"), subKey, _T("PackedCatalogItem"), ItemValue, sizeof(WSAPROTOCOL_INFOW) + MAX_PATH, REG_BINARY))
		{
			RegCloseKey(hSubkeyBackUp);
			printf("�����ݵ�ע�������д��ԭע���ʱʧ��!\n");
			return false;
		}
		RegDeleteKey(hSubkeyBackUp, _T("PackedCatalogItem"));
		RegCloseKey(hSubkeyBackUp);
	}
	RegCloseKey(hkeyBackUp);
	//ɾ��֮ǰ�ı���
	if (RegOpenKeyEx(//��ָ����ע������ע�⣬���������ִ�Сд��
		HKEY_LOCAL_MACHINE//һ������ע�����ľ��������ע����һ�����ڵ�
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2")//ע������������
		, 0//ָ������ԿʱӦ�õ�ѡ����˲�������Ϊ���REG_OPTION_OPEN_LINK
		, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE//�������Ȩ��
		, &hkeyBackUp//�ñ������մ򿪵ļ��ľ��������ü�����Ԥ�����ע�����֮һ���������ʹ�þ������� RegCloseKey����
	) != ERROR_SUCCESS)//��������ɹ�������ֵ��ERROR_SUCCESS��
	{
		printf("ɾ�����ݵ�ע���ʱ->�򿪱��ݵ�ע���ʱʧ�ܣ�������Ȩ�޲�����\n");
		return false;
	}
	if (!DeleteSubKeyTree(hkeyBackUp, _T("SpiBackUp")))
	{
		printf("ɾ�����ݵ�ע�����Ϣʱʧ��!\n");
	}
	RegCloseKey(hkeyBackUp);
	return true;
}

void GetPath(OUT TCHAR *sPath)
{
	TCHAR sFilename[MAX_PATH];
	TCHAR sDrive[_MAX_DRIVE];
	TCHAR sDir[_MAX_DIR];
	TCHAR sFname[_MAX_FNAME];
	TCHAR sExt[_MAX_EXT];

	GetModuleFileName(NULL, sFilename, _MAX_PATH);

	_tsplitpath(sFilename, sDrive, sDir, sFname, sExt);

	_tcscpy(sPath, sDrive);
	_tcscat(sPath, sDir);

	if (sPath[_tcslen(sPath) - 1] != _T('\\'))
		_tcscat(sPath, _T("\\"));
}

int main()
{
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		printf("����Ȩ��ʧ�ܣ����Թ���ԱȨ�޴򿪱�����\n");
		printf("������ִ����ϣ�\n");
		char c[100];
		scanf("%s", c);
		return 0;
	}
	char com[20];
	memset(com, 0, 20);
	printf("��װ������i��ж��������r\n");
	scanf("%s", com);
	if (strcmp(com, "i") == 0)
	{
		TCHAR path[MAX_PATH];
		TCHAR dll[MAX_PATH];
		GetPath(path);
		printf("�ڿ�ʼ��װǰ�������µ�dll���������ƣ�����dll���ļ����ͺ�׺��\n");
		scanf("%ls", dll);
		lstrcatW(path,dll);
		if(Install(path))
			printf("��װ�ɹ���\n");
		else
			printf("Sorry����װʧ�ܣ�����\n");
		
	}
	else if (strcmp(com, "r") == 0)
	{
		if (Remove())
			printf("ж�سɹ���\n");
		else
			printf("Sorry��ж��ʧ�ܣ�����\n");
	}
	else
	{
		printf("�޴����ʲô��û������\n");
	}
	printf("������ִ����ϣ�\n");
	scanf("%s", com);
	return 0;


}

