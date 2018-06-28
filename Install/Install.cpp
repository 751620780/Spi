// Install.cpp : 定义控制台应用程序的入口点。
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
	//获取字节长度   
	DWORD dLength = WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, NULL, 0, NULL, NULL);
	if (dLength > cbAnsiStr)
		return false;
	//将tchar值赋给_char
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
	HKEY	hkey,//一个开放注册表项的句柄，或是注册表的一个根节点
	TCHAR	*sSubKey,//注册表子项的名称
	TCHAR	*lpSubKey,//创建的子项名称
	TCHAR	*sKey,//创建子项下的键名
	BYTE	*pBuffer,//键值的内容，即缓冲区指针
	DWORD	dwBufSize,//缓冲区大小
	DWORD	ulType//键值内容的类型
)
{
	HKEY	hKey;
	HKEY	hSubkey;
	DWORD	dwDisposition;

	if (RegCreateKeyEx(//创建指定的注册表项。如果该键已经存在，该功能将打开它。请注意，键名不区分大小写。
		hkey//一个已经打开的注册表项的句柄。
		, sSubKey//此函数打开或创建的子项的名称。
		, 0//该参数被保留并且必须为零
		, NULL//该参数可以是NULL
		, REG_OPTION_NON_VOLATILE//REG_OPTION_NON_VOLATILE这个键不易变化; 这是默认值。信息存储在文件中，并在系统重新启动时保留。
		, KEY_ALL_ACCESS//权限
		, NULL//
		, &hKey//打开 or 创建后的句柄
		, &dwDisposition//返回操作信息，可能是被创建或是被打开
	) != ERROR_SUCCESS)
		return false;
	if (RegCreateKeyEx(//创建指定的注册表项。如果该键已经存在，该功能将打开它。请注意，键名不区分大小写。
		hKey//一个已经打开的注册表项的句柄。
		, lpSubKey//此函数打开或创建的子项的名称。
		, 0//该参数被保留并且必须为零
		, NULL//该参数可以是NULL
		, REG_OPTION_NON_VOLATILE//REG_OPTION_NON_VOLATILE这个键不易变化; 这是默认值。信息存储在文件中，并在系统重新启动时保留。
		, KEY_ALL_ACCESS//权限
		, NULL//
		, &hSubkey//打开 or 创建后的句柄
		, &dwDisposition//返回操作信息，可能是被创建或是被打开
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
	//判断有没有安装过！
	HKEY hKeyBackup = NULL;
	if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
		HKEY_LOCAL_MACHINE//一个开放注册表项的句柄，或是注册表的一个根节点
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//注册表子项的名称
		, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
		, KEY_READ//所需访问权限
		, &hKeyBackup//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
	) == ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
	{
		printf("已经安装过，请先删除！\n");
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
		//打开注册表
		if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
			HKEY_LOCAL_MACHINE//一个开放注册表项的句柄，或是注册表的一个根节点
			, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries")//注册表子项的名称
			, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
			, KEY_READ//所需访问权限
			, &hkey//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
		) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
		{
			printf("Error! Open reg error.\n");
			return false;
		}
		while (RegEnumKey(//枚举指定的打开注册表项的子项。该函数每次调用时都会检索一个子项的名称
			hkey//一个开放注册表项的句柄
			, index++//要检索的hKey的子键的索引。对于首次调用RegEnumKey函数，该值应为零 ，然后对后续调用增加
			, subKey//该缓冲区接收子密钥的名称，包括终止的空字符。该功能只将子密钥的名称而不是完整的密钥层次复制到缓冲区。
			, MAX_PATH//lpName参数指向的缓冲区的大小
		) == ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
		{
			if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
				hkey//一个开放注册表项的句柄，或是注册表的一个根节点
				, subKey//注册表子项的名称
				, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
				, KEY_ALL_ACCESS//所需访问权限
				, &hsubKey//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
			) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
			{
				printf("Error! Open sub reg error.\n");
				return false;
			}
			if (RegQueryValueEx(//检索与打开的注册表项关联的指定值名称的类型和数据
				hsubKey//一个开放注册表项的句柄
				, _T("PackedCatalogItem")//注册表值的名称。
				, 0//为NULL
				, NULL//示存储在指定值中的数据类型的代码，NULL为不指定类型
				, ItemValue//接收值数据的缓冲区的指针，可为NULL
				, &ItemSize//lpData参数指向的缓冲区的大小（以字节为单位），调用完成会指示实际长度
			) != ERROR_SUCCESS)
			{
				printf("Error! Query sub reg error.\n");
				return false;
			}
			mProtocolInfo = (WSAPROTOCOL_INFOW*)(ItemValue + MAX_PATH);
			if (mProtocolInfo->ProtocolChain.ChainLen == 1 && mProtocolInfo->iAddressFamily == AF_INET)//ChainLen=1表示是基础服务提供者，AF_INET是IPV4地址族
			{
				char subkeychar[MAX_PATH];
				Unicode16ToChar8(subKey, subkeychar ,MAX_PATH);
				printf("正在对注册表%s的子项%s操作...\n", "SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries",subkeychar);
				//比较一下这个里面的路径是否与我们的一样，不一样就备份，然后再写入
				if (strcmp(szPath, (char*)ItemValue) != 0)
				{
					if (!SaveReg(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp"), subKey, _T("PackedCatalogItem"), ItemValue, sizeof(WSAPROTOCOL_INFOW) + MAX_PATH, REG_BINARY))
						printf("备份数据时出现错误。\n");
					//写入
					memset(ItemValue, '\0', MAX_PATH);
					memcpy(ItemValue, szPath, strlen(szPath));
					if (RegSetValueEx(hsubKey, _T("PackedCatalogItem"), 0, REG_BINARY, ItemValue, ItemSize) != ERROR_SUCCESS)
						printf("修改注册表键值时出现错误，修改失败！\n");
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
	//判断有没有安装过！
	HKEY hKey = NULL;
	if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
		HKEY_LOCAL_MACHINE//一个开放注册表项的句柄，或是注册表的一个根节点
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//注册表子项的名称
		, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
		, KEY_READ//所需访问权限
		, &hKey//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
	) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
	{
		printf("没有安装过，无法还原！\n");
		return false;
	}
	RegCloseKey(hKey);
	//开始还原
	HKEY hkeyBackUp = NULL;
	HKEY hSubkeyBackUp = NULL;
	//打开备份的注册表项
	if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
		HKEY_LOCAL_MACHINE//一个开放注册表项的句柄，或是注册表的一个根节点
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\SpiBackUp")//注册表子项的名称
		, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
		, KEY_READ//所需访问权限
		, &hkeyBackUp//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
	) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
	{
		printf("打开备份的注册表时失败！\n");
		return false;
	}

	DWORD index = 0;
	TCHAR subKey[MAX_PATH];
	BYTE	ItemValue[sizeof(WSAPROTOCOL_INFOW) + MAX_PATH];
	DWORD	ItemSize = sizeof(WSAPROTOCOL_INFOW) + MAX_PATH;

	while (RegEnumKey(hkeyBackUp, index++, subKey, MAX_PATH) == ERROR_SUCCESS)
	{
		if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
			hkeyBackUp//一个开放注册表项的句柄，或是注册表的一个根节点
			, subKey//注册表子项的名称
			, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
			, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_READ//所需访问权限
			, &hSubkeyBackUp//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
		) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
		{
			RegCloseKey(hkeyBackUp);
			printf("打开备份的注册表子项时失败！\n");
			return false;
		}
		if (RegQueryValueEx(hSubkeyBackUp, _T("PackedCatalogItem"), 0, NULL, ItemValue, &ItemSize) != ERROR_SUCCESS)
		{
			RegCloseKey(hSubkeyBackUp);
			RegCloseKey(hkeyBackUp);
			printf("查询备份的注册表内容时失败！\n");
			return false;
		}
		if (!SaveReg(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"), subKey, _T("PackedCatalogItem"), ItemValue, sizeof(WSAPROTOCOL_INFOW) + MAX_PATH, REG_BINARY))
		{
			RegCloseKey(hSubkeyBackUp);
			printf("将备份的注册表内容写入原注册表时失败!\n");
			return false;
		}
		RegDeleteKey(hSubkeyBackUp, _T("PackedCatalogItem"));
		RegCloseKey(hSubkeyBackUp);
	}
	RegCloseKey(hkeyBackUp);
	//删除之前的备份
	if (RegOpenKeyEx(//打开指定的注册表项。请注意，键名不区分大小写。
		HKEY_LOCAL_MACHINE//一个开放注册表项的句柄，或是注册表的一个根节点
		, _T("SYSTEM\\CurrentControlSet\\Services\\WinSock2")//注册表子项的名称
		, 0//指定打开密钥时应用的选项。将此参数设置为零或REG_OPTION_OPEN_LINK
		, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE//所需访问权限
		, &hkeyBackUp//该变量接收打开的键的句柄。如果该键不是预定义的注册表项之一，则在完成使用句柄后调用 RegCloseKey函数
	) != ERROR_SUCCESS)//如果函数成功，返回值是ERROR_SUCCESS。
	{
		printf("删除备份的注册表时->打开备份的注册表时失败，可能是权限不够！\n");
		return false;
	}
	if (!DeleteSubKeyTree(hkeyBackUp, _T("SpiBackUp")))
	{
		printf("删除备份的注册表信息时失败!\n");
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
		printf("提升权限失败，请以管理员权限打开本程序！\n");
		printf("程序已执行完毕！\n");
		char c[100];
		scanf("%s", c);
		return 0;
	}
	char com[20];
	memset(com, 0, 20);
	printf("安装请输入i，卸载请输入r\n");
	scanf("%s", com);
	if (strcmp(com, "i") == 0)
	{
		TCHAR path[MAX_PATH];
		TCHAR dll[MAX_PATH];
		GetPath(path);
		printf("在开始安装前请输入新的dll的完整名称，包含dll的文件名和后缀。\n");
		scanf("%ls", dll);
		lstrcatW(path,dll);
		if(Install(path))
			printf("安装成功！\n");
		else
			printf("Sorry，安装失败！！！\n");
		
	}
	else if (strcmp(com, "r") == 0)
	{
		if (Remove())
			printf("卸载成功！\n");
		else
			printf("Sorry，卸载失败！！！\n");
	}
	else
	{
		printf("无此命令！什么都没有做。\n");
	}
	printf("程序已执行完毕！\n");
	scanf("%s", com);
	return 0;


}

