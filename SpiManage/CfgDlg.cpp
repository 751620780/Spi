// CfgDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SpiManage.h"
#include "CfgDlg.h"
#include "afxdialogex.h"
#include <Tlhelp32.h>
#pragma warning(disable : 4996)
#define STR_WHITE_LIST				L"������"
#define STR_REIN_LIST				L"����"
#define STR_PORT					L"�˿�"
#define STR_LOCAL_IP				L"����IP��ַ"
#define STR_REMOTE_IP				L"Զ��IP��ַ"
#define STR_LOCAL_IP_RANGE			L"����IP��Χ"
#define STR_REMOTE_IP_RANGE			L"Զ��IP��Χ"
#define STR_PROCESS_NAME			L"������"
#define STR_NEW						L"����"
#define STR_OLD						L""
#define STR_DELET					L"׼��ɾ��"

// CCfgDlg �Ի���

IMPLEMENT_DYNAMIC(CCfgDlg, CDialog)

CCfgDlg::CCfgDlg(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_DIALOG_CFG, pParent)
{

}

CCfgDlg::~CCfgDlg()
{
}

void CCfgDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCfgDlg, CDialog)
	ON_BN_CLICKED(IDC_BTN_REFRESH, &CCfgDlg::OnBnClickedBtnRefresh)
	ON_BN_CLICKED(IDC_BTN_APPLY, &CCfgDlg::OnBnClickedBtnApply)
	ON_BN_CLICKED(IDC_BTN_ADD, &CCfgDlg::OnBnClickedBtnAdd)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST, &CCfgDlg::OnCustomDrawList)
	ON_NOTIFY(NM_RCLICK, IDC_LIST, &CCfgDlg::OnRclickList)
	ON_COMMAND(ID_32771, &CCfgDlg::OnMenuDelet)
	ON_COMMAND(ID_32772, &CCfgDlg::OnMenuDeletAll)
END_MESSAGE_MAP()


// CCfgDlg ��Ϣ�������


void CCfgDlg::OnBnClickedBtnRefresh()
{
	RefreshDataToControl();
}


void CCfgDlg::OnBnClickedBtnApply()
{
	RefreshDataToCfg();
}


void CCfgDlg::OnBnClickedBtnAdd()
{
	CString type1, type2, edit;
	TCHAR str[MAX_PATH], ch;
	int a, b, c, d, a1, b1, c1, d1, port = -1;
	m_pCbType1->GetWindowTextW(type1);
	m_pCbType2->GetWindowTextW(type2);
	m_pEditText->GetWindowTextW(edit);
	if (wcscmp(edit, L"") == 0)
	{
		MessageBoxW(L"����Ϊ��", L"����");
		m_pEditText->SetFocus();
		return;
	}
	if (edit.GetLength() >= 50)
	{
		MessageBoxW(L"���ȹ�����ӦС��50", L"����");
		m_pEditText->SetFocus();
		return;
	}
	if (wcscmp(type1, STR_WHITE_LIST) == 0)
	{
		if (wcscmp(type2, STR_PORT) == 0)
		{
			if (swscanf(edit, L"%d%c", &port, &ch) == 1 && port >= 0 && port <= 65535)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_WHITE_LIST);
				m_pList->SetItemText(0, 1, STR_PORT);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"�˿ڸ�ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
		else if (wcscmp(type2, STR_PROCESS_NAME) == 0)
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_WHITE_LIST);
			m_pList->SetItemText(0, 1, STR_PROCESS_NAME);
			m_pList->SetItemText(0, 2, edit);
			m_pList->SetItemText(0, 3, STR_NEW);
		}
		else if (wcscmp(type2, STR_LOCAL_IP) == 0 || wcscmp(type2, STR_REMOTE_IP) == 0)
		{

			if (swscanf(edit, L"%d.%d.%d.%d%c", &a, &b, &c, &d, &ch) == 4
				&& a >= 0 && a <= 255
				&& b >= 0 && b <= 255
				&& c >= 0 && c <= 255
				&& d >= 0 && d <= 255
				)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_WHITE_LIST);
				m_pList->SetItemText(0, 1, type2);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"IP��ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
		else if (wcscmp(type2, STR_LOCAL_IP_RANGE) == 0 || wcscmp(type2, STR_REMOTE_IP_RANGE) == 0)
		{
			if (swscanf(edit, L"%d.%d.%d.%d-%d.%d.%d.%d%c", &a, &b, &c, &d, &a1, &b1, &c1, &d1, &ch) == 8
				&& a >= 0 && a <= 255
				&& b >= 0 && b <= 255
				&& c >= 0 && c <= 255
				&& d >= 0 && d <= 255
				&& a1 >= 0 && a1 <= 255
				&& b1 >= 0 && b1 <= 255
				&& c1 >= 0 && c1 <= 255
				&& d1 >= 0 && d1 <= 255
				)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_WHITE_LIST);
				m_pList->SetItemText(0, 1, type2);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"IP��ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
	}
	else if (wcscmp(type1, STR_REIN_LIST) == 0)
	{
		if (wcscmp(type2, STR_PORT) == 0)
		{
			if (swscanf(edit, L"%d%c", &port, &ch) == 1 && port >= 0 && port <= 65535)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_REIN_LIST);
				m_pList->SetItemText(0, 1, STR_PORT);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"�˿ڸ�ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
		else if (wcscmp(type2, STR_PROCESS_NAME) == 0)
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_REIN_LIST);
			m_pList->SetItemText(0, 1, STR_PROCESS_NAME);
			m_pList->SetItemText(0, 2, edit);
			m_pList->SetItemText(0, 3, STR_NEW);

		}
		else if (wcscmp(type2, STR_LOCAL_IP) == 0 || wcscmp(type2, STR_REMOTE_IP) == 0)
		{

			if (swscanf(edit, L"%d.%d.%d.%d%c", &a, &b, &c, &d, &ch) == 4
				&& a >= 0 && a <= 255
				&& b >= 0 && b <= 255
				&& c >= 0 && c <= 255
				&& d >= 0 && d <= 255
				)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_REIN_LIST);
				m_pList->SetItemText(0, 1, type2);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"IP��ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
		else if (wcscmp(type2, STR_LOCAL_IP_RANGE) == 0 || wcscmp(type2, STR_REMOTE_IP_RANGE) == 0)
		{
			if (swscanf(edit, L"%d.%d.%d.%d-%d.%d.%d.%d%c", &a, &b, &c, &d, &a1, &b1, &c1, &d1, &ch) == 8
				&& a >= 0 && a <= 255
				&& b >= 0 && b <= 255
				&& c >= 0 && c <= 255
				&& d >= 0 && d <= 255
				&& a1 >= 0 && a1 <= 255
				&& b1 >= 0 && b1 <= 255
				&& c1 >= 0 && c1 <= 255
				&& d1 >= 0 && d1 <= 255
				)
			{
				m_pList->InsertItem(0, L"");
				m_pList->SetItemText(0, 0, STR_REIN_LIST);
				m_pList->SetItemText(0, 1, type2);
				m_pList->SetItemText(0, 2, edit);
				m_pList->SetItemText(0, 3, STR_NEW);
			}
			else
			{
				MessageBoxW(L"IP��ʽ����ȷ", L"����");
				m_pEditText->SetFocus();
				return;
			}
		}
	}
}


BOOL CCfgDlg::OnInitDialog()
{
	CDialog::OnInitDialog();
	TCHAR szError[MAX_PATH];
	TCHAR sProcessName[MAX_PATH];
	TCHAR sExtension[50];
	TCHAR m_drive[10];
	TCHAR m_dir[MAX_PATH];
	GetModuleFileNameW(NULL, sProcessName, MAX_PATH);//��ü��ر�dll��Ӧ�ó�������·��
	_wsplitpath(sProcessName, m_drive, m_dir, sProcessName, sExtension);
	_swprintf(m_sCfgFilePath, L"%s%s%s", m_drive, m_dir, L"cfg.cfg");
	m_hGlobVarMutex = CreateMutexW(NULL, FALSE, L"SpiMutexGlobVar");
	if (m_hGlobVarMutex == NULL)
	{
		_swprintf(szError, L"���������� SpiMutexGlobVar �������:[%d].\n����ȷ�����̽�������", GetLastError());
		MessageBoxW(szError, L"����", MB_ICONSTOP | MB_OK);
		CDialog::OnOK();
	}
	m_hMapFileGlob = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(GLOBVAR), L"SpiSharedMemaryGlobVar");
	if (m_hMapFileGlob == NULL)
	{
		_swprintf(szError, L"�����ļ�ӳ����� SpiSharedMemaryGlobVar �������:[%d].\n����ȷ�����̽�������", GetLastError());
		MessageBoxW(szError, L"����", MB_ICONSTOP | MB_OK);
		CDialog::OnOK();
	}
	m_pGlobVar = (PGLOBVAR)MapViewOfFile(m_hMapFileGlob, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(GLOBVAR));
	if (m_pGlobVar == NULL)
	{
		_swprintf(szError, L"�����ļ�ӳ��ʱʧ�ܣ��������:[%d].\n����ȷ�����̽�������", GetLastError());
		MessageBoxW(szError, L"����", MB_ICONSTOP | MB_OK);
		CDialog::OnOK();
	}
	m_hGlobVarSemap = CreateSemaphoreW(NULL, 0, 0x7fffffff, L"SpiGlobSemap");
	if (m_hGlobVarSemap == NULL)
	{
		_swprintf(szError, L"�����ź��� SpiGlobSemap �������:[%d].\n����ȷ�����̽�������", GetLastError());
		MessageBoxW(szError, L"����", MB_ICONSTOP | MB_OK);
		CDialog::OnOK();
	}
	//��ʼ���ռ�ľ�����ؼ�������
	m_pCbType1 = (CComboBox*)GetDlgItem(IDC_COMBO_TYPE1);
	m_pCbType1->AddString(STR_WHITE_LIST);
	m_pCbType1->AddString(STR_REIN_LIST);
	m_pCbType1->SetCurSel(0);
	m_pCbType2 = (CComboBox*)GetDlgItem(IDC_COMBO_TYPE2);
	m_pCbType2->AddString(STR_PORT);
	m_pCbType2->AddString(STR_LOCAL_IP);
	m_pCbType2->AddString(STR_REMOTE_IP);
	m_pCbType2->AddString(STR_LOCAL_IP_RANGE);
	m_pCbType2->AddString(STR_REMOTE_IP_RANGE);
	m_pCbType2->AddString(STR_PROCESS_NAME);
	m_pCbType2->SetCurSel(0);
	m_pAllConnect = (CButton*)GetDlgItem(IDC_CHECK_CONNECT);
	m_pAllAccept = (CButton*)GetDlgItem(IDC_CHECK_ACCEPT);
	m_pAllClose = (CButton*)GetDlgItem(IDC_CHECK_CLOSE);
	m_pAllSend = (CButton*)GetDlgItem(IDC_CHECK_SEND);
	m_pAllRecv = (CButton*)GetDlgItem(IDC_CHECK_RECV);
	m_pRein = (CButton*)GetDlgItem(IDC_CHECK_REIN);
	m_pReinConnect = (CButton*)GetDlgItem(IDC_CHECK_REINCONNECT);
	m_pReinAccept = (CButton*)GetDlgItem(IDC_CHECK_REINACCEPT);
	m_pReinClose = (CButton*)GetDlgItem(IDC_CHECK_REINCLOSE);
	m_pReinSend = (CButton*)GetDlgItem(IDC_CHECK_REINSEND);
	m_pReinRecv = (CButton*)GetDlgItem(IDC_CHECK_REINRECV);
	m_pList = (CListCtrl*)GetDlgItem(IDC_LIST);
	m_pEditKey = (CEdit*)GetDlgItem(IDC_EDIT_KEY);
	m_pEditText = (CEdit*)GetDlgItem(IDC_EDIT_TEXT);
	m_pStaticCount = (CStatic*)GetDlgItem(IDC_STATIC_COUNT);
	//���ñ���ķ��
	m_pList->SetExtendedStyle(LVS_EX_FLATSB | LVS_EX_FULLROWSELECT | LVS_EX_HEADERDRAGDROP | LVS_EX_ONECLICKACTIVATE | LVS_EX_GRIDLINES | LVS_EDITLABELS | LVS_EX_SUBITEMIMAGES);
	//���ñ������
	m_pList->InsertColumn(0, L"����", LVCFMT_LEFT, 80, 0);
	m_pList->InsertColumn(1, L"��֧", LVCFMT_LEFT, 80, 1);
	m_pList->InsertColumn(2, L"ֵ", LVCFMT_LEFT, 308, 2);
	m_pList->InsertColumn(3, L"��ע", LVCFMT_LEFT, 70, 3);
	ReadCfg();
	//��ʼ�������ļ������ݵ��ؼ�
	RefreshDataToControl();
	return TRUE;  
}

void CCfgDlg::OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult)
{
	NMLVCUSTOMDRAW* pLVCD = reinterpret_cast<NMLVCUSTOMDRAW*>(pNMHDR);
	*pResult = CDRF_DODEFAULT;
	if (CDDS_PREPAINT == pLVCD->nmcd.dwDrawStage)//���ػ�
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}
	else if (CDDS_ITEMPREPAINT == pLVCD->nmcd.dwDrawStage)//��ĳһ�н��л���
	{
		*pResult = CDRF_NOTIFYSUBITEMDRAW;
	}
	else if ((CDDS_ITEMPREPAINT | CDDS_SUBITEM) == pLVCD->nmcd.dwDrawStage)//����ĳһ�е�ĳ����Ԫ��
	{
		COLORREF clrNewTextColor, clrNewBkColor;
		int    nItem = static_cast<int>(pLVCD->nmcd.dwItemSpec);
		CString str3 = m_pList->GetItemText(nItem, 3);
		CString str0 = m_pList->GetItemText(nItem, 0);
		if (wcscmp(str0, STR_WHITE_LIST) == 0) {
			clrNewTextColor = RGB(0, 0, 0);
			clrNewBkColor = RGB(128, 255, 128);
		}
		else if (wcscmp(str0, STR_REIN_LIST) == 0) {
			clrNewTextColor = RGB(0, 0, 0);
			clrNewBkColor = RGB(255, 255, 0);
		}
		if (wcscmp(str3, STR_NEW) == 0) {
			clrNewTextColor = RGB(0, 0, 0);
			clrNewBkColor = RGB(255, 128, 128);
		}
		pLVCD->clrText = clrNewTextColor;
		pLVCD->clrTextBk = clrNewBkColor;
		*pResult = CDRF_DODEFAULT;
	}
}

void CCfgDlg::OnRclickList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	*pResult = 0;
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	if (pNMListView->iItem != -1)
	{
		DWORD dwPos = GetMessagePos();
		CPoint point(LOWORD(dwPos), HIWORD(dwPos));
		CMenu menu;
		VERIFY(menu.LoadMenu(IDR_MENU1));
		CMenu* popup = menu.GetSubMenu(0);
		ASSERT(popup != NULL);
		popup->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, point.x, point.y, this);
	}
}


void CCfgDlg::OnMenuDelet()
{
	int pos = m_pList->GetNextItem(-1, LVIS_SELECTED);
	m_pList->SetItemText(pos, 3, STR_DELET);
}


void CCfgDlg::OnMenuDeletAll()
{
	if (MessageBoxW(L"ȫ�����Ϊ��׼��ɾ����?", L"ѯ��", MB_ICONQUESTION | MB_OKCANCEL) == 1)
	{
		for (int i = 0; i < m_pList->GetItemCount(); i++)
		{
			if (wcscmp(m_pList->GetItemText(i, 3), STR_OLD) == 0)
			{
				m_pList->SetItemText(i, 3, STR_DELET);
			}
		}
	}
}


void CCfgDlg::ReadCfg()
{
	WaitForSingleObject(m_hGlobVarMutex, INFINITE);
	{
		if (_waccess(m_sCfgFilePath, 0) != -1)
		{
			FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"rb");
			if (pCfgFile != NULL&&m_pGlobVar->dDllCount == 0)
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
			if (MessageBoxW(L"��������·���Ҳ��������������ļ����Ƿ������ڸ�·���´��������ļ���\n���ѡ�񡰷񡱣����������˳���", L"����", MB_OKCANCEL | MB_ICONWARNING) == IDOK)
			{
				FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"wb");
				if (m_pGlobVar->dDllCount == 0)
				{
					char KeyDefault[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
					memcpy(m_pGlobVar->bMainKey, KeyDefault, 16);
				}
				fwrite(m_pGlobVar, sizeof(GLOBVAR), 1, pCfgFile);
				fclose(pCfgFile);
			}
			else
			{
				CDialog::OnOK();
			}
		}
	}
	ReleaseMutex(m_hGlobVarMutex);
}

void CCfgDlg::SaveCfg()
{
	FILE *pCfgFile = _wfopen(m_sCfgFilePath, L"wb");
	fwrite(m_pGlobVar, sizeof(GLOBVAR), 1, pCfgFile);
	fclose(pCfgFile);
}

DWORD CCfgDlg::crc32(BYTE *buffer, DWORD size)
{
	DWORD crc = 0;
	for (DWORD i = 0; i < size; i++)
	{
		crc = m_CrcTable[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	return crc;
}

//��ansi�ַ�ת��ΪUnicode�ַ�
//lpChar			ansi�ַ�������ʼ��ַ
//lpTchar			ת���󱣴�unicode�ַ�����ʼ��ַ
//lengthTchar	����unicode�ַ�����󳤶�
bool CCfgDlg::Char8ToUnicode16(char *lpChar, TCHAR *lpTchar, DWORD lengthTchar)
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
bool CCfgDlg::Unicode16ToChar8(TCHAR *lpTcharStr, char *lpAnsiStr, DWORD lengthChar)
{
	DWORD dLength = WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, NULL, 0, NULL, NULL);
	if (dLength >= lengthChar)
		return false;
	if (WideCharToMultiByte(CP_ACP, 0, lpTcharStr, -1, lpAnsiStr, dLength, NULL, NULL) == dLength)
		return true;
	return false;
}

void CCfgDlg::RefreshDataToControl()
{
	TCHAR str[MAX_PATH];
	BYTE *ps = NULL, *pe = NULL;
	WaitForSingleObject(m_hGlobVarMutex, INFINITE);
	{
		m_pAllConnect->SetCheck(m_pGlobVar->allConnect);
		m_pAllAccept->SetCheck(m_pGlobVar->allAccept);
		m_pAllClose->SetCheck(m_pGlobVar->allCloseSocket);
		m_pAllSend->SetCheck(m_pGlobVar->allSend);
		m_pAllRecv->SetCheck(m_pGlobVar->allRecv);
		m_pRein->SetCheck(m_pGlobVar->rein);
		m_pReinConnect->SetCheck(m_pGlobVar->reinConnect);
		m_pReinAccept->SetCheck(m_pGlobVar->reinAccept);
		m_pReinClose->SetCheck(m_pGlobVar->reinCloseSocket);
		m_pReinSend->SetCheck(m_pGlobVar->reinSend);
		m_pReinRecv->SetCheck(m_pGlobVar->reinRecv);
		_swprintf(str, L"%d", m_pGlobVar->dDllCount);
		m_pStaticCount->SetWindowTextW(str);
		m_pList->DeleteAllItems();

		for (int i = 0; i < m_pGlobVar->reinPortLen; i++)//port��������
		{
			_swprintf(str, L"%d", m_pGlobVar->reinPort[i]);
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_REIN_LIST);
			m_pList->SetItemText(0, 1, STR_PORT);
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinProcessLen; i++)//��������������
		{
			Char8ToUnicode16(m_pGlobVar->reinProcess[i].name, str, MAX_PATH);
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_REIN_LIST);
			m_pList->SetItemText(0, 1, STR_PROCESS_NAME);
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinLocalIPLen; i++)//����ip��������
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_REIN_LIST);
			if (m_pGlobVar->reinLocalIP[i].type != 0)
			{
				ps = (BYTE*)&(m_pGlobVar->reinLocalIP[i].addrStart);
				pe = (BYTE*)&(m_pGlobVar->reinLocalIP[i].addrEnd);
				_swprintf(str, L"%d.%d.%d.%d-%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0], pe[3], pe[2], pe[1], pe[0]);
				m_pList->SetItemText(0, 1, STR_LOCAL_IP_RANGE);
			}
			else
			{
				ps = (BYTE*)&(m_pGlobVar->reinLocalIP[i].addr);
				_swprintf(str, L"%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0]);
				m_pList->SetItemText(0, 1, STR_LOCAL_IP);
			}
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinRemoteIPLen; i++)//Զ��ip��������
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_REIN_LIST);
			if (m_pGlobVar->reinRemoteIP[i].type != 0)
			{
				ps = (BYTE*)&(m_pGlobVar->reinRemoteIP[i].addrStart);
				pe = (BYTE*)&(m_pGlobVar->reinRemoteIP[i].addrEnd);
				_swprintf(str, L"%d.%d.%d.%d-%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0], pe[3], pe[2], pe[1], pe[0]);
				m_pList->SetItemText(0, 1, STR_REMOTE_IP_RANGE);
			}
			else
			{
				ps = (BYTE*)&(m_pGlobVar->reinRemoteIP[i].addr);
				_swprintf(str, L"%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0]);
				m_pList->SetItemText(0, 1, STR_REMOTE_IP);
			}
			m_pList->SetItemText(0, 2, str);
		}
		/***************************************************************************************************************/
		for (int i = 0; i < m_pGlobVar->reinPortWhiteLen; i++)//port������
		{
			_swprintf(str, L"%d", m_pGlobVar->reinPortWhite[i]);
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_WHITE_LIST);
			m_pList->SetItemText(0, 1, STR_PORT);
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinProcessWhiteLen; i++)//������������
		{
			Char8ToUnicode16(m_pGlobVar->reinProcessWhite[i].name, str, MAX_PATH);
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_WHITE_LIST);
			m_pList->SetItemText(0, 1, STR_PROCESS_NAME);
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinLocalIPWhiteLen; i++)//����ip������
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_WHITE_LIST);
			if (m_pGlobVar->reinLocalIPWhite[i].type != 0)
			{
				ps = (BYTE*)&(m_pGlobVar->reinLocalIPWhite[i].addrStart);
				pe = (BYTE*)&(m_pGlobVar->reinLocalIPWhite[i].addrEnd);
				_swprintf(str, L"%d.%d.%d.%d-%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0], pe[3], pe[2], pe[1], pe[0]);
				m_pList->SetItemText(0, 1, STR_LOCAL_IP_RANGE);
			}
			else
			{
				ps = (BYTE*)&(m_pGlobVar->reinLocalIPWhite[i].addr);
				_swprintf(str, L"%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0]);
				m_pList->SetItemText(0, 1, STR_LOCAL_IP);
			}
			m_pList->SetItemText(0, 2, str);
		}
		for (int i = 0; i < m_pGlobVar->reinRemoteIPWhiteLen; i++)//Զ��ip������
		{
			m_pList->InsertItem(0, L"");
			m_pList->SetItemText(0, 0, STR_WHITE_LIST);
			if (m_pGlobVar->reinRemoteIPWhite[i].type != 0)
			{
				ps = (BYTE*)&(m_pGlobVar->reinRemoteIPWhite[i].addrStart);
				pe = (BYTE*)&(m_pGlobVar->reinRemoteIPWhite[i].addrEnd);
				_swprintf(str, L"%d.%d.%d.%d-%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0], pe[3], pe[2], pe[1], pe[0]);
				m_pList->SetItemText(0, 1, STR_REMOTE_IP_RANGE);
			}
			else
			{
				ps = (BYTE*)&(m_pGlobVar->reinRemoteIPWhite[i].addr);
				_swprintf(str, L"%d.%d.%d.%d", ps[3], ps[2], ps[1], ps[0]);
				m_pList->SetItemText(0, 1, STR_REMOTE_IP);
			}
			m_pList->SetItemText(0, 2, str);
		}

		_swprintf(str, L"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x"
			, m_pGlobVar->bMainKey[0], m_pGlobVar->bMainKey[1], m_pGlobVar->bMainKey[2], m_pGlobVar->bMainKey[3]
			, m_pGlobVar->bMainKey[4], m_pGlobVar->bMainKey[5], m_pGlobVar->bMainKey[6], m_pGlobVar->bMainKey[7]
			, m_pGlobVar->bMainKey[8], m_pGlobVar->bMainKey[9], m_pGlobVar->bMainKey[10], m_pGlobVar->bMainKey[11]
			, m_pGlobVar->bMainKey[12], m_pGlobVar->bMainKey[13], m_pGlobVar->bMainKey[14], m_pGlobVar->bMainKey[15]
		);
		m_pEditKey->SetWindowTextW(str);
	}
	ReleaseMutex(m_hGlobVarMutex);
}

//�����硰0f 2c 1a���������ַ���ת����char�����������
//����0 �ַ�������
//����-1 ���ȳ���Χ
//�������� ת���ɹ��ĸ���
int CCfgDlg::HexTextToHex(char *text, char *hex, int length)
{
	char ss[5] = "0x";
	int i = 0;
	char* p = strtok(text, " ");
	while (p != NULL)
	{
		if (strlen(p) > 2)return 0;
		if (i >= length)return -1;
		strcat(ss, p);
		if (1 != sscanf(ss, "%x", &hex[i++]))return i;
		p = strtok(NULL, " "); ss[2] = 0;
	}
	return i;
}

//�ж�ĳģ��(dll)�Ƿ�����Ӧ�Ľ�����  
//dwPID         ���̵�PID  
//szDllPath     ��ѯ��dll������·��  
BOOL CCfgDlg::CheckDllInProcess(DWORD dwPID)
{
	BOOL                    bMore = FALSE;
	HANDLE                  hSnapshot = INVALID_HANDLE_VALUE;
	MODULEENTRY32           me = { sizeof(me), };

	if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))//��ý��̵Ŀ���  
		return FALSE;
	bMore = Module32First(hSnapshot, &me);//���������ڵõ�����ģ��  
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (!_tcsicmp(me.szModule, L"Spi.dll") || !_tcsicmp(me.szExePath, L"Spi.dll"))//ģ������·���������  
		{
			CloseHandle(hSnapshot);
			return TRUE;
		}
	}
	CloseHandle(hSnapshot);
	return FALSE;
}

DWORD  CCfgDlg::GetAllModules()
{
	DWORD dllCount = 0;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
		return -1;
	BOOL bResult = Process32First(hProcessSnap, &pe32);
	while (bResult)
	{
		dllCount += CheckDllInProcess(pe32.th32ProcessID);
		bResult = Process32Next(hProcessSnap, &pe32);
	}
	CloseHandle(hProcessSnap);
	return dllCount;
}

void CCfgDlg::RefreshDataToCfg()
{
	GLOBVAR gvar;
	memset(&gvar, 0, sizeof(GLOBVAR));
	TCHAR str[MAX_PATH];
	//��Կ
	int length = m_pEditKey->GetWindowTextLengthW();
	TCHAR *wkey = (TCHAR*)malloc(length * 2 + 4);
	CHAR *ckey = (CHAR*)malloc(length * 2 + 4);
	m_pEditKey->GetWindowTextW(wkey, length * 2 + 4);
	Unicode16ToChar8(wkey, ckey, length + 2);
	char key[17];
	if (HexTextToHex(ckey, key, 16) != 16)
	{
		free(wkey);
		free(ckey);
		MessageBoxW(L"�������Կ����ȷ��Ӧ����16����������֮��������һ���ո����\n���ҳ��Ȳ��ܳ���16����", L"����", MB_ICONSTOP | MB_OK);
		return;
	}
	memcpy(gvar.bMainKey, key, 16);
	free(wkey);
	free(ckey);
	//����
	gvar.allConnect = m_pAllConnect->GetCheck();
	gvar.allAccept = m_pAllAccept->GetCheck();
	gvar.allCloseSocket = m_pAllClose->GetCheck();
	gvar.allSend = m_pAllSend->GetCheck();
	gvar.allRecv = m_pAllRecv->GetCheck();
	gvar.rein = m_pRein->GetCheck();
	gvar.reinConnect = m_pReinConnect->GetCheck();
	gvar.reinAccept = m_pReinAccept->GetCheck();
	gvar.reinCloseSocket = m_pReinClose->GetCheck();
	gvar.reinSend = m_pReinSend->GetCheck();
	gvar.reinRecv = m_pReinRecv->GetCheck();
	//�������е�ģ������
	DWORD dllCount = GetAllModules();
	if (dllCount != -1)
		gvar.dDllCount = dllCount;
	//�б�
	CString l[4];
	PROCESSNAME *pro = NULL;
	IPRANGE *iprange = NULL;
	int a, b, c, d, a1, b1, c1, d1;
	for (int i = 0; i < m_pList->GetItemCount(); i++)
	{
		//�������
		for (int j = 0; j < 4; j++)
			l[j] = m_pList->GetItemText(i, j);
		if (wcscmp(l[3], STR_DELET) == 0)
			continue;
		if (wcscmp(l[0], STR_WHITE_LIST) == 0)
		{
			if (wcscmp(l[1], STR_PORT) == 0)
			{
				gvar.reinPortWhite[gvar.reinPortWhiteLen] = _wtoi(l[2]);
				gvar.reinPortWhiteLen++;
			}
			else if (wcscmp(l[1], STR_PROCESS_NAME) == 0)
			{
				pro = &gvar.reinProcessWhite[gvar.reinProcessWhiteLen];
				Unicode16ToChar8(l[2].GetBuffer(), pro->name, 50);
				pro->crc32 = crc32((BYTE*)l[2].GetBuffer(), lstrlenW(l[2].GetBuffer()));
				gvar.reinProcessWhiteLen++;
			}
			else if (wcscmp(l[1], STR_LOCAL_IP) == 0)
			{
				iprange = &gvar.reinLocalIPWhite[gvar.reinLocalIPWhiteLen];
				iprange->type = 0;
				swscanf(l[2], L"%d.%d.%d.%d", &a, &b, &c, &d);
				*(DWORD*)&(iprange->addr) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				gvar.reinLocalIPWhiteLen++;
			}
			else if (wcscmp(l[1], STR_LOCAL_IP_RANGE) == 0)
			{
				iprange = &gvar.reinLocalIPWhite[gvar.reinLocalIPWhiteLen];
				iprange->type = 1;
				swscanf(l[2], L"%d.%d.%d.%d-%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1);
				*(DWORD*)&(iprange->addrStart) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				*(DWORD*)&(iprange->addrEnd) = (DWORD)(a1 << 24 | b1 << 16 | c1 << 8 | d1);
				gvar.reinLocalIPWhiteLen++;
			}
			else if (wcscmp(l[1], STR_REMOTE_IP) == 0)
			{
				iprange = &gvar.reinRemoteIPWhite[gvar.reinRemoteIPWhiteLen];
				iprange->type = 0;
				swscanf(l[2], L"%d.%d.%d.%d", &a, &b, &c, &d);
				*(DWORD*)&(iprange->addr) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				gvar.reinRemoteIPWhiteLen++;
			}
			else if (wcscmp(l[1], STR_REMOTE_IP_RANGE) == 0)
			{
				iprange = &gvar.reinRemoteIPWhite[gvar.reinRemoteIPWhiteLen];
				iprange->type = 1;
				swscanf(l[2], L"%d.%d.%d.%d-%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1);
				*(DWORD*)&(iprange->addrStart) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				*(DWORD*)&(iprange->addrEnd) = (DWORD)(a1 << 24 | b1 << 16 | c1 << 8 | d1);
				gvar.reinRemoteIPWhiteLen++;
			}
		}
		else if (wcscmp(l[0], STR_REIN_LIST) == 0)
		{
			if (wcscmp(l[1], STR_PORT) == 0)
			{
				gvar.reinPort[gvar.reinPortLen] = _wtoi(l[2]);
				gvar.reinPortLen++;
			}
			else if (wcscmp(l[1], STR_PROCESS_NAME) == 0)
			{
				pro = &gvar.reinProcess[gvar.reinProcessLen];
				Unicode16ToChar8(l[2].GetBuffer(), pro->name, 50);
				pro->crc32 = crc32((BYTE*)l[2].GetBuffer(), lstrlenW(l[2].GetBuffer()));
				gvar.reinProcessLen++;
			}
			else if (wcscmp(l[1], STR_LOCAL_IP) == 0)
			{
				iprange = &gvar.reinLocalIP[gvar.reinLocalIPLen];
				iprange->type = 0;
				swscanf(l[2], L"%d.%d.%d.%d", &a, &b, &c, &d);
				*(DWORD*)&(iprange->addr) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				gvar.reinLocalIPLen++;
			}
			else if (wcscmp(l[1], STR_LOCAL_IP_RANGE) == 0)
			{
				iprange = &gvar.reinLocalIP[gvar.reinLocalIPLen];
				iprange->type = 1;
				swscanf(l[2], L"%d.%d.%d.%d-%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1);
				*(DWORD*)&(iprange->addrStart) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				*(DWORD*)&(iprange->addrEnd) = (DWORD)(a1 << 24 | b1 << 16 | c1 << 8 | d1);
				gvar.reinLocalIPLen++;
			}
			else if (wcscmp(l[1], STR_REMOTE_IP) == 0)
			{
				iprange = &gvar.reinRemoteIP[gvar.reinRemoteIPLen];
				iprange->type = 0;
				swscanf(l[2], L"%d.%d.%d.%d", &a, &b, &c, &d);
				*(DWORD*)&(iprange->addr) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				gvar.reinRemoteIPLen++;
			}
			else if (wcscmp(l[1], STR_REMOTE_IP_RANGE) == 0)
			{
				iprange = &gvar.reinRemoteIP[gvar.reinRemoteIPLen];
				iprange->type = 1;
				swscanf(l[2], L"%d.%d.%d.%d-%d.%d.%d.%d", &a, &b, &c, &d, &a1, &b1, &c1, &d1);
				*(DWORD*)&(iprange->addrStart) = (DWORD)(a << 24 | b << 16 | c << 8 | d);
				*(DWORD*)&(iprange->addrEnd) = (DWORD)(a1 << 24 | b1 << 16 | c1 << 8 | d1);
				gvar.reinRemoteIPLen++;
			}
		}
	}
	WaitForSingleObject(m_hGlobVarMutex, INFINITE);
	{
		memcpy(m_pGlobVar, &gvar, sizeof(GLOBVAR));
		SaveCfg();
		RefreshDataToControl();
	}
	ReleaseMutex(m_hGlobVarMutex);
	ReleaseSemaphore(m_hGlobVarSemap, gvar.dDllCount + 2, NULL);
}
