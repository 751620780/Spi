
// SpiManageDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "SpiManage.h"
#include "SpiManageDlg.h"
#include "afxdialogex.h"
#pragma warning(disable : 4996)

#define WM_SHOWTASK (WM_USER + 123)
#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()




HANDLE hevent;
DWORD WINAPI EventThreadProc(LPVOID lpParam)
{
	while (true)
	{
		WaitForSingleObject(hevent, INFINITE);
		CSpiManageDlg *p = (CSpiManageDlg*)(theApp.m_pMainWnd);
		p->ShowWindow(SW_MINIMIZE);//��������С��
		p->ShowWindow(SW_RESTORE);//Ȼ���ٻָ�
	}

}



// CSpiManageDlg �Ի���



CSpiManageDlg::CSpiManageDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SPIMANAGE_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSpiManageDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CSpiManageDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB1, &CSpiManageDlg::OnTcnSelchangeTab1)
	ON_MESSAGE(WM_SHOWTASK, &CSpiManageDlg::OnShowTask)
END_MESSAGE_MAP()


// CSpiManageDlg ��Ϣ�������

BOOL CSpiManageDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��
	//��ֹ�࿪����
	HANDLE cfgMutex = CreateMutexW(NULL, FALSE, L"SpiMutexManage");
	hevent = CreateEventW(NULL, FALSE, FALSE, L"SpiEventManage");
	if (WaitForSingleObject(cfgMutex, 80) == WAIT_TIMEOUT)
	{
		//һ�����ֶ࿪�������õ�һ��������ʽ�������������ر�
		CloseHandle(cfgMutex);
		SetEvent(hevent);
		CDialogEx::OnOK();
	}
	//���Ƕ࿪�������̼߳��Ӷ࿪
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EventThreadProc, NULL, 0, NULL);
	m_pTabMain = (CTabCtrl*)GetDlgItem(IDC_TAB1);
	m_pTabMain->InsertItem(0, L"����", 0);
	m_CfgDlg.Create(IDD_DIALOG_CFG, m_pTabMain);
	CRect clientRC;
	m_pTabMain->GetClientRect(clientRC);
	clientRC.DeflateRect(2, 22, 2,2);
	m_CfgDlg.MoveWindow(clientRC);
	m_CfgDlg.ShowWindow(SW_SHOW);
	m_pTabMain->SetCurSel(0);
	return TRUE;
}

void CSpiManageDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else if (nID == SC_MINIMIZE) // ��С������
	{
		m_nid.cbSize = (DWORD)sizeof(NOTIFYICONDATA);
		m_nid.hWnd = this->m_hWnd;
		m_nid.uID = IDR_MAINFRAME;
		m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
		m_nid.uCallbackMessage = WM_SHOWTASK; // �Զ������Ϣ���� 
		m_nid.hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME));
		::GetWindowTextW(this->m_hWnd, m_nid.szTip, 128);
		Shell_NotifyIcon(NIM_ADD, &m_nid); // �����������ͼ�� 
		ShowWindow(SW_HIDE); // ����������
		return;
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CSpiManageDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CSpiManageDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CSpiManageDlg::OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult)
{
	int pos = m_pTabMain->GetCurSel();
	if (pos == 0)
	{
		m_CfgDlg.ShowWindow(SW_SHOW);
	}
	*pResult = 0;
}



LRESULT CSpiManageDlg::OnShowTask(WPARAM wParam, LPARAM lParam)//wParam���յ���ͼ���ID��lParam���յ������Ķ���----��С��������
{
	if (wParam != IDR_MAINFRAME)
		return 1;
	if (WM_LBUTTONDBLCLK == lParam)
	{
		this->ShowWindow(SW_SHOWNORMAL);
		this->SetForegroundWindow();
		Shell_NotifyIcon(NIM_DELETE, &m_nid); // ����ͼ�겻��ʾ
	}
	if (lParam == WM_RBUTTONDOWN)
	{
		//�һ��������̲˵�

		//CMenu menu;
		//menu.LoadMenu(IDR_MENU2);//���Ƚ����˵���IDR_MENU2
		//CMenu *pPopUp = menu.GetSubMenu(0);
		//CPoint pt;
		//GetCursorPos(&pt);
		//SetForegroundWindow();
		//pPopUp->TrackPopupMenu(TPM_RIGHTBUTTON, pt.x, pt.y, this);
		//PostMessage(WM_NULL, 0, 0);

	}
	return 0;
}
