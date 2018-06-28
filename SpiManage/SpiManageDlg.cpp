
// SpiManageDlg.cpp : 实现文件
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


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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
		p->ShowWindow(SW_MINIMIZE);//必须先最小化
		p->ShowWindow(SW_RESTORE);//然后再恢复
	}

}



// CSpiManageDlg 对话框



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


// CSpiManageDlg 消息处理程序

BOOL CSpiManageDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标
	//防止多开程序
	HANDLE cfgMutex = CreateMutexW(NULL, FALSE, L"SpiMutexManage");
	hevent = CreateEventW(NULL, FALSE, FALSE, L"SpiEventManage");
	if (WaitForSingleObject(cfgMutex, 80) == WAIT_TIMEOUT)
	{
		//一旦发现多开，立即让第一个程序显式，本程序立即关闭
		CloseHandle(cfgMutex);
		SetEvent(hevent);
		CDialogEx::OnOK();
	}
	//不是多开，创建线程监视多开
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)EventThreadProc, NULL, 0, NULL);
	m_pTabMain = (CTabCtrl*)GetDlgItem(IDC_TAB1);
	m_pTabMain->InsertItem(0, L"配置", 0);
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
	else if (nID == SC_MINIMIZE) // 最小化窗口
	{
		m_nid.cbSize = (DWORD)sizeof(NOTIFYICONDATA);
		m_nid.hWnd = this->m_hWnd;
		m_nid.uID = IDR_MAINFRAME;
		m_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
		m_nid.uCallbackMessage = WM_SHOWTASK; // 自定义的消息名称 
		m_nid.hIcon = LoadIcon(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDR_MAINFRAME));
		::GetWindowTextW(this->m_hWnd, m_nid.szTip, 128);
		Shell_NotifyIcon(NIM_ADD, &m_nid); // 在托盘区添加图标 
		ShowWindow(SW_HIDE); // 隐藏主窗口
		return;
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSpiManageDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
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



LRESULT CSpiManageDlg::OnShowTask(WPARAM wParam, LPARAM lParam)//wParam接收的是图标的ID，lParam接收的是鼠标的动作----最小化到托盘
{
	if (wParam != IDR_MAINFRAME)
		return 1;
	if (WM_LBUTTONDBLCLK == lParam)
	{
		this->ShowWindow(SW_SHOWNORMAL);
		this->SetForegroundWindow();
		Shell_NotifyIcon(NIM_DELETE, &m_nid); // 托盘图标不显示
	}
	if (lParam == WM_RBUTTONDOWN)
	{
		//右击弹出托盘菜单

		//CMenu menu;
		//menu.LoadMenu(IDR_MENU2);//首先建立菜单项IDR_MENU2
		//CMenu *pPopUp = menu.GetSubMenu(0);
		//CPoint pt;
		//GetCursorPos(&pt);
		//SetForegroundWindow();
		//pPopUp->TrackPopupMenu(TPM_RIGHTBUTTON, pt.x, pt.y, this);
		//PostMessage(WM_NULL, 0, 0);

	}
	return 0;
}
