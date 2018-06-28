
// SpiManageDlg.h : 头文件
//

#pragma once

#include "CfgDlg.h"
// CSpiManageDlg 对话框
class CSpiManageDlg : public CDialogEx
{
// 构造
public:
	CSpiManageDlg(CWnd* pParent = NULL);	// 标准构造函数
	
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SPIMANAGE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持

// 实现
protected:
	HICON m_hIcon;
	CTabCtrl *m_pTabMain = NULL;
	int pos;
	CCfgDlg  m_CfgDlg;
	NOTIFYICONDATA m_nid;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	LRESULT OnShowTask(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult);
};
