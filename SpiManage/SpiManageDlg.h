
// SpiManageDlg.h : ͷ�ļ�
//

#pragma once

#include "CfgDlg.h"
// CSpiManageDlg �Ի���
class CSpiManageDlg : public CDialogEx
{
// ����
public:
	CSpiManageDlg(CWnd* pParent = NULL);	// ��׼���캯��
	
// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SPIMANAGE_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��

// ʵ��
protected:
	HICON m_hIcon;
	CTabCtrl *m_pTabMain = NULL;
	int pos;
	CCfgDlg  m_CfgDlg;
	NOTIFYICONDATA m_nid;
	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	LRESULT OnShowTask(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnTcnSelchangeTab1(NMHDR *pNMHDR, LRESULT *pResult);
};
