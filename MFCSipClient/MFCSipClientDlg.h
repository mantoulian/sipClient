
// MFCSipClientDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// CMFCSipClientDlg 对话框
class CMFCSipClientDlg : public CDialogEx
{
// 构造
public:
	CMFCSipClientDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCSIPCLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	void print_log(CString str_log);
	afx_msg void OnBnClickedButtonPlay();
	CEdit m_edit_status;
	CEdit m_edit_sev_address;
	CEdit m_edit_sev_port;
	CEdit m_edit_username;
	CEdit m_edit_password;
	CEdit m_edit_contact;
	afx_msg void OnBnClickedButtonMakeCall();
	afx_msg void OnBnClickedButtonInit();
	CEdit m_edit_local_address;
	afx_msg void OnBnClickedButtonConnectRtsp();
	CEdit m_edit_rtsp_address;
};
