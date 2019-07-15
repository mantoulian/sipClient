
// MFCSipClientDlg.h : ͷ�ļ�
//

#pragma once
#include "afxwin.h"


// CMFCSipClientDlg �Ի���
class CMFCSipClientDlg : public CDialogEx
{
// ����
public:
	CMFCSipClientDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFCSIPCLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
