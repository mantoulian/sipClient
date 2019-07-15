#pragma once
// MFCSipClientDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "MFCSipClient.h"
#include "MFCSipClientDlg.h"
#include "afxdialogex.h"

#include "../SipClient/Rtp.h"
#include "../SipClient/SipClient.h"
#include "../SipClient/RtspClient.h"
#include "../SipClient/SDP.h"

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


// CMFCSipClientDlg �Ի���



CMFCSipClientDlg::CMFCSipClientDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MFCSIPCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCSipClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_SHOW_STATUS, m_edit_status);
	DDX_Control(pDX, IDC_EDIT_SERVER_ADDRESS, m_edit_sev_address);
	DDX_Control(pDX, IDC_EDIT_SERVER_PORT, m_edit_sev_port);
	DDX_Control(pDX, IDC_EDIT_USERNAME, m_edit_username);
	DDX_Control(pDX, IDC_EDIT_PASSWORD, m_edit_password);
	DDX_Control(pDX, IDC_EDIT_CONTACT, m_edit_contact);
	DDX_Control(pDX, IDC_EDIT_LOCAL_ADDRESS, m_edit_local_address);
	DDX_Control(pDX, IDC_EDIT_RTSP_ADDRESS, m_edit_rtsp_address);
}

BEGIN_MESSAGE_MAP(CMFCSipClientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_PLAY, &CMFCSipClientDlg::OnBnClickedButtonPlay)
	ON_BN_CLICKED(IDC_BUTTON_MAKE_CALL, &CMFCSipClientDlg::OnBnClickedButtonMakeCall)
	ON_BN_CLICKED(IDC_BUTTON_INIT, &CMFCSipClientDlg::OnBnClickedButtonInit)
	ON_BN_CLICKED(IDC_BUTTON_CONNECT_RTSP, &CMFCSipClientDlg::OnBnClickedButtonConnectRtsp)
END_MESSAGE_MAP()


// CMFCSipClientDlg ��Ϣ�������

BOOL CMFCSipClientDlg::OnInitDialog()
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

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	m_edit_username.SetWindowTextW(_T("1001"));
	m_edit_password.SetWindowTextW(_T("1001"));
	m_edit_sev_port.SetWindowTextW(_T("5060"));
	m_edit_sev_address.SetWindowTextW(_T("192.168.100.60"));
	m_edit_rtsp_address.SetWindowTextW(_T("rtsp://192.168.100.80:554"));
	m_edit_local_address.SetWindowTextW(_T("192.168.100.82"));
	m_edit_contact.SetWindowTextW(_T("1002"));

	


	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

void CMFCSipClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CMFCSipClientDlg::OnPaint()
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
HCURSOR CMFCSipClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CMFCSipClientDlg::OnBnClickedButtonPlay()
{
	CString str_username, str_password;

	//����sdp
	theApp.m_sip_client.set_local_sdp(theApp.m_rtsp_client.get_SDP());


	m_edit_username.GetWindowTextW(str_username);
	m_edit_password.GetWindowTextW(str_password);
	if (FALSE == theApp.m_sip_client.register_account(str_username, str_password))
	{
		print_log(_T("sipע��ʧ��"));
		return;
	}
	Sleep(500);
	if(theApp.m_sip_client.get_client_status() == register_ok)
	{
		print_log(_T("sipע��ɹ�"));
		return;
	}
	else
	{
		print_log(_T("sipע��ʧ��"));
		return;
	}


}


//#define ANSWER_WAIT_TIME	60
void CMFCSipClientDlg::OnBnClickedButtonMakeCall()
{
	CString str_contact, str_log, str_video_fmtp;

	//����
	m_edit_contact.GetWindowTextW(str_contact);
	if (theApp.m_sip_client.make_call(str_contact, FALSE, 0, TRUE, 0))
	{
		str_log.Format(_T("����%s"), str_contact);
		print_log(str_log);
	}
	else
	{
		str_log.Format(_T("����%sʧ��"), str_contact);
		print_log(str_log);
		return;
	}



	//��ʼ��������
	if (FALSE == theApp.m_player_2.init(theApp.m_sip_client.get_local_sdp().get_video_fmtp()))
	{
		print_log(_T("������2��ʼ��ʧ��"));
		return;
	}
	CWnd* pImageWnd = GetDlgItem(IDC_STATIC_SHOW);
	if (pImageWnd == NULL)
	{
		return;
	}
	int answer_time = 60;
	while (answer_time)
	{
		if (theApp.m_sip_client.get_client_status() == calling)
		{
			theApp.m_player_2.Play(pImageWnd);
			break;
		}
		Sleep(1000);
		answer_time--;
	}


	return;

}


void incoming_call(CSipPacketInfo *packet)
{
	if (NULL == packet)
		return;

	if (theApp.m_sip_client.call_answer(packet))
	{

		//��ʼ��������
		if (FALSE == theApp.m_player_2.init(theApp.m_sip_client.get_local_sdp().get_video_fmtp()))
		{
			//CMFCSipClientDlg::print_log(_T("������2��ʼ��ʧ��"));
			return;
		}
		//CWnd* pImageWnd = CWnd::GetDlgItem(IDC_STATIC_SHOW);
		CWnd* pImageWnd;
		if (pImageWnd == NULL)
		{
			return;
		}
		int answer_time = 60;
		while (answer_time)
		{
			if (theApp.m_sip_client.get_client_status() == calling)
			{
				theApp.m_player_2.Play(pImageWnd);
				break;
			}
			Sleep(1000);
			answer_time--;
		}
	}




	return;
}

void CMFCSipClientDlg::OnBnClickedButtonInit()
{
	CString str_sev_address, str_sev_port, str_local_address;
	CString str_log, str_rtsp_url;
	unsigned short sev_port = 0;
	int nLength = 0;

	//rtsp clinet init
	if (FALSE == theApp.m_rtsp_client.init())
	{
		print_log(_T("rtsp�ͻ��˳�ʼ��ʧ��"));
		return;
	}
	//m_edit_rtsp_address.GetWindowTextW(str_rtsp_url);
	//if (NULL == theApp.m_rtsp_client.open_url(str_rtsp_url))
	//{
	//	print_log(_T("����rtspʧ��"));
	//	return;
	//}
	
	m_edit_sev_address.GetWindowTextW(str_sev_address);
	m_edit_sev_port.GetWindowTextW(str_sev_port);
	m_edit_local_address.GetWindowTextW(str_local_address);
	sev_port = _ttoi(str_sev_port);
	if (FALSE == theApp.m_sip_client.init(str_sev_address, sev_port, str_local_address))
	{
		print_log(_T("sip�ͻ��˳�ʼ��ʧ��"));
		return;
	}




	print_log(_T("sip�ͻ��˳�ʼ���ɹ�"));


	theApp.m_sip_client.set_coming_call_function(incoming_call);
	//cache ����
	//������ʾcache
	theApp.m_rtsp_client.AddCache(&theApp.local_play_cache);
	theApp.m_player_1.SetRtpCache(&theApp.local_play_cache);
	//����cache
	theApp.m_rtsp_client.AddCache(&theApp.send_cache);
	theApp.m_sip_client.set_send_cache(&theApp.send_cache);
	//����cache
	theApp.m_sip_client.set_recv_cache(&theApp.recv_cache);
	theApp.m_player_2.SetRtpCache(&theApp.recv_cache);

	return;
}

void CMFCSipClientDlg::print_log(CString str_log)
{
	CString  m_date;
	SYSTEMTIME stTime;
	int nLength = 0;


	GetLocalTime(&stTime);
	WORD wYear = stTime.wYear;
	WORD wMonth = stTime.wMonth;
	WORD wDay = stTime.wDay;
	WORD wHour = stTime.wHour;
	WORD wMinute = stTime.wMinute;
	WORD wSecond = stTime.wSecond;
	m_date.Format(_T("%4d-%d-%2d %2d:%2d:%2d  %s\r\n"), wYear, wMonth, wDay, wHour, wMinute, wSecond, str_log);

	nLength = m_edit_status.SendMessage(WM_GETTEXTLENGTH);
	m_edit_status.SetSel(nLength, nLength);
	m_edit_status.ReplaceSel(m_date);

}


void CMFCSipClientDlg::OnBnClickedButtonConnectRtsp()
{
	CString str_rtsp_url, str_log;

	//��������ͷ
	m_edit_rtsp_address.GetWindowTextW(str_rtsp_url);
	if (NULL == theApp.m_rtsp_client.open_url(str_rtsp_url))
	{
		print_log(_T("����rtspʧ��"));
		return;
	}

	//��ʾ
	if (FALSE == theApp.m_player_1.init(theApp.m_rtsp_client.get_SDP().get_video_fmtp()))
	{
		print_log(_T("������1��ʼ��ʧ��"));
		return;
	}
	CWnd* pImageWnd = GetDlgItem(IDC_STATIC_ShowLocal);
	if (pImageWnd != NULL)
		theApp.m_player_1.Play(pImageWnd);

	print_log(_T("rtsp���ӳɹ�"));
	return;

}
