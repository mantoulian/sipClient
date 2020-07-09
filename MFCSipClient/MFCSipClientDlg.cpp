#pragma once
// MFCSipClientDlg.cpp : 实现文件
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


// CMFCSipClientDlg 对话框



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
	ON_BN_CLICKED(IDC_BUTTON_hangup, &CMFCSipClientDlg::OnBnClickedButton_hangup)
END_MESSAGE_MAP()


// CMFCSipClientDlg 消息处理程序

BOOL CMFCSipClientDlg::OnInitDialog()
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

	// TODO: 在此添加额外的初始化代码
	m_edit_username.SetWindowTextW(_T("1001"));
	m_edit_password.SetWindowTextW(_T("1001"));
	m_edit_sev_port.SetWindowTextW(_T("5060"));
	m_edit_sev_address.SetWindowTextW(_T("192.168.100.100"));
	m_edit_rtsp_address.SetWindowTextW(_T("rtsp://admin:admin@192.168.66.10:554"));
	m_edit_local_address.SetWindowTextW(_T("192.168.100.82"));
	m_edit_contact.SetWindowTextW(_T("1002"));

	


	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMFCSipClientDlg::OnPaint()
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
HCURSOR CMFCSipClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//注册
void CMFCSipClientDlg::OnBnClickedButtonPlay()
{
	//CString str_username, str_password, sev_addr, sev_port;
	//WORD nsev_port = 0;

	//设置sdp
	//theApp.m_sip_client.set_local_sdp(theApp.m_rtsp_client.get_SDP());
	//m_edit_username.GetWindowTextW(str_username);
	//m_edit_password.GetWindowTextW(str_password);
	//m_edit_sev_address.GetWindowTextW(sev_addr);
	//m_edit_sev_port.GetWindowTextW(sev_port);
	//nsev_port = _ttoi(sev_port);
	


	if (FALSE == theApp.m_sip_client.register_account())
	{
		print_log(_T("sip注册失败"));
		return;
	}
	Sleep(500);
	CLIENT_STATUS cs = theApp.m_sip_client.get_client_status();
	if(cs == wait)
	{
		print_log(_T("sip注册成功"));
		return;
	}
	else
	{
		print_log(_T("sip注册失败"));
		return;
	}


}

//呼叫
void CMFCSipClientDlg::OnBnClickedButtonMakeCall()
{
	CSDP sdp;
	CString str_contact, str_log, str_video_fmtp;

	//设置本地sdp
	sdp = theApp.m_rtsp_client.get_SDP();
	//sdp.m_bVideoMedia = FALSE;
	if (!theApp.m_sip_client.set_sdp(sdp))
		return;
	//设置send cache
	theApp.m_rtsp_client.AddCache(&theApp.m_send_cache);
	theApp.m_sip_client.set_send_cache(&theApp.m_send_cache);



	//呼叫
	m_edit_contact.GetWindowTextW(str_contact);
	if (theApp.m_sip_client.make_call(str_contact))
	{
		str_log.Format(_T("呼叫%s"), str_contact);
		print_log(str_log);
	}
	else
	{
		str_log.Format(_T("呼叫%s失败"), str_contact);
		print_log(str_log);
		return;
	}



	//播放
	CWnd* pImageWnd = GetDlgItem(IDC_STATIC_SHOW);
	if (pImageWnd == NULL)
	{
		return;
	}

	int answer_time = 60;
	CLIENT_STATUS client_stu;
	while (answer_time)
	{
		client_stu = theApp.m_sip_client.get_client_status();
		if (client_stu == calling)
		{
			//设置 recv cache
			CRtpPacketCache *cache = theApp.m_sip_client.get_recv_cache();
			BOOL play2_ok = FALSE;
			if (NULL == cache)
				return;
			theApp.m_player_2.SetRtpCache(cache);
			play2_ok = theApp.m_player_2.Play(theApp.m_sip_client.get_sdp().m_strVideoFmtp,
				pImageWnd);
			break;
		}

		Sleep(1000);
		answer_time --;
	}


	return;

}


int incoming_call(CSipPacketInfo *pack_info)
{
	if (NULL == pack_info)
		return -1;

	//接听
	if (!theApp.m_sip_client.call_answer(pack_info))
		return -2;


	//初始化播放器
	//if (FALSE == theApp.m_player_2.init(theApp.m_sip_client.get_local_sdp().m_strVideoFmtp))
	//{
	//	CMFCSipClientDlg::print_log(_T("播放器2初始化失败"));
	//	return -3;
	//}
	//CWnd* pImageWnd = GetDlgItem(IDC_STATIC_SHOW);
	////CWnd* pImageWnd;
	//if (pImageWnd == NULL)
	//{
	//	return;
	//}
	//int answer_time = 60;
	//while (answer_time)
	//{
	//	if (theApp.m_sip_client.get_client_status() == calling)
	//	{
	//		theApp.m_player_2.Play(pImageWnd);
	//		break;
	//	}
	//	Sleep(1000);
	//	answer_time--;
	//}
	//


	return 0;
}

//初始化
void CMFCSipClientDlg::OnBnClickedButtonInit()
{
	CString user, passwd, sev_addr, sev_port, str_rtsp_url;
	WORD n_s_port;

	//rtsp clinet init
	if (FALSE == theApp.m_rtsp_client.init())
	{
		print_log(_T("rtsp客户端初始化失败"));
		return;
	}

	m_edit_sev_address.GetWindowTextW(sev_addr);
	m_edit_sev_port.GetWindowTextW(sev_port);
	m_edit_username.GetWindowTextW(user);
	m_edit_password.GetWindowTextW(passwd);
	n_s_port = _ttoi(sev_port);

	if (FALSE == theApp.m_sip_client.init(user, passwd, sev_addr, n_s_port))
	{
		print_log(_T("sip客户端初始化失败"));
		return;
	}
	if (!theApp.m_player_1.init())
	{
		print_log(_T("播放器1 初始化失败"));
		return;
	}
	if (!theApp.m_player_2.init())
	{
		print_log(_T("播放器2 初始化失败"));
		return;
	}

	print_log(_T("sip客户端初始化成功"));

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

//1 使用rtsp连接摄像头 2 本地显示
void CMFCSipClientDlg::OnBnClickedButtonConnectRtsp()
{
	CString str_rtsp_url;


	//设置cache
	theApp.m_rtsp_client.AddCache(&theApp.m_local_play_cache);

	//链接摄像头
	m_edit_rtsp_address.GetWindowTextW(str_rtsp_url);
	if (FALSE == theApp.m_rtsp_client.open_url(str_rtsp_url))
	{
		print_log(_T("链接rtsp失败"));
		return;
	}

	//显示
	CSDP sdp;
	CWnd* pImageWnd = GetDlgItem(IDC_STATIC_ShowLocal);
	if (NULL == pImageWnd)
	{
		theApp.m_rtsp_client.teardown();
		return;
	}
	sdp = theApp.m_rtsp_client.get_SDP();
	if (sdp.m_strVideoFmtp.IsEmpty())
	{
		theApp.m_rtsp_client.teardown();
		return;
	}
	theApp.m_player_1.SetRtpCache(&theApp.m_local_play_cache);
	if (!theApp.m_player_1.Play(sdp.m_strVideoFmtp, pImageWnd))
	{
		theApp.m_rtsp_client.teardown();
		return;
	}

	return;
}


void CMFCSipClientDlg::OnBnClickedButton_hangup()
{
	// TODO: 在此添加控件通知处理程序代码

	if (theApp.m_sip_client.get_client_status() == calling)
	{
		if (!theApp.m_sip_client.hangup())
		{
			print_log(_T("结束通话失败"));
			return;

		}
	}
}
