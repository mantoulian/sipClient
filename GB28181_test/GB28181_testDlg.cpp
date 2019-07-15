
// GB28181_testDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "GB28181_test.h"
#include "GB28181_testDlg.h"
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


// CGB28181_testDlg 对话框



CGB28181_testDlg::CGB28181_testDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_GB28181_TEST_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CGB28181_testDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CGB28181_testDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_PLAY, &CGB28181_testDlg::OnBnClickedButtonPlay)
END_MESSAGE_MAP()


// CGB28181_testDlg 消息处理程序

BOOL CGB28181_testDlg::OnInitDialog()
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

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CGB28181_testDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CGB28181_testDlg::OnPaint()
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
HCURSOR CGB28181_testDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//#define SERVER_ADDR		"192.168.10.80"
//#define SERVER_PORT		5060
//#define LOCAL_ADDR		"192.168.10.68"
//#define LOCAL_PORT		5060
void CGB28181_testDlg::OnBnClickedButtonPlay()
{
	//BOOL ret = FALSE;
	CString server_addr, local_addr, username, password;
	CString call_name;
	WORD server_port, local_port;
	CSDP local_sdp;
	char *buf = NULL;
	int buf_len = 0;


	server_addr = _T("192.168.10.80");
	server_port = 5060;
	local_addr = _T("192.168.10.68");
	local_port = 5060;

	if (!theApp.m_sip_client.init(server_addr, server_port, local_addr, local_port))
		return;

	//sdp
	buf = (char *)calloc(4096, 1);
	buf_len = sprintf_s(buf, 4096, "%s", "");
	if (buf_len < 0)
		return;
	local_sdp.from_buffer(buf, buf_len);
	theApp.m_sip_client.set_local_sdp(local_sdp);

	//register
	username = _T("1001");
	password = _T("1001");
	if (!theApp.m_sip_client.register_account(username, password))
		return;

	//invite
	call_name = _T("");
	theApp.m_sip_client.make_call(call_name);


}
