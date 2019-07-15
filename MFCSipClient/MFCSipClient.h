
// MFCSipClient.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号
#include "../SipClient/Rtp.h"
#include "../SipClient/SipClient.h"
#include "../SipClient/RtspClient.h"
#include "../SipClient/SDP.h"


// CMFCSipClientApp: 
// 有关此类的实现，请参阅 MFCSipClient.cpp
//

class CMFCSipClientApp : public CWinApp
{
public:
	CMFCSipClientApp();

// 重写
public:
	virtual BOOL InitInstance();

	//CString build_log(CString str_log);

// 实现

	DECLARE_MESSAGE_MAP()

public:
	CRtspClient m_rtsp_client;
	CSipClient m_sip_client;
	CRtpPlayer m_player_1;
	CRtpPlayer m_player_2;
	CRtpPacketCache local_play_cache;
	CRtpPacketCache send_cache;
	CRtpPacketCache recv_cache;

};

extern CMFCSipClientApp theApp;