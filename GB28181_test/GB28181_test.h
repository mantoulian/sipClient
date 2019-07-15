
// GB28181_test.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号
#include "../SipClient/Rtp.h"
#include "../SipClient/SipClient.h"
#include "../SipClient/SDP.h"


// CGB28181_testApp: 
// 有关此类的实现，请参阅 GB28181_test.cpp
//

class CGB28181_testApp : public CWinApp
{
public:
	CGB28181_testApp();

// 重写
public:
	virtual BOOL InitInstance();

// 实现

	DECLARE_MESSAGE_MAP()

public:
	CSipClient m_sip_client;
	CRtpPlayer m_player;
	CRtpPacketCache m_rtp_cache;

};

extern CGB28181_testApp theApp;