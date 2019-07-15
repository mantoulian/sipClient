
// GB28181_test.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
#include "../SipClient/Rtp.h"
#include "../SipClient/SipClient.h"
#include "../SipClient/SDP.h"


// CGB28181_testApp: 
// �йش����ʵ�֣������ GB28181_test.cpp
//

class CGB28181_testApp : public CWinApp
{
public:
	CGB28181_testApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()

public:
	CSipClient m_sip_client;
	CRtpPlayer m_player;
	CRtpPacketCache m_rtp_cache;

};

extern CGB28181_testApp theApp;