
// MFCSipClient.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������
#include "../SipClient/Rtp.h"
#include "../SipClient/SipClient.h"
#include "../SipClient/RtspClient.h"
#include "../SipClient/SDP.h"


// CMFCSipClientApp: 
// �йش����ʵ�֣������ MFCSipClient.cpp
//

class CMFCSipClientApp : public CWinApp
{
public:
	CMFCSipClientApp();

// ��д
public:
	virtual BOOL InitInstance();

	//CString build_log(CString str_log);

// ʵ��

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