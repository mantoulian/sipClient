#include "stdafx.h"
#include "RtspClient.h"

#define RTSP_MESSAGE_SIZE	1500
#define RTP_BUF_SIZE	4096


typedef struct rtsp_message
{
	int nLen;
	char szData[RTSP_MESSAGE_SIZE];
}RTSP_MESSAGE;

typedef enum respond_status
{
	ok = 200,
	other
}RESPOND_STATUS;



//����Options��Ϣ 
BOOL buildOptionsMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl)
{
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char * p = T2A(strRtspUrl);
	int count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE, 
		"OPTIONS %s RTSP/1.0\r\n""CSeq: %d\r\n""\r\n", p, nCseq);
	rtspMess.nLen = count;
	return true;
}

//����Describe��Ϣ
BOOL buildDescribeMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl)
{
	if (strRtspUrl.IsEmpty())
	{
		return false;
	}
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char * p = T2A(strRtspUrl);
	int count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE, 
		"DESCRIBE %s RTSP/1.0\r\n""CSeq: %d\r\n""\r\n", p, nCseq);
	rtspMess.nLen = count;

	return true;
}

//����setup��Ϣ
BOOL buildSetUpMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString  strTrackID, int nRtpPort)
{
	if (strRtspUrl.IsEmpty())
	{
		return false;
	}
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char * p = T2A(strRtspUrl);
	const char *szTrackId = T2A(strTrackID);
	int count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"SETUP %s/%s RTSP/1.0\r\n"
		"CSeq: %d\r\n"
		"Transport: RTP/AVP;unicast;client_port=%d\r\n"
		"\r\n",
		p, szTrackId, nCseq, nRtpPort);
	rtspMess.nLen = count;

	return true;
}

//����play��Ϣ
BOOL buildPlayMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString strSession)
{
	if (strRtspUrl.IsEmpty())
	{
		return false;
	}
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char *p = T2A(strRtspUrl);
	const char *pSession = T2A(strSession);

	int count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"PLAY %s RTSP/1.0\r\n"
		"CSeq: %d\r\n"
		"Session:%s\r\n"
		"\r\n",
		p, nCseq, pSession);
	rtspMess.nLen = count;

	return true;
}


//����teardown��Ϣ
BOOL buildTeardownMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString strSession)
{
	if (strRtspUrl.IsEmpty())
	{
		return false;
	}
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char *p = T2A(strRtspUrl);
	const char *pSession = T2A(strSession);

	int count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"TEARDOWN %s RTSP/1.0\r\n"
		"CSeq: %d\r\n"
		"Session:%s\r\n"
		"\r\n",
		p, nCseq, pSession);
	rtspMess.nLen = count;

	return true;
}

//����������Ϣ
BOOL buildGetParamemter(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString strSession)
{
	int count = 0;
	if (strRtspUrl.IsEmpty() || strSession.IsEmpty())
	{
		return false;
	}
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	const char *p = T2A(strRtspUrl);
	const char *pSe = T2A(strSession);
	count = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"GET_PARAMETER %s RTSP/1.0\r\n"
		"CSeq: %d\r\n"
		"Session:%s\r\n"
		"\r\n",
		p, nCseq, pSe);
	rtspMess.nLen = count;

	return true;
}

//ȡ��rtsp��ַ�е�ip�Ͷ˿�
BOOL rtspUrlToAddr(CString strRtspUrl, CString &IP, unsigned short &nPort)
{

	unsigned short port = 0;


	USES_CONVERSION;
	const char * p = T2A(strRtspUrl);
	if (p == NULL)
	{
		return false;
	}

	p = strstr(p, ":");//�ҵ�ð��
	if (p == NULL)
	{
		return false;
	}
	p+=3;//����ð�ź�2��б��
	while (*p != ':')//����ð�Ž���
	{
		IP += *p;
		p++;
	}
	p++;

	//�˿�
	while (*p != '\0')
	{
		if (*p >= 48 && *p <= 57)
		{
			port = port * 10 + (*p - 48);
		}
		p++;
	}
	nPort = port;


	return true;
}

//������Ӧ��Ϣ�е�״̬��Cseq
BOOL ProcessRespondMessage(RTSP_MESSAGE &rtspMess, RESPOND_STATUS &status, int &nCseq)
{
	char *szTemp = NULL;
	int nRepStatu = 0, nCseqT = 0;


	szTemp = strstr(rtspMess.szData, " ");//�ҵ���һ���ո�
	if (szTemp == NULL)
	{
		return false;
	}
	szTemp++;


	while (*szTemp != ' ')//�����ո����
	{
		if (*szTemp >= 48 && *szTemp <= 57)//���������
			nRepStatu = nRepStatu * 10 + (*szTemp - 48);
		szTemp++;
	}
	switch (nRepStatu)//ֻ�ж���ok��200��״̬
	{
	case 200:
		status = ok;
		break;
	default:
		status = other;
		break;
	}

	//����cseq
	szTemp = strstr(rtspMess.szData, "CSeq");
	if (szTemp == NULL)
	{
		return false;
	}
	szTemp += 6;
	while (*szTemp != 13)
	{
		if (*szTemp >= 48 && *szTemp <= 57)
		{
			nCseqT = nCseqT * 10 + (*szTemp - 48);
		}
		szTemp++;
	}

	if (nCseqT > 0)
	{
		nCseq = nCseqT;
	}
	else
	{
		return false;
	}

	return true;
}

BOOL GetSession(RTSP_MESSAGE &rtspMess, CString &strSession)
{

	CString strSessionTemp;
	char *szTemp = NULL;

	szTemp = strstr(rtspMess.szData, "Session");
	if (szTemp != NULL)
	{

		while (*szTemp != ' ')//�����ո�
		{
			szTemp++;
		}
		szTemp++;

		while (*szTemp != '\r')//\r ����
		{
			strSessionTemp += *szTemp;
			szTemp++;
		}

		strSession = strSessionTemp;
		return true;
	}


	return false;
}



CRtspClient::CRtspClient()
{
	m_usCameraPort = 0;
	m_nCSeq=0;
	m_bWork = FALSE;

	m_hRecvAudioThread=NULL;
	m_hRecvVideoThread=NULL;
	m_hSendHeartbeatThread = NULL;
}


CRtspClient::~CRtspClient()
{
	m_bWork = FALSE;
	Sleep(50);

	m_TcpSockRtsp.Close();
	m_udpAudio.Close();
	m_udpVideo.Close();

	CloseHandle(m_hRecvAudioThread);
	CloseHandle(m_hRecvVideoThread);
	CloseHandle(m_hSendHeartbeatThread);

}

BOOL CRtspClient::init(unsigned short usRtspPort, unsigned short usRtpAudioPort, unsigned short usRtpVideoPort)
{
	CString strIP;
	unsigned short usPort = 0;

	m_bWork = false;
	m_usLocalRtspPort = usRtspPort;
	m_usLocalRtpVideoPort = usRtpAudioPort;
	m_usLocalRtpAudioPort = usRtpAudioPort;
	m_nCSeq = 0;


	//rtsp����tcpЭ��
	if (!m_TcpSockRtsp.Create(usRtspPort))
	{
		return false;
	}
	//���¶˿ں�
	if (!m_TcpSockRtsp.GetSockName(strIP, usPort))
	{
		return false;
	}
	m_usLocalRtspPort = usPort;
	//������ģʽ
	if (!m_TcpSockRtsp.EnableNonBlocking(true))
	{
		return false;
	}


	//if (!m_UdpSockRtpAudio.Create(usRtpAudioPort, SOCK_DGRAM))
	//{
	//	return false;
	//}
	//if (usRtpAudioPort == 0)
	//{
	//	if (!m_UdpSockRtpAudio.GetSockName(strIP, usPort))
	//	{
	//		return false;
	//	}
	//	m_usRtpAudioPort = usPort;
	//}
	//else
	//{
	//	m_usRtpAudioPort = usPort;
	//}

	//���������߳�
	//m_hRecvAudioThread = ::CreateThread(NULL, 0, ReceiveAudioThread, this, CREATE_SUSPENDED, NULL);
	//if (NULL == m_hRecvAudioThread)
	//{
	//	return FALSE;
	//}
	

	//if (!m_UdpSockRtpVideo.Create(usRtpVideoPort, SOCK_DGRAM))
	//{
	//	return false;
	//}
	////if (usRtpVideoPort == 0)
	//{
	//	if (!m_UdpSockRtpVideo.GetSockName(strIP, usPort))
	//	{
	//		return false;
	//	}
	//	m_usRtpVideoPort = usPort;
	//}
	////else
	//{
	//	m_usRtpVideoPort = usPort;
	//}


	//m_hRecvVideoThread = ::CreateThread(NULL, 0, ReceiveVideoThread, this, CREATE_SUSPENDED, NULL);
	//if (NULL == m_hRecvVideoThread)
	//{
	//	return FALSE;
	//}
	//
	

	//���������߳�
	m_hSendHeartbeatThread = ::CreateThread(NULL, 0, SendHeartbeat, this, CREATE_SUSPENDED, NULL);
	if (NULL == m_hSendHeartbeatThread)
	{
		return FALSE;
	}

	m_bWork = TRUE;

	return TRUE;
}


//��������ͷ
BOOL CRtspClient::open_url(CString strUrl)
{
	RTSP_MESSAGE requestMess, respondMess;
	int nCount = 0,nRepCseq = 0;
	BOOL bRet = FALSE;
	RESPOND_STATUS rtspStatus = other;
	CString strIP;
	unsigned short usPort;

	m_strRtspUrl = strUrl;
	//��������ͷ
	if (rtspUrlToAddr(strUrl, m_strCameraIP, m_usCameraPort) == false)
	{
		return false;
	}
	if (m_TcpSockRtsp.Connect(m_strCameraIP, m_usCameraPort) ==false)
	{
		return false;
	}

	//���� options ��Ϣ
	m_nCSeq++;
	if (!buildOptionsMessage(requestMess, m_nCSeq, strUrl))
	{
		return bRet;
	}
	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(50);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
	{
		return bRet;
	}
	//�����Ӧ��Ϣ״̬�ǲ���ok
	if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
	{
		if (rtspStatus != ok)
		{
			return bRet;
		}
	}



	//���� describe ��Ϣ���õ�����ͷ��sdp
	m_nCSeq++;
	if (!buildDescribeMessage(requestMess, m_nCSeq, strUrl))
	{
		return bRet;
	}
	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(50);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
	{
		return bRet;
	}
	//�����Ӧ��Ϣ״̬�ǲ���ok
	if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
	{
		if (rtspStatus != ok)
		{
			return bRet;
		}
	}
	//��ȡsdp
	char *sdp = strstr(respondMess.szData, "\r\n\r\nv=");
	if (sdp != NULL)
	{
		sdp += 4;
		int rtsp_head_len = sdp - respondMess.szData;
		int sdp_len = nCount - rtsp_head_len;
		//char *sdp_buf = new char[sdp_len + 1];
		//memcpy(sdp_buf, sdp, sdp_len);
		bRet = m_CameraSdp.from_buffer(sdp, sdp_len);
		//delete sdp_buf;
		if (FALSE == bRet)
			return bRet;
	}



	//����setup��Ϣ
	//SDP_INFO *sdp_info = m_CameraSdp.get_sdp_info();
	//if (NULL == sdp_info)
	//	return FALSE;
	if (m_CameraSdp.get_audio_media())//���sdp������Ƶ��Ϣ��
	{
		if (!m_udpAudio.Create(m_usLocalRtpAudioPort, SOCK_DGRAM))
			return FALSE;
		if (!m_udpAudio.GetSockName(strIP, usPort))
			return FALSE;
		
		m_usLocalRtpAudioPort = usPort;


		m_nCSeq++;
		if (!buildSetUpMessage(requestMess, m_nCSeq++, strUrl,
			m_CameraSdp.get_audio_track_id(), m_usLocalRtpAudioPort))
		{
			return bRet;
		}

		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(50);
		nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (nCount < 0)
		{
			return bRet;
		}
		//�����Ӧ��Ϣ״̬�ǲ���ok
		if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
		{
			if (rtspStatus != ok)
			{
				return bRet;
			}
		}
		//��ȡsession(��Ƶ����Ƶ��sessionӦ����һ����)
		if (!GetSession(respondMess, m_strSession))
		{
			return bRet;
		}
		//���������߳�
		m_hRecvAudioThread = ::CreateThread(NULL, 0, ReceiveAudioThread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_hRecvAudioThread)
		{
			return FALSE;
		}
		::ResumeThread(m_hRecvAudioThread);
	}

	if (m_CameraSdp.get_video_media())//��Ƶ
	{
		strIP.Empty();
		if (!m_udpVideo.Create(m_usLocalRtpVideoPort, SOCK_DGRAM))
			return FALSE;
		if (!m_udpVideo.GetSockName(strIP, usPort))
			return false;

		m_usLocalRtpVideoPort = usPort;


		m_nCSeq++;
		if (!buildSetUpMessage(requestMess, m_nCSeq++, strUrl,
			m_CameraSdp.get_video_track_id(), m_usLocalRtpVideoPort))
		{
			return bRet;
		}

		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(50);
		nCount = m_TcpSockRtsp.Receive(requestMess.szData, RTSP_MESSAGE_SIZE);
		if (nCount < 0)
		{
			return bRet;
		}
		//�����Ӧ��Ϣ״̬�ǲ���ok
		if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
		{
			if (rtspStatus != ok)
			{
				return bRet;
			}
		}
		//���������߳�
		m_hRecvVideoThread = ::CreateThread(NULL, 0, ReceiveVideoThread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_hRecvVideoThread)
		{
			return FALSE;
		}
		::ResumeThread(m_hRecvVideoThread);
	}


	//����play��Ϣ
	m_nCSeq++;
	if (!buildPlayMessage(requestMess, m_nCSeq, strUrl, m_strSession))
	{
		return bRet;
	}

	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(50);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
	{
		return bRet;
	}
	//�����Ӧ��Ϣ״̬�ǲ���ok
	if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
	{
		if (rtspStatus != ok)
		{
			return bRet;
		}
	}

	
	::ResumeThread(m_hSendHeartbeatThread);
	bRet = TRUE;

	return bRet;
}

//�������
BOOL CRtspClient::teardown()
{
	RTSP_MESSAGE requestMess, respondMess;
	int nCount = 0, nRepCseq = 0;
	BOOL bRet = false;
	RESPOND_STATUS rtspStatus = other;

	m_nCSeq++;
	if (buildTeardownMessage(requestMess, m_nCSeq, m_strRtspUrl, m_strSession) == false)
	{
		return false;
	}

	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(50);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
	{
		return false;
	}

	if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
	{
		if (nRepCseq == m_nCSeq && rtspStatus == ok)
		{
			bRet = true;
		}
	}


	return bRet;
}

CSDP CRtspClient::get_SDP()
{
	return m_CameraSdp;
}


DWORD CRtspClient::ReceiveAudioThread(LPVOID lpParam)
{

	CRtspClient *pObject = (CRtspClient *)lpParam;
	ASSERT(NULL != pObject);
	return pObject->DoReceiveAudioStream();

}

DWORD CRtspClient::ReceiveVideoThread(LPVOID lpParam)
{
	CRtspClient *pObject = (CRtspClient *)lpParam;
	ASSERT(NULL != pObject);
	return pObject->DoReceiveVideoStream();

}

DWORD CRtspClient::SendHeartbeat(LPVOID lpParam)
{
	CRtspClient *pObject = (CRtspClient *)lpParam;
	ASSERT(NULL != pObject);
	return pObject->DoSendHearbeat();

}

DWORD CRtspClient::DoReceiveAudioStream()
{
	int count = 0;
	unsigned char *buf = NULL;
	CString recv_ip;
	WORD recv_port;

	buf = new unsigned char[RTP_BUF_SIZE];
	if (NULL == buf) return 1;
	while (m_bWork )
	{
		count = m_udpAudio.ReceiveFrom(buf, RTP_BUF_SIZE, recv_ip, recv_port);
		if (count > 0 && recv_ip == recv_ip)
		{
			for (int i = 0; i < m_arrCache.GetSize(); i++)
			{
				CRtpPacketPtr p = new RTP_PACKET;
				memcpy(p->szData, buf, count);
				p->usPackLen = count;
				p->enType = audio;

				m_arrCache[i]->AddPacket(p);
			}
			
		}
	}
	if (NULL != buf)
	{
		delete buf;
		buf = NULL;
	}

	return 0;
}

DWORD CRtspClient::DoReceiveVideoStream()
{
	int count = 0, ret = 0;
	unsigned char *buf = NULL;
	CString recv_address;
	WORD recv_port;

	buf = new unsigned char[RTP_BUF_SIZE];
	if (NULL == buf) return 1;
	while (m_bWork)
	{

		count = m_udpVideo.ReceiveFrom(buf, RTP_BUF_SIZE, recv_address, recv_port);
		if (count > 0 && recv_address == m_strCameraIP)
		{
			for (int i = 0; i < m_arrCache.GetSize(); i++)
			{
				CRtpPacketPtr p = new RTP_PACKET;
				memcpy(p->szData, buf, count);
				p->usPackLen = count;
				p->enType = video;
				m_arrCache[i]->AddPacket(p);
			}
		}
		if (count < 0)
		{
			ret = WSAGetLastError();
		}

	}

	if (NULL != buf)
	{
		delete buf;
		buf = NULL;
	}


	return 0;
}

//�����������������ܻ�Ӧ
DWORD CRtspClient::DoSendHearbeat()
{
	Sleep(50);
	int count = 0, nCSeq = 0;
	RTSP_MESSAGE requestMess, respondMess ;
	RESPOND_STATUS repStatus;

	while (m_bWork)
	{
		m_nCSeq++;

		if (!buildGetParamemter(requestMess, m_nCSeq, m_strRtspUrl, m_strSession))
		{
			break;
		}
		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(50);
		count = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (count > 0)
		{
			//�����Ӧ��Ϣ״̬ok
			if (!ProcessRespondMessage(respondMess, repStatus, nCSeq) || repStatus != ok)
			{
				m_bWork = false;
				break;
			}
		}
		
		Sleep(58000);
	}


	return 0;
}


