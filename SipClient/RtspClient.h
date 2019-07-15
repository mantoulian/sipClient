#pragma once
#include "Rtp.h"
#include "SDP.h"



class AFX_EXT_CLASS CRtspClient
{
public:
	CRtspClient();
	~CRtspClient();

	BOOL init(unsigned short usRtspPort = 0, unsigned short usRtpAudioPort = 0, unsigned short usRtpVideoPort = 0);

	//url: "rtsp://192.168.1.1:554"
	BOOL open_url(CString strUrl);

	//关闭
	BOOL teardown();

	//获取sdp_info
	CSDP get_SDP();

	void AddCache(CRtpPacketCache* pCache)
	{
		CSingleLock TheLock(&m_CacheLock, TRUE);
		if (NULL != pCache)
			m_arrCache.Add(pCache);
	}

	void RemoveCache(CRtpPacketCache* pCache)
	{
		CSingleLock TheLock(&m_CacheLock, TRUE);
		for (int i = m_arrCache.GetSize() - 1; i >= 0; i--)
		{
			if (pCache == m_arrCache[i])
				m_arrCache.RemoveAt(i);
		}
	}


private:

	static DWORD WINAPI ReceiveAudioThread(LPVOID lpParam);
	static DWORD WINAPI ReceiveVideoThread(LPVOID lpParam);
	static DWORD WINAPI SendHeartbeat(LPVOID lpParam);
	DWORD DoReceiveAudioStream();
	DWORD DoReceiveVideoStream();
	DWORD DoSendHearbeat();


private:
	CMutex m_CacheLock;
	CTypedPtrArray<CPtrArray, CRtpPacketCache*> m_arrCache;

	unsigned short  m_usLocalRtspPort;
	unsigned short  m_usLocalRtpVideoPort;
	unsigned short  m_usLocalRtpAudioPort;

	//相机端口
	CString m_strCameraIP;
	unsigned short  m_usCameraPort;
	BOOL m_bWork;
	CSDP m_CameraSdp;

	//rtsp消息参数
	CString m_strRtspUrl;
	CString m_strSession;
	int m_nCSeq;


	//线程句柄
	CNetSocket m_TcpSockRtsp;//rtsp和心跳包
	CNetSocket m_udpAudio;
	CNetSocket m_udpVideo;
	HANDLE m_hRecvAudioThread;
	HANDLE m_hRecvVideoThread;
	HANDLE m_hSendHeartbeatThread;


};


