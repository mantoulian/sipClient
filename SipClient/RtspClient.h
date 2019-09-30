#pragma once
#include "Rtp.h"
#include "SDP.h"


BOOL build_md5(const BYTE * pbData, int nDataLen, CString &strMd5Hash)
{
	HCRYPTPROV hProv;
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return FALSE;

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (!CryptHashData(hHash, pbData, nDataLen, 0))
	{
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	DWORD dwSize;
	DWORD dwLen = sizeof(dwSize);
	CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)(&dwSize), &dwLen, 0);

	BYTE* pHash = new BYTE[dwSize];
	dwLen = dwSize;
	CryptGetHashParam(hHash, HP_HASHVAL, pHash, &dwLen, 0);

	strMd5Hash = _T("");
	for (DWORD i = 0; i<dwLen; i++)
		strMd5Hash.AppendFormat(_T("%02X"), pHash[i]);
	delete[] pHash;


	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return TRUE;
}


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

	CString m_user;
	CString m_passwd;

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


