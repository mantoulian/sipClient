#pragma once
#include "stdafx.h"

typedef enum media_type
{
	audio,
	video
}MEDIA_TYPE;

typedef struct rtp_packet
{
	MEDIA_TYPE enType;
	unsigned short usPackLen;
	char szData[1500];
}RTP_PACKET;



typedef CSmartPtr<RTP_PACKET> CRtpPacketPtr;

class AFX_EXT_CLASS CRtpPacketCache
{
public:
	CRtpPacketCache() {}

	virtual ~CRtpPacketCache() {}

	void AddPacket(CRtpPacketPtr packet)
	{

		CSingleLock TheLock(&m_CacheLock, TRUE);
		m_rtpPacketList.AddTail(packet);

	}
	CRtpPacketPtr GetNextPacket()
	{
		CSingleLock TheLock(&m_CacheLock, TRUE);
		if (m_rtpPacketList.IsEmpty())
			return NULL;

		return m_rtpPacketList.RemoveHead();
	}

private:
	CMutex m_CacheLock;
	CList<CRtpPacketPtr> m_rtpPacketList;
};

class AFX_EXT_CLASS CRtpPlayer
{
public:
	CRtpPlayer();
	virtual ~CRtpPlayer();

	BOOL init(CString str_fmtp);

	//BOOL set_sps_pps(CString str_fmtp);

	CRtpPacketCache* GetRtpCache();
	void SetRtpCache(CRtpPacketCache *cache);

	void Play(CWnd* pCWnd);


private:
	static DWORD WINAPI DecodeVideoThread(LPVOID lpParam);

	DWORD DoDecode();


private:

	CRtpPacketCache *m_RtpCache;
	//sps pps
	CString m_str_sps_pps;
	BOOL m_sps_pps_ok;

	//ffmpeg
	const AVCodec *m_codec;
	AVCodecParserContext *m_parser;
	AVCodecContext *m_c;
	AVFrame *m_frame;
	AVPacket *m_pkt;
	AVCodecParameters *m_codecPa;
	HANDLE m_hDecodeThread;
	//HANDLE m_hPlayThread;

	BOOL m_bWork;
	int m_width;
	int m_height;
	CWnd* m_pWnd;
};

