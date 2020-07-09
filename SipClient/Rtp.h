#pragma once
#include "stdafx.h"

#define RTP_PACKET_SIZE		4096

//typedef enum media_type
//{
//	audio,
//	video
//}MEDIA_TYPE;

typedef struct rtp_packet
{
	//MEDIA_TYPE enType;
	WORD usPackLen;
	//char szData[RTP_PACKET_SIZE];
	BYTE *pData;
}RTP_PACKET;

class AFX_EXT_CLASS CRtpPacket
{
public:
	CRtpPacket();
	CRtpPacket(WORD usSize);

	//CRtpPacket(MEDIA_TYPE type, WORD usSize);

	virtual ~CRtpPacket();


private:
	//MEDIA_TYPE m_enType;
	WORD m_usPackLen;
	BYTE *m_pData;
};



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

	BOOL init();


	//CRtpPacketCache* GetRtpCache();
	BOOL SetRtpCache(CRtpPacketCache *cache);

	BOOL Play(const CString &fmtp, CWnd* pCWnd);


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

	BOOL m_bWork;
	int m_width;
	int m_height;
	CWnd* m_pWnd;
};

