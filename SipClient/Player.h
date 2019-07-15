#pragma once
#include "Rtp.h"
#include "RtspClient.h"

//typedef struct video_data_YUV
//{
//	int nYLen;
//	unsigned char Y[1920 * 1080];
//	int nULen;
//	unsigned char U[1920 * 1080];
//	int nVLen;
//	unsigned char V[1920 * 1080];
//}VIDEO_DATA_YUV;



class AFX_EXT_CLASS CPlayer
{
public:
	CPlayer();
	virtual ~CPlayer();

	BOOL init(SDP_INFO *sdpInfo);


	CRtpPacketCache* GetRtpCache();


	void Play(CWnd* pCWnd);


protected:
	BOOL SetSpsPps(unsigned char *szSpsPps, int nSpsPpsLen);


private:
	static DWORD WINAPI DecodeThread(LPVOID lpParam);
	DWORD DoDecode();
	//static DWORD WINAPI PlayThread(LPVOID lpParam);
	//DWORD DoPlay();


private:

	CRtpPacketCache *m_RtpCache;//需要解码的rtp包队列


	const AVCodec *m_codec;
	AVCodecParserContext *m_parser;
	AVCodecContext *m_c;
	AVFrame *m_frame;
	AVPacket *m_pkt;
	AVCodecParameters *m_codecPa;
	HANDLE m_hDecodeThread;
	HANDLE m_hPlayThread;

	BOOL m_bWork;
	int m_width;
	int m_height;
	CWnd* m_pWnd;

};

