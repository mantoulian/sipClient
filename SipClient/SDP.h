#pragma once

//typedef struct sdp_info
//{
//	CString strAddress;
//	//“Ù∆µ
//	BOOL bAudioMedia;
//	unsigned short usAudioPort;
//	CString strAudioIP;
//	int nAudioLoadType;
//	CString strAudioTrackId;
//	CString strAudioRtpMap;
//	CString strAudioFmtp;
//	// ”∆µ
//	BOOL bVideoMedia;
//	unsigned short usVideoPort;
//	CString strVideoIP;
//	int nVideoLoadType;
//	CString  strVideoTrackId;
//	CString strVideoRtpMap;
//	CString strVideoFmtp;
//
//}SDP_INFO;


class AFX_EXT_CLASS CSDP
{
public:
	CSDP();
	~CSDP();

	BOOL from_buffer(char * buffer, int buf_len);
	CString to_buffer();

	void set_address(CString str_address);

	void set_audio_media(BOOL media);
	void set_audio_address(CString str_address);
	void set_audio_port(unsigned short port);
	void set_audio_load_type(int type);
	void set_audio_track_id(CString track_id);
	void set_audio_rtp_map(CString rtp_map);
	void set_audio_fmtp(CString fmtp);

	void set_video_media(BOOL media);
	void set_video_address(CString str_address);
	void set_video_port(unsigned short port);
	void set_video_load_type(int type);
	void set_video_track_id(CString track_id);
	void set_video_rtp_map(CString rtp_map);
	void set_video_fmtp(CString fmtp);


	CString get_address();

	BOOL get_audio_media();
	CString get_audio_address();
	unsigned short get_audio_port();
	int get_audio_load_type();
	CString get_audio_track_id();
	CString get_audio_rtp_map();
	CString get_audio_fmtp();

	BOOL get_video_media();
	CString get_video_address();
	unsigned short get_video_port();
	int get_video_load_type();
	CString get_video_track_id();
	CString get_video_rtp_map();
	CString get_video_fmtp();




public:
	CString m_strAddress;
	//“Ù∆µ
	BOOL m_bAudioMedia;
	unsigned short m_usAudioPort;
	CString m_strAudioIP;
	int m_nAudioLoadType;
	CString m_strAudioTrackId;
	CString m_strAudioRtpMap;
	CString m_strAudioFmtp;
	// ”∆µ
	BOOL m_bVideoMedia;
	unsigned short m_usVideoPort;
	CString m_strVideoIP;
	int m_nVideoLoadType;
	CString  m_strVideoTrackId;
	CString  m_strVideoRtpMap;
	CString  m_strVideoFmtp;
};

