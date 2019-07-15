#include "stdafx.h"
#include "SDP.h"


CSDP::CSDP()
{
	m_bAudioMedia = FALSE;
	m_usAudioPort = 0;
	m_nAudioLoadType = 0;
	//视频
	m_bVideoMedia = FALSE;
	m_usVideoPort = 0;
	m_nVideoLoadType = 0;
}


CSDP::~CSDP()
{
}


#define SDP_MEDIA_SIZE	1024
BOOL CSDP::from_buffer(char * buffer, int buf_len)
{
	if (NULL == buffer || buf_len <= 0)
		return FALSE;


	char value[SDP_MEDIA_SIZE] = { 0 }, media_buf[SDP_MEDIA_SIZE] = { 0 };
	char *pFlag = NULL, *pTemp = NULL, *buf = NULL;
	int num = 0, i = 0;


	buf = (char *)calloc(buf_len + 1, 1);
	memcpy(buf, buffer, buf_len);

	pFlag = strstr(buf, "IN IP4");
	if (pFlag != NULL)
	{
		pFlag += strlen("IN IP4 ");
		while (i < SDP_MEDIA_SIZE)
		{
			if ('\r' == pFlag[i] || '\0' == pFlag[i])
				break;
			value[i] = pFlag[i];
			i++;
		}
		m_strAddress = value;
	}
	//有音频sdp
	pFlag = strstr(buf, "m=audio");
	if (pFlag != NULL)
	{
		m_bAudioMedia = TRUE;
		//取出音频媒体
		memset(media_buf, 0, SDP_MEDIA_SIZE);
		pTemp = strstr(pFlag, "m=video");
		if (pTemp == NULL)
		{
			strncpy_s(media_buf, SDP_MEDIA_SIZE, pFlag, SDP_MEDIA_SIZE - 1);
		}
		else
		{
			i = pTemp - pFlag;
			if (i <= SDP_MEDIA_SIZE)
				memcpy(media_buf, pFlag, i);
		}



		//提取port
		i = strlen("m=audio ");
		num = 0;
		while (i < SDP_MEDIA_SIZE)
		{
			if (' ' == pFlag[i] || '\0' == pFlag[i])
				break;
			if (pFlag[i] >= 48 && pFlag[i] <= 57)
			{
				num = num * 10 + (pFlag[i] - 48);
			}
			i++;
		}
		m_usAudioPort = num;
		//提取load type
		i++;
		num = 0;
		i += strlen("RTP/AVP ");
		while (i < SDP_MEDIA_SIZE)
		{
			if ('\r' == pFlag[i] || '\0' == pFlag[i])
				break;
			if (pFlag[i] >= 48 && pFlag[i] <= 57)
			{
				num = num * 10 + (pFlag[i] - 48);
			}
			i++;

		}
		m_nAudioLoadType = num;
		//取出ip地址
		pTemp = strstr(media_buf, "c=IN IP4");
		if (pTemp != NULL)
		{
			pTemp += strlen("c=IN IP4 ");
			i = 0;
			memset(value, 0, SDP_MEDIA_SIZE);
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strAudioIP = value;
		}
		//提取rtpmap
		pTemp = strstr(media_buf, "rtpmap");
		if (pTemp != NULL)
		{
			pTemp += strlen("rtpmap:");
			i = 0;
			memset(value, 0, SDP_MEDIA_SIZE);
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strAudioRtpMap = value;
		}

		//提取fmtp
		pTemp = strstr(media_buf, "fmtp");
		if (pTemp != NULL)
		{
			pTemp += strlen("fmtp:");
			i = 0;
			memset(value, 0, SDP_MEDIA_SIZE);
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strAudioFmtp = value;
		}

		//提取trackid
		pTemp = strstr(media_buf, "control:track");
		if (pTemp != NULL)
		{
			pTemp += strlen("control:");
			i = 0;
			memset(value, 0, SDP_MEDIA_SIZE);
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strAudioTrackId = value;
		}


	}
	//有视频sdp
	pFlag = strstr(buf, "m=video");
	if (pFlag != NULL)
	{
		m_bVideoMedia = TRUE;

		//取出视频媒体信息
		memset(media_buf, 0, SDP_MEDIA_SIZE);
		pTemp = strstr(pFlag, "m=audio");
		if (pTemp == NULL)
		{
			strncpy_s(media_buf, SDP_MEDIA_SIZE, pFlag, SDP_MEDIA_SIZE - 1);
		}
		else
		{
			i = pTemp - pFlag;
			if (i <= SDP_MEDIA_SIZE)
				memcpy(media_buf, pFlag, i);
		}


		//提取port
		i = strlen("m=video ");
		num = 0;
		while (i<SDP_MEDIA_SIZE)
		{
			if (' ' == pFlag[i] || '\0' == pFlag[i])
				break;
			if (pFlag[i] >= 48 && pFlag[i] <= 57)
			{
				num = num * 10 + (pFlag[i] - 48);
			}
			i++;
		}
		m_usVideoPort = num;
		//提取load type
		i++;
		num = 0;
		i += strlen("RTP/AVP ");
		while (i<SDP_MEDIA_SIZE)
		{
			if ('\0' == pFlag[i] || '\r' == pFlag[i])
				break;
			if (pFlag[i] >= 48 && pFlag[i] <= 57)
			{
				num = num * 10 + (pFlag[i] - 48);
			}
			i++;
		}
		m_nVideoLoadType = num;

		//取出ip地址
		pTemp = strstr(media_buf, "c=IN IP4");
		if (pTemp != NULL)
		{
			pTemp += strlen("c=IN IP4 ");
			memset(value, 0, SDP_MEDIA_SIZE);
			i = 0;
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strVideoIP = value;
		}

		//提取trackid
		pTemp = strstr(media_buf, "control:track");
		if (pTemp != NULL)
		{
			pTemp += strlen("control:");
			memset(value, 0, SDP_MEDIA_SIZE);
			i = 0;
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strVideoTrackId = value;
		}

		//提取rtpmap
		pTemp = strstr(media_buf, "rtpmap");
		if (pTemp != NULL)
		{
			pTemp += strlen("rtpmap:");
			memset(value, 0, SDP_MEDIA_SIZE);
			i = 0;
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strVideoRtpMap = value;
		}
		//提取fmpt
		pTemp = strstr(media_buf, "fmtp");
		if (pTemp != NULL)
		{
			pTemp += strlen("fmtp:");
			memset(value, 0, SDP_MEDIA_SIZE);
			i = 0;
			while (i<SDP_MEDIA_SIZE)
			{
				if ('\r' == pTemp[i] || '\0' == pTemp[i])
					break;
				value[i] = pTemp[i];
				i++;
			}
			m_strVideoFmtp = value;
		}
	}
	if (NULL != buf)
	{
		delete buf;
		buf = NULL;
	}


	return TRUE;

}
CString CSDP::to_buffer()
{
	CString buf, temp;

	//v
	temp.Format(_T("v=0\r\n"));
	buf += temp;
	//o
	temp.Format(_T("o=- 0 0 IN IP4 %s\r\n"), m_strAddress);
	buf += temp;
	//s
	temp.Format(_T("s=0\r\n"));
	buf += temp;
	//t
	temp.Format(_T("t=0 0\r\n"));
	buf += temp;
	//m
	if (m_bAudioMedia)
	{
		temp.Format(_T("m=audio %d RTP/AVP %d\r\n"), m_usAudioPort, m_nAudioLoadType);
		buf += temp;

		temp.Format(_T("c=IN IP4 %s\r\n"), m_strAudioIP);
		buf += temp;

		temp.Format(_T("a=rtpmap:%s\r\n"), m_strAudioRtpMap);
		buf += temp;

		temp.Format(_T("a=fmtp:%s\r\n"), m_strAudioFmtp);
		buf += temp;

		temp.Format(_T("a=sendrecv\r\n"));
		buf += temp;

	}

	if (m_bVideoMedia)
	{
		temp.Format(_T("m=video %d RTP/AVP %d\r\n"), m_usVideoPort, m_nVideoLoadType);
		buf += temp;

		temp.Format(_T("c=IN IP4 %s\r\n"), m_strVideoIP);
		buf += temp;

		temp.Format(_T("a=rtpmap:%s\r\n"), m_strVideoRtpMap);
		buf += temp;

		temp.Format(_T("a=fmtp:%s\r\n"), m_strVideoFmtp);
		//temp.Format(_T("a=fmtp:96 profile-level-id=4D002A;packetization-mode=1\r\n"));
		buf += temp;

		temp.Format(_T("a=sendrecv\r\n"));
		buf += temp;

	}

	return  buf;

}

void CSDP::set_address(CString str_address)
{
	m_strAddress = str_address;
}

void CSDP::set_audio_media(BOOL media)
{
	m_bAudioMedia = media;
}

void CSDP::set_audio_address(CString str_address)
{
	m_strAudioIP = str_address;
}

void CSDP::set_video_media(BOOL media)
{
	m_bVideoMedia = media;
}

void CSDP::set_video_address(CString str_address)
{
	m_strVideoIP = str_address;
}

void CSDP::set_audio_port(unsigned short port)
{
	m_usAudioPort = port;
}

void CSDP::set_audio_load_type(int type)
{
	m_nAudioLoadType = type;
}

void CSDP::set_audio_track_id(CString track_id)
{
	m_strAudioTrackId = track_id;
}

void CSDP::set_audio_rtp_map(CString rtp_map)
{
	m_strAudioRtpMap = rtp_map;
}

void CSDP::set_audio_fmtp(CString fmtp)
{
	m_strAudioFmtp = fmtp;
}

void CSDP::set_video_port(unsigned short port)
{
	m_usVideoPort = port;
}

void CSDP::set_video_load_type(int type)
{
	m_nVideoLoadType = type;
}

void CSDP::set_video_track_id(CString track_id)
{
	m_strVideoTrackId = track_id;
}

void CSDP::set_video_rtp_map(CString rtp_map)
{
	m_strVideoRtpMap = rtp_map;
}

void CSDP::set_video_fmtp(CString fmtp)
{
	m_strVideoFmtp = fmtp;
}

CString CSDP::get_address()
{
	return m_strAddress;
}

BOOL CSDP::get_audio_media()
{
	return m_bAudioMedia;
}

CString CSDP::get_audio_address()
{
	return m_strAudioIP;
}

BOOL CSDP::get_video_media()
{
	return m_bVideoMedia;
}

CString CSDP::get_video_address()
{
	return m_strVideoIP;
}

unsigned short CSDP::get_audio_port()
{
	return m_usAudioPort;
}

int CSDP::get_audio_load_type()
{
	return m_nAudioLoadType;
}

CString CSDP::get_audio_track_id()
{
	return m_strAudioTrackId;
}

CString CSDP::get_audio_rtp_map()
{
	return m_strAudioRtpMap;
}

CString CSDP::get_audio_fmtp()
{
	return m_strAudioFmtp;
}

unsigned short CSDP::get_video_port()
{
	return m_usVideoPort;
}

int CSDP::get_video_load_type()
{
	return m_nVideoLoadType;
}

CString CSDP::get_video_track_id()
{
	return m_strVideoTrackId;
}

CString CSDP::get_video_rtp_map()
{
	return m_strVideoRtpMap;
}

CString CSDP::get_video_fmtp()
{
	return m_strVideoFmtp;
}

//SDP_INFO * CSDP::get_sdp_info()
//{
//	return m_sdp_info;
//}

//void CSDP::set_audio_port(unsigned short port)
//{
//	m_sdp_info->usAudioPort = port;
//	
//}
//
//void CSDP::set_video_port(unsigned short port)
//{
//	m_sdp_info->usVideoPort = port;
//}

//CSDP & CSDP::operator=(const CSDP & sdp)
//{
//	if (this != &sdp && NULL != sdp.m_sdp_info)
//	{
//		if (NULL == m_sdp_info)
//			m_sdp_info = new SDP_INFO;
//		memcpy(m_sdp_info, sdp.m_sdp_info, sizeof(SDP_INFO));
//	}
//
//	return *this;
//}

//CSDP & CSDP::operator=(const SDP_INFO * sdp)
//{
//	if (NULL != sdp)
//	{
//		if (NULL == m_sdp_info)
//			m_sdp_info = new SDP_INFO;
//		memcpy(m_sdp_info, sdp, sizeof(SDP_INFO));
//	}
//	return *this;
//}
