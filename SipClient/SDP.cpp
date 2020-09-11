#include "stdafx.h"
#include "SDP.h"


CSDP::CSDP()
{
	//m_bAudioMedia = FALSE;
	//m_usAudioPort = 0;
	//m_nAudioLoadType = 0;
	////视频
	//m_bVideoMedia = FALSE;
	//m_usVideoPort = 0;
	//m_nVideoLoadType = 0;

	for (int i = 0; i < SDP_MAX_MEDIA; i++)
		m_media[i] = new MEDIA_ATTRIBUTES();

	m_mediaCount = 0;



}


CSDP::~CSDP()
{
	for (int i = 0; i < SDP_MAX_MEDIA; i++)
	{
		if (m_media[i] != NULL)
		{
			delete m_media[i];
			m_media[i] = NULL;
		}
	}

	m_mediaCount = 0;

}

//CSDP::CSDP(const CSDP & sdp)
//{
//	m_netType = sdp.m_addrType;
//	m_addrType = sdp.m_addrType;
//	m_addr = sdp.m_addr;
//
//
//	for (int i = 0; i < m_mediaCount; i++)
//	{
//		if(sdp.m_media[i])
//		if (m_media[i] == NULL)
//		{
//			m_media[i] = new MEDIA_ATTRIBUTES();
//			if(m_media[i]!=NULL)
//		}
//	}
//}


#define SDP_MEDIA_SIZE	1024
//BOOL CSDP::from_buffer(char * buffer, int buf_len)
//{
//	if (NULL == buffer || buf_len <= 0)
//		return FALSE;
//
//
//	char value[SDP_MEDIA_SIZE] = { 0 }, media_buf[SDP_MEDIA_SIZE] = { 0 };
//	char *pFlag = NULL, *pTemp = NULL, *buf = NULL;
//	int num = 0, i = 0;
//
//
//	buf = (char *)calloc(buf_len + 1, 1);
//	memcpy(buf, buffer, buf_len);
//
//	pFlag = strstr(buf, "IN IP4");
//	if (pFlag != NULL)
//	{
//		pFlag += strlen("IN IP4 ");
//		while (i < SDP_MEDIA_SIZE)
//		{
//			if ('\r' == pFlag[i] || '\0' == pFlag[i])
//				break;
//			value[i] = pFlag[i];
//			i++;
//		}
//		m_strAddress = value;
//	}
//	//有音频sdp
//	pFlag = strstr(buf, "m=audio");
//	if (pFlag != NULL)
//	{
//		m_bAudioMedia = TRUE;
//		//取出音频媒体
//		memset(media_buf, 0, SDP_MEDIA_SIZE);
//		pTemp = strstr(pFlag, "m=video");
//		if (pTemp == NULL)
//		{
//			strncpy_s(media_buf, SDP_MEDIA_SIZE, pFlag, SDP_MEDIA_SIZE - 1);
//		}
//		else
//		{
//			i = pTemp - pFlag;
//			if (i <= SDP_MEDIA_SIZE)
//				memcpy(media_buf, pFlag, i);
//		}
//
//
//
//		//提取port
//		i = strlen("m=audio ");
//		num = 0;
//		while (i < SDP_MEDIA_SIZE)
//		{
//			if (' ' == pFlag[i] || '\0' == pFlag[i])
//				break;
//			if (pFlag[i] >= 48 && pFlag[i] <= 57)
//			{
//				num = num * 10 + (pFlag[i] - 48);
//			}
//			i++;
//		}
//		m_usAudioPort = num;
//		//提取load type
//		i++;
//		num = 0;
//		i += strlen("RTP/AVP ");
//		while (i < SDP_MEDIA_SIZE)
//		{
//			if ('\r' == pFlag[i] || '\0' == pFlag[i])
//				break;
//			if (pFlag[i] >= 48 && pFlag[i] <= 57)
//			{
//				num = num * 10 + (pFlag[i] - 48);
//			}
//			i++;
//
//		}
//		m_nAudioLoadType = num;
//		//取出ip地址
//		pTemp = strstr(media_buf, "c=IN IP4");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("c=IN IP4 ");
//			i = 0;
//			memset(value, 0, SDP_MEDIA_SIZE);
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strAudioIP = value;
//		}
//		//提取rtpmap
//		pTemp = strstr(media_buf, "rtpmap");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("rtpmap:");
//			i = 0;
//			memset(value, 0, SDP_MEDIA_SIZE);
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strAudioRtpMap = value;
//		}
//
//		//提取fmtp
//		pTemp = strstr(media_buf, "fmtp");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("fmtp:");
//			i = 0;
//			memset(value, 0, SDP_MEDIA_SIZE);
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strAudioFmtp = value;
//		}
//
//		//提取control
//		pTemp = strstr(media_buf, "a=control");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("a=control:");
//			i = 0;
//			memset(value, 0, SDP_MEDIA_SIZE);
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strAudioControl = value;
//		}
//
//
//	}
//	//有视频sdp
//	pFlag = strstr(buf, "m=video");
//	if (pFlag != NULL)
//	{
//		m_bVideoMedia = TRUE;
//
//		//取出视频媒体信息
//		memset(media_buf, 0, SDP_MEDIA_SIZE);
//		pTemp = strstr(pFlag, "m=audio");
//		if (pTemp == NULL)
//		{
//			strncpy_s(media_buf, SDP_MEDIA_SIZE, pFlag, SDP_MEDIA_SIZE - 1);
//		}
//		else
//		{
//			i = pTemp - pFlag;
//			if (i <= SDP_MEDIA_SIZE)
//				memcpy(media_buf, pFlag, i);
//		}
//
//
//		//提取port
//		i = strlen("m=video ");
//		num = 0;
//		while (i<SDP_MEDIA_SIZE)
//		{
//			if (' ' == pFlag[i] || '\0' == pFlag[i])
//				break;
//			if (pFlag[i] >= 48 && pFlag[i] <= 57)
//			{
//				num = num * 10 + (pFlag[i] - 48);
//			}
//			i++;
//		}
//		m_usVideoPort = num;
//		//提取load type
//		i++;
//		num = 0;
//		i += strlen("RTP/AVP ");
//		while (i<SDP_MEDIA_SIZE)
//		{
//			if ('\0' == pFlag[i] || '\r' == pFlag[i])
//				break;
//			if (pFlag[i] >= 48 && pFlag[i] <= 57)
//			{
//				num = num * 10 + (pFlag[i] - 48);
//			}
//			i++;
//		}
//		m_nVideoLoadType = num;
//
//		//取出ip地址
//		pTemp = strstr(media_buf, "c=IN IP4");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("c=IN IP4 ");
//			memset(value, 0, SDP_MEDIA_SIZE);
//			i = 0;
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strVideoIP = value;
//		}
//
//		//提取control
//		pTemp = strstr(media_buf, "a=control");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("a=control:");
//			memset(value, 0, SDP_MEDIA_SIZE);
//			i = 0;
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strVideoControl = value;
//		}
//
//		//提取rtpmap
//		pTemp = strstr(media_buf, "rtpmap");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("rtpmap:");
//			memset(value, 0, SDP_MEDIA_SIZE);
//			i = 0;
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strVideoRtpMap = value;
//		}
//		//提取fmpt
//		pTemp = strstr(media_buf, "fmtp");
//		if (pTemp != NULL)
//		{
//			pTemp += strlen("fmtp:");
//			memset(value, 0, SDP_MEDIA_SIZE);
//			i = 0;
//			while (i<SDP_MEDIA_SIZE)
//			{
//				if ('\r' == pTemp[i] || '\0' == pTemp[i])
//					break;
//				value[i] = pTemp[i];
//				i++;
//			}
//			m_strVideoFmtp = value;
//		}
//	}
//	if (NULL != buf)
//	{
//		delete [] buf;
//		buf = NULL;
//	}
//
//
//	return TRUE;
//
//}


BOOL CSDP::from_buffer(char * buffer, int buf_len)
{
	if (buffer == NULL)
		return FALSE;

	CString strSDP, conn, strMedia;
	int i = 0, j = 0;

	strSDP = buffer;


	//c=
	i = strSDP.Find(_T("c="));
	if (i < 0)
		return FALSE;

	j = strSDP.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;

	conn = strSDP.Mid(j, i - j);
	if (!conn.IsEmpty())
		m_conn.frome_string(conn);


	//media
	m_mediaCount = i = j = 0;

	while (i < strSDP.GetLength() -1)
	{
		i = strSDP.Find(_T("m="), j);
		if (i < 0)
			break;
		j = strSDP.Find(_T("m="), i + 2);
		if (j >= 0)
		{
			strMedia = strSDP.Mid(i, j - i);

		}
		else
		{
			j = strSDP.ReverseFind('\n');
			if (j < 0)
				break;
			strMedia = strSDP.Right(strSDP.GetLength() - i);
		}

		//if (m_media[m_mediaCount] == NULL)
		//	m_media[m_mediaCount] = new MEDIA_ATTRIBUTES();
		if (m_media[m_mediaCount] != NULL)
		{
			if (m_media[m_mediaCount]->from_string(strMedia))
				m_mediaCount++;
			else
			{
				delete m_media[m_mediaCount];
				m_media[m_mediaCount] = NULL;
			}

		}

		i = j;

	}
	









}



//CString CSDP::to_string() const
//{
//	CString buf, temp;
//
//	//v
//	temp.Format(_T("v=0\r\n"));
//	buf += temp;
//	//o
//	temp.Format(_T("o=- 0 0 IN IP4 %s\r\n"), m_strAddress);
//	buf += temp;
//	//s
//	temp.Format(_T("s=0\r\n"));
//	buf += temp;
//	//t
//	temp.Format(_T("t=0 0\r\n"));
//	buf += temp;
//	//m
//	if (m_bAudioMedia)
//	{
//		temp.Format(_T("m=audio %d RTP/AVP %d\r\n"), m_usAudioPort, m_nAudioLoadType);
//		buf += temp;
//
//		temp.Format(_T("c=IN IP4 %s\r\n"), m_strAudioIP);
//		buf += temp;
//
//		temp.Format(_T("a=rtpmap:%s\r\n"), m_strAudioRtpMap);
//		buf += temp;
//
//		temp.Format(_T("a=fmtp:%s\r\n"), m_strAudioFmtp);
//		buf += temp;
//
//		temp.Format(_T("a=sendrecv\r\n"));
//		buf += temp;
//
//	}
//
//	if (m_bVideoMedia)
//	{
//		temp.Format(_T("m=video %d RTP/AVP %d\r\n"), m_usVideoPort, m_nVideoLoadType);
//		buf += temp;
//
//		temp.Format(_T("c=IN IP4 %s\r\n"), m_strVideoIP);
//		buf += temp;
//
//		temp.Format(_T("a=rtpmap:%s\r\n"), m_strVideoRtpMap);
//		buf += temp;
//
//		temp.Format(_T("a=fmtp:%s\r\n"), m_strVideoFmtp);
//		//temp.Format(_T("a=fmtp:96 profile-level-id=4D002A;packetization-mode=1\r\n"));
//		buf += temp;
//
//		temp.Format(_T("a=sendrecv\r\n"));
//		buf += temp;
//
//	}
//
//	return  buf;
//
//}


CString CSDP::to_string() const
{
	CString strSDP, strTemp;



	//v
	strTemp.Format(_T("v=0\r\n"));
	strSDP += strTemp;
	//o
	strTemp.Format(_T("o=- 0 0 IN IP4 %s\r\n"), m_conn.addr);
	strSDP += strTemp;
	//s
	strTemp.Format(_T("s=0\r\n"));
	strSDP += strTemp;
	//t
	strTemp.Format(_T("t=0 0\r\n"));
	strSDP += strTemp;

	//m
	for (int i = 0; i < m_mediaCount && i < SDP_MAX_MEDIA; i++)
	{
		if (m_media[i] != NULL)
		{
			strTemp = m_media[i]->to_string();
			strSDP += strTemp;
		}
	}



}

void CSDP::Clone(CSDP & sdp)
{
}

CSDP CSDP::sdp_compare(const CSDP & sdp)
{
	CSDP consultSdp;

	//比较sdp中的媒体属性，找出相同的媒体，返回新的sdp。
	consultSdp = *this;

	//consultSdp.m_mediaCount;








	return consultSdp;
}

BOOL CSDP::set_conn(const CString & strConn)
{
	return 0;
}

BOOL CSDP::set_media_conn(int nIndex, const CString & strConn)
{
	return 0;
}

BOOL CSDP::set_media_port(int nIndex, WORD wPort)
{
	return 0;
}

int CSDP::get_sdp_len()
{




	return 0;
}

//void CSDP::set_address(CString str_address)
//{
//	m_strAddress = str_address;
//}
//
//void CSDP::set_audio_media(BOOL media)
//{
//	m_bAudioMedia = media;
//}
//
//void CSDP::set_audio_address(CString str_address)
//{
//	m_strAudioIP = str_address;
//}
//
//void CSDP::set_video_media(BOOL media)
//{
//	m_bVideoMedia = media;
//}
//
//void CSDP::set_video_address(CString str_address)
//{
//	m_strVideoIP = str_address;
//}
//
//void CSDP::set_audio_port(unsigned short port)
//{
//	m_usAudioPort = port;
//}
//
//void CSDP::set_audio_load_type(int type)
//{
//	m_nAudioLoadType = type;
//}
//
//void CSDP::set_audio_track_id(CString track_id)
//{
//	m_strAudioTrackId = track_id;
//}
//
//void CSDP::set_audio_rtp_map(CString rtp_map)
//{
//	m_strAudioRtpMap = rtp_map;
//}
//
//void CSDP::set_audio_fmtp(CString fmtp)
//{
//	m_strAudioFmtp = fmtp;
//}
//
//void CSDP::set_video_port(unsigned short port)
//{
//	m_usVideoPort = port;
//}
//
//void CSDP::set_video_load_type(int type)
//{
//	m_nVideoLoadType = type;
//}
//
//void CSDP::set_video_track_id(CString track_id)
//{
//	m_strVideoTrackId = track_id;
//}
//
//void CSDP::set_video_rtp_map(CString rtp_map)
//{
//	m_strVideoRtpMap = rtp_map;
//}
//
//void CSDP::set_video_fmtp(CString fmtp)
//{
//	m_strVideoFmtp = fmtp;
//}
//
//CString CSDP::get_address()
//{
//	return m_strAddress;
//}
//
//BOOL CSDP::get_audio_media()
//{
//	return m_bAudioMedia;
//}
//
//CString CSDP::get_audio_address()
//{
//	return m_strAudioIP;
//}
//
//BOOL CSDP::get_video_media()
//{
//	return m_bVideoMedia;
//}
//
//CString CSDP::get_video_address()
//{
//	return m_strVideoIP;
//}
//
//unsigned short CSDP::get_audio_port()
//{
//	return m_usAudioPort;
//}
//
//int CSDP::get_audio_load_type()
//{
//	return m_nAudioLoadType;
//}
//
//CString CSDP::get_audio_track_id()
//{
//	return m_strAudioTrackId;
//}
//
//CString CSDP::get_audio_rtp_map()
//{
//	return m_strAudioRtpMap;
//}
//
//CString CSDP::get_audio_fmtp()
//{
//	return m_strAudioFmtp;
//}
//
//unsigned short CSDP::get_video_port()
//{
//	return m_usVideoPort;
//}
//
//int CSDP::get_video_load_type()
//{
//	return m_nVideoLoadType;
//}
//
//CString CSDP::get_video_track_id()
//{
//	return m_strVideoTrackId;
//}
//
//CString CSDP::get_video_rtp_map()
//{
//	return m_strVideoRtpMap;
//}
//
//CString CSDP::get_video_fmtp()
//{
//	return m_strVideoFmtp;
//}

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


//"m= ... \r\n"
BOOL media_attributes::from_string(const CString &strMedia)
{
	if (strMedia.IsEmpty())
		return FALSE;


	CString value;
	int i = 0, j = 0, n = 0, m = 0, port = 0, index = 0;




	//strBuf = buf;
	//i = strBuf.Find(_T("m="));
	//if (i < 0)
	//	return FALSE;
	//j = strBuf.Find(_T("\r\n"), i);
	//if (j < 0)
	//	return FALSE;
	//strMedia = strBuf


	//m=
	i = strMedia.Find(_T("m="));
	if (i < 0)
		return FALSE;
	j = strMedia.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;

	//desc.media type
	m = strMedia.Find(_T(" "), i);
	if (m < 0)
		return FALSE;
	value = strMedia.Mid(i, m - i);
	if (value.Compare(_T("m=audio")) == 0)
		desc.media = _T("audio");
	else if (value.Compare(_T("m=video")) == 0)
		desc.media = _T("vidio");
	else
		return FALSE;

	//desc.port
	i = m + 1;
	m = strMedia.Find(_T(" "), i);
	if (m < 0)
		return FALSE;
	value = strMedia.Mid(i, m - i);
	port = _ttoi(value);
	if (0 < port && port < 65536)
		desc.port = port;
	else
		return FALSE;

	//desc.transport
	i = m + 1;
	m = strMedia.Find(_T("RTP/AVP"));
	if (m < 0)
		return FALSE;
	else
		desc.transport = _T("RTP/AVP");

	//fmt
	m += strlen("RTP/AVP ");
	i = m;
	desc.fmt_count = 0;
	while (m < j && desc.fmt_count <= MEDIA_MAX_SDP_FMT)
	{
		m = strMedia.Find(_T(" "), i);
		if (m > 0)
		{
			value = strMedia.Mid(i, m - i);
			desc.fmt[desc.fmt_count] = value;
			desc.fmt_count++;
		}

		i = m + 1;
	}

	//c=
	if (conn != NULL)
	{
		conn->frome_string(strMedia);
	}

	//a=
	//m = strMedia.Find(_T("m="))
	attrCount = 0;

	while (i < strMedia.GetLength() -1)
	{
		i = strMedia.Find(_T("a="));
		if (i < 0)
			break;
		j = strMedia.Find(_T("\r\n"));
		if (j < 0)
			break;
		value = strMedia.Mid(i, j - i);

		if (attr[attrCount] == NULL)
			attr[attrCount] = new sdp_attr();
		if (attr[attrCount] != NULL)
		{
			if (attr[attrCount]->frome_string(value))
				attrCount++;
			else
			{
				delete attr[attrCount];
				attr[attrCount] = NULL;
			}
		}

		i = j + 2; 
		
	}


	return TRUE;
}

CString media_attributes::to_string()
{

	CString strMedia, media_line,conn_line, attrLiset,strTemp;

	//m=
	media_line.Format(_T("m=%s %d %s"), desc.media, desc.port, desc.transport);

	for (int i = 0; i <desc.fmt_count; i++)
	{
		strTemp.Format(_T(" %s"), desc.fmt[i]);
		media_line += strTemp;
	}
	media_line += _T("\r\n");
	strMedia += media_line;

	//c=
	if (conn != NULL)
		conn_line = conn->to_string();
	strMedia += conn_line;


	//attr
	for (int i = 0; i < attrCount; i++)
	{
		if (attr[i] != NULL)
		{
			strTemp = attr[i]->to_string();
			strMedia += strTemp;
		}
	}


	return strMedia;
}

BOOL sdp_conn::frome_string(const CString & strConn)
{

	if (strConn.IsEmpty())
		return FALSE;


	int i = 0, j = 0, m = 0;

	i = strConn.Find(_T("c="));
	if (i < 0)
		return FALSE;
	j = strConn.Find(_T("\r\n"));
	if (j < 0)
		return FALSE;

	i += 2;
	m = strConn.Find(_T(" "), i);
	if (m >= 0 && m < j)
		net_type = strConn.Mid(i, m - i);

	i = m + 1;
	m = strConn.Find(_T(" "), i);
	if (m >= 0 && m < j)
		addr_type = strConn.Mid(i, m - i);

	i = m + 1;
	m = strConn.Find(_T(" "), i);
	if (m >= 0 && m < j)
		addr = strConn.Mid(i, m - i);



	return TRUE;
}

CString sdp_conn::to_string()
{
	CString conn;

	conn.Format(_T("c=%s %s %s\r\n"), net_type, addr_type, addr);

	return conn;
}
 
BOOL sdp_attr::frome_string(const CString & strAttr)
{
	if (strAttr.IsEmpty())
		return FALSE;

	BOOL ret = FALSE;
	int i = 0, j = 0, m = 0;


	i = strAttr.Find(_T("a="));
	if (i < 0)
		return FALSE;
	j = strAttr.Find(_T("\r\n"));
	if (j < 0)
		return FALSE;


	m = strAttr.Find(_T(":"), i);
	if (m >= 0 && m < j)
	{
		i += 2;
		name = strAttr.Mid(i, m - i);
		value = strAttr.Right(j - m - 1);
		ret = TRUE;
	}



	return ret;
}

CString sdp_attr::to_string()
{
	CString attr;

	attr.Format(_T("a=%s:%s\r\n"), name, value);
	return attr;
}
