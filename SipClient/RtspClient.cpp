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
	Unauthorized = 401,
	other
}RESPOND_STATUS;



//构建Options消息 
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

//构建Describe消息
BOOL buildDescribeMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl, CString auth)
{
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	int i = 0, count = 0;
	CString url;

	USES_CONVERSION;
	const char * p = T2A(strRtspUrl);
	i = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE, 
		"DESCRIBE %s RTSP/1.0\r\n""CSeq: %d\r\n", p, nCseq);
	count += i;
	if (auth.IsEmpty())
	{
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count, "\r\n");
		count += i;
	}
	else
	{
		p = T2A(auth);
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Authorization: %s\r\n\r\n", p);
		count += i;
		//i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
		//	"Accept: application/sdp\r\n\r\n");
		//count += i;
	}



	rtspMess.nLen = count;

	return true;
}

//构建setup消息
BOOL buildSetUpMessage(RTSP_MESSAGE &rtspMess, const CString &url, int nCseq, 
	const CString &auth, int rtp_p, int rtcp_p, const CString &session)
{
	char *p = NULL;
	int count = 0, i = 0;

	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	p = T2A(url);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"SETUP %s RTSP/1.0\r\n"
		"CSeq: %d\r\n", p, nCseq);
	if (i <= 0)
		return FALSE;
	count += i;
	if (!auth.IsEmpty())
	{
		p = T2A(auth);
		if (NULL == p)
			return FALSE;
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Authorization: %s\r\n", p);
		if (i <= 0)
			return FALSE;
		count += i;
	}

	i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
		"Transport: RTP/AVP;unicast;client_port=%d-%d\r\n", rtp_p, rtcp_p);
	if (i <= 0)
		return FALSE;
	count += i;

	if (!session.IsEmpty())
	{
		p = T2A(session);
		if (NULL == p)
			return FALSE;
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Session: %s\r\n", p);
		if (i <= 0)
			return FALSE;
		count += i;
	}

	i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,"\r\n");
	if (i <= 0)
		return FALSE;
	count += i;


	rtspMess.nLen = count;

	return TRUE;
}

//构建play消息
BOOL buildPlayMessage(RTSP_MESSAGE &rtspMess, int nCseq, const CString strRtspUrl,
	const CString strSession, const CString &auth)
{
	if (strRtspUrl.IsEmpty())
		return false;

	char *p = NULL;
	int count = 0, i = 0;

	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	p = T2A(strRtspUrl);

	i = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"PLAY %s RTSP/1.0\r\n"
		"CSeq: %d\r\n", p, nCseq);
	if (i <= 0)
		return FALSE;
	count += i;

	if (!auth.IsEmpty())
	{
		p = T2A(auth);
		if (NULL == p)
			return FALSE;
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Authorization: %s\r\n", p);
		if (i <= 0)
			return FALSE;
		count += i;
	}

	p = T2A(strSession);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
		"Session: %s\r\n"
		"Range: npt=0.000-\r\n\r\n", p);
	if (i <= 0)
		return FALSE;
	count += i;

	rtspMess.nLen = count;

	return TRUE;
}


//构建teardown消息
BOOL buildTeardownMessage(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString strSession, const CString auth)
{
	char * p = NULL;
	int count = 0, i = 0;
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	p = T2A(strRtspUrl);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"TEARDOWN %s RTSP/1.0\r\n"
		"CSeq: %d\r\n", p, nCseq);
	if (i <= 0)
		return FALSE;
	count += i;

	if (!auth.IsEmpty())
	{
		p = T2A(auth);
		if (NULL == p)
			return FALSE;
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Authorization: %s\r\n", p);
		if (i <= 0)
			return FALSE;
		count += i;
	}
	p = T2A(strSession);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
		"Session: %s\r\n\r\n", p);
	if (i <= 0)
		return FALSE;
	count += i;


	rtspMess.nLen = count;

	return true;
}

//构建心跳消息
BOOL buildGetParamemter(RTSP_MESSAGE &rtspMess, int nCseq, CString strRtspUrl,
	CString strSession, const CString auth)
{
	char * p = NULL;
	int count = 0, i = 0;
	memset(rtspMess.szData, 0, RTSP_MESSAGE_SIZE);

	USES_CONVERSION;
	p = T2A(strRtspUrl);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData, RTSP_MESSAGE_SIZE,
		"GET_PARAMETER %s RTSP/1.0\r\n"
		"CSeq: %d\r\n", p, nCseq);
	if (i <= 0)
		return FALSE;
	count += i;

	if (!auth.IsEmpty())
	{
		p = T2A(auth);
		if (NULL == p)
			return FALSE;
		i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
			"Authorization: %s\r\n", p);
		if (i <= 0)
			return FALSE;
		count += i;
	}
	p = T2A(strSession);
	if (NULL == p)
		return FALSE;
	i = sprintf_s(rtspMess.szData + count, RTSP_MESSAGE_SIZE - count,
		"Session: %s\r\n\r\n", p);
	if (i <= 0)
		return FALSE;
	count += i;


	rtspMess.nLen = count;

	return true;
}

//取出rtsp地址中的 用户名和密码 ip和端口
BOOL process_url(const CString &strRtspUrl, CString & username, CString &passwd,
	CString &IP, unsigned short &nPort)
{
	CString t_addr, t_user, t_passwd;
	unsigned short port = 0;
	char  url[1024] = { 0 }, *p = NULL;


	USES_CONVERSION;
	p = T2A(strRtspUrl);
	if (p == NULL)
		return FALSE;
	strcpy_s(url, 1024, p);


	p = strstr(url, "@");//有用户名和密码
	if (p != NULL)
	{
		p = strstr(url, ":");
		if (NULL == p)
			return FALSE;
		//user
		p += 3;
		while (*p != '\0' && *p != ':')
		{
			t_user += *p;
			p++;
		}
		//passwd
		p++;
		while (*p != '\0' && *p != '@')
		{
			t_passwd += *p;
			p++;
		}
		//user
		p++;
		while (*p != '\0' && *p != ':')
		{
			if ((*p > 47 && *p < 58) || *p == '.')
				t_addr += *p;
			p++;
		}
		//port
		p++;
		while (*p != '\0')
		{
			if (*p > 47 && *p < 58)
				port = port * 10 + (*p - 48);
			p++;
		}

	}
	else//没有用户名和密码
	{
		p = strstr(url, ":");
		if (NULL == p)
			return FALSE;
		//addr
		p++;
		while (*p != '\0' && *p != ':')
		{
			if ((*p > 47 && *p < 58) || *p == '.')
				t_addr += *p;
			p++;
		}
		//port
		p++;
		while (*p != '\0')
		{
			if (*p > 47 && *p < 58)
				port = port * 10 + (*p - 48);
			p++;

		}

	}

	username = t_user;
	passwd = t_passwd;
	IP = t_addr;
	nPort = port;

	return TRUE;
}

//解析401中的realm nonce
BOOL proc_realm_nonce(CString &realm, CString &nonce, char *mess)
{
	char *p = NULL;
	CString str_realm, str_nonce;

	p = strstr(mess, "realm");
	if (p == NULL)
		return FALSE;
	p += strlen("realm=\"");
	while (1)
	{
		if (*p == '\"' || *p == '\0')
			break;
		str_realm += *p;
		p++;
	}
	realm = str_realm;

	p = strstr(mess, "nonce");
	if (p == NULL)
	return FALSE;
	p += strlen("nonce=\"");
	while (1)
	{
		if (*p == '\"' || *p == '\0')
			break;
		str_nonce += *p;
		p++;
	}
	nonce = str_nonce;
		
	return TRUE;
}




//解析回应消息中的状态和Cseq 以及
BOOL ProcessRespondMessage(RTSP_MESSAGE &rtspMess, RESPOND_STATUS &status, int &nCseq)
{
	char *szTemp = NULL;
	int nRepStatu = 0, nCseqT = 0;


	szTemp = strstr(rtspMess.szData, " ");//找到第一个空格
	if (szTemp == NULL)
	{
		return false;
	}
	szTemp++;


	while (*szTemp != ' ')//遇到空格结束
	{
		if (*szTemp >= 48 && *szTemp <= 57)//如果是数字
			nRepStatu = nRepStatu * 10 + (*szTemp - 48);
		szTemp++;
	}
	switch (nRepStatu)//只判定了ok（200）和 401 状态
	{
	case 200:
		status = ok;
		break;
	case 401:
		status = Unauthorized;
		break;
	default:
		status = other;
		break;
	}

	//解析cseq
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

		while (*szTemp != ' ')//跳过空格
		{
			szTemp++;
		}
		szTemp++;

		while (*szTemp != '\r')//\r 结束
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
	Sleep(500);

	m_TcpSockRtsp.Close();
	m_udpAudio.Close();
	m_udpVideo.Close();

	CloseHandle(m_hRecvAudioThread);
	CloseHandle(m_hRecvVideoThread);
	CloseHandle(m_hSendHeartbeatThread);

}

BOOL CRtspClient::init(WORD usRtspPort, WORD usRtpAudioPort, WORD usRtcp_a_p, WORD usRtpVideoPort,
	WORD usRtcp_v_p)
{
	CString strIP;
	unsigned short usPort = 0;

	m_bWork = false;
	m_usLocalRtspPort = usRtspPort;
	m_a_port = usRtpAudioPort;
	m_a_port_rtcp = usRtcp_a_p;
	m_v_port = usRtpAudioPort;
	m_v_port_rtcp = usRtcp_v_p;
	m_nCSeq = 0;
	m_auth_md = non;


	//rtsp基于tcp协议
	if (!m_TcpSockRtsp.Create(usRtspPort))
	{
		return false;
	}
	//更新端口号
	if (!m_TcpSockRtsp.GetSockName(strIP, usPort))
	{
		return false;
	}
	m_usLocalRtspPort = usPort;
	//不阻塞模式
	if (!m_TcpSockRtsp.EnableNonBlocking(true))
	{
		return false;
	}
	//创建心跳线程
	m_hSendHeartbeatThread = ::CreateThread(NULL, 0, SendHeartbeat, this, CREATE_SUSPENDED, NULL);
	if (NULL == m_hSendHeartbeatThread)
	{
		return FALSE;
	}

	m_bWork = TRUE;

	return TRUE;
}

//BOOL CRtspClient::init(unsigned short usRtspPort, unsigned short usRtpAudioPort,
//	unsigned short usRtpVideoPort)
//{
//	CString strIP;
//	unsigned short usPort = 0;
//
//	m_bWork = false;
//	m_usLocalRtspPort = usRtspPort;
//	m_usLocalRtpVideoPort = usRtpAudioPort;
//	m_usLocalRtpAudioPort = usRtpAudioPort;
//	m_nCSeq = 0;
//	m_auth_md = non;
//
//
//	//rtsp基于tcp协议
//	if (!m_TcpSockRtsp.Create(usRtspPort))
//	{
//		return false;
//	}
//	//更新端口号
//	if (!m_TcpSockRtsp.GetSockName(strIP, usPort))
//	{
//		return false;
//	}
//	m_usLocalRtspPort = usPort;
//	//不阻塞模式
//	if (!m_TcpSockRtsp.EnableNonBlocking(true))
//	{
//		return false;
//	}
//
//
//	//if (!m_UdpSockRtpAudio.Create(usRtpAudioPort, SOCK_DGRAM))
//	//{
//	//	return false;
//	//}
//	//if (usRtpAudioPort == 0)
//	//{
//	//	if (!m_UdpSockRtpAudio.GetSockName(strIP, usPort))
//	//	{
//	//		return false;
//	//	}
//	//	m_usRtpAudioPort = usPort;
//	//}
//	//else
//	//{
//	//	m_usRtpAudioPort = usPort;
//	//}
//
//	//创建接收线程
//	//m_hRecvAudioThread = ::CreateThread(NULL, 0, ReceiveAudioThread, this, CREATE_SUSPENDED, NULL);
//	//if (NULL == m_hRecvAudioThread)
//	//{
//	//	return FALSE;
//	//}
//	
//
//	//if (!m_UdpSockRtpVideo.Create(usRtpVideoPort, SOCK_DGRAM))
//	//{
//	//	return false;
//	//}
//	////if (usRtpVideoPort == 0)
//	//{
//	//	if (!m_UdpSockRtpVideo.GetSockName(strIP, usPort))
//	//	{
//	//		return false;
//	//	}
//	//	m_usRtpVideoPort = usPort;
//	//}
//	////else
//	//{
//	//	m_usRtpVideoPort = usPort;
//	//}
//
//
//	//m_hRecvVideoThread = ::CreateThread(NULL, 0, ReceiveVideoThread, this, CREATE_SUSPENDED, NULL);
//	//if (NULL == m_hRecvVideoThread)
//	//{
//	//	return FALSE;
//	//}
//	//
//	
//
//	//创建心跳线程
//	m_hSendHeartbeatThread = ::CreateThread(NULL, 0, SendHeartbeat, this, CREATE_SUSPENDED, NULL);
//	if (NULL == m_hSendHeartbeatThread)
//	{
//		return FALSE;
//	}
//
//	m_bWork = TRUE;
//
//	return TRUE;
//}



//构建digest认证的response
BOOL build_digest_response(CString &response, const CString &realm, const CString &nonce,
	const CString &rtsp_url, const CString method, const CString &user, const CString &passwd)
{

	char *p = NULL;
	int len = 0;
	CString  str, md5_mt, md5_us, resp;

	//算法：response= md5( md5(username:realm:password):nonce:md5(public_method:url) );

	//char *s = "10749049fe180c7cb61f0cf1d4cc3d25:D221052JBHUGNIHUIHYUGYKJHOIYHYGYOI213ED0275523963E31BBE72F0:b1072e1b017d8f3ac08ddde0b13013ed";
	//CRtspClient::build_md5((unsigned char *)s, strlen(s), resp);
	//user
	str.Format(_T("%s:%s:%s"), user, realm, passwd);
	USES_CONVERSION;
	p = T2A(str);
	if (NULL == p)
		return FALSE;
	len = str.GetLength();
	if (!CRtspClient::build_md5((unsigned char *)p, len, md5_us))
		return FALSE;

	//method:url
	str.Format(_T("%s:%s"), method, rtsp_url);
	p = T2A(str);
	if (NULL == p)
		return FALSE;
	len = str.GetLength();
	if (!CRtspClient::build_md5((unsigned char *)p, len, md5_mt))
		return FALSE;

	//response
	str.Format(_T("%s:%s:%s"), md5_us, nonce, md5_mt);
	p = T2A(str);
	if (NULL == p)
		return FALSE;
	len = str.GetLength();
	if (!CRtspClient::build_md5((unsigned char *)p, len, resp))
		return FALSE;

	response = resp;

	return TRUE;

}


BOOL CRtspClient::build_md5(const BYTE * pbData, int nDataLen, CString & strMd5Hash)
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
		strMd5Hash.AppendFormat(_T("%02x"), pHash[i]);
	delete[] pHash;


	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return TRUE;

}

CString CRtspClient::base64_encode(CString src, int srclen)
{
	unsigned char * base64 = (unsigned char *)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	int n, buflen, i, j;
	static unsigned char *dst;
	CString buf = src;
	buflen = n = srclen;
	dst = (unsigned char*)malloc(buflen / 3 * 4 + 3);
	memset(dst, 0, buflen / 3 * 4 + 3);
	for (i = 0, j = 0; i <= buflen - 3; i += 3, j += 4) {
		dst[j] = (buf[i] & 0xFC) >> 2;
		dst[j + 1] = ((buf[i] & 0x03) << 4) + ((buf[i + 1] & 0xF0) >> 4);
		dst[j + 2] = ((buf[i + 1] & 0x0F) << 2) + ((buf[i + 2] & 0xC0) >> 6);
		dst[j + 3] = buf[i + 2] & 0x3F;
	}
	if (n % 3 == 1) {
		dst[j] = (buf[i] & 0xFC) >> 2;
		dst[j + 1] = ((buf[i] & 0x03) << 4);
		dst[j + 2] = 64;
		dst[j + 3] = 64;
		j += 4;
	}
	else if (n % 3 == 2) {
		dst[j] = (buf[i] & 0xFC) >> 2;
		dst[j + 1] = ((buf[i] & 0x03) << 4) + ((buf[i + 1] & 0xF0) >> 4);
		dst[j + 2] = ((buf[i + 1] & 0x0F) << 2);
		dst[j + 3] = 64;
		j += 4;
	}
	for (i = 0; i<j; i++) /* map 6 bit value to base64 ASCII character */
		dst[i] = base64[(int)dst[i]];
	dst[j] = 0;
	return CString(dst);
}

BOOL CRtspClient::base64_decode(char * szCode, int nCodeLen, char * szDeCode, int * nDecodeLen)
{
	if (szCode == NULL || szDeCode == NULL)
	{
		return false;
	}

	//根据base64表，以字符找到对应的十进制数据    
	int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,62,0,0,0,
		63,52,53,54,55,56,57,58,
		59,60,61,0,0,0,0,0,0,0,0,
		1,2,3,4,5,6,7,8,9,10,11,12,
		13,14,15,16,17,18,19,20,21,
		22,23,24,25,0,0,0,0,0,0,26,
		27,28,29,30,31,32,33,34,35,
		36,37,38,39,40,41,42,43,44,
		45,46,47,48,49,50,51
	};
	long len;
	long str_len;
	//unsigned char *res;
	int i, j;

	//计算解码后的字符串长度    
	len = nCodeLen;
	//判断编码后的字符串后是否有=    
	if (strstr(szCode, "=="))
		str_len = len / 4 * 3 - 2;
	else if (strstr(szCode, "="))
		str_len = len / 4 * 3 - 1;
	else
		str_len = len / 4 * 3;

	*nDecodeLen = str_len;

	//以4个字符为一位进行解码    
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		//取出第一个字符对应base64表的十进制数的前6位与第二个字符对应base64表的十进制数的后2位进行组合    
		szDeCode[j] = ((unsigned char)table[szCode[i]]) << 2 | (((unsigned char)table[szCode[i + 1]]) >> 4);
		//取出第二个字符对应base64表的十进制数的后4位与第三个字符对应bas464表的十进制数的后4位进行组合    
		szDeCode[j + 1] = (((unsigned char)table[szCode[i + 1]]) << 4) | (((unsigned char)table[szCode[i + 2]]) >> 2);
		//取出第三个字符对应base64表的十进制数的后2位与第4个字符进行组合    
		szDeCode[j + 2] = (((unsigned char)table[szCode[i + 2]]) << 6) | ((unsigned char)table[szCode[i + 3]]);
	}

	return true;
}

////digest 认证
//CString CRtspClient::build_digest_authorization(const CString username, const CString &passwd, 
//	const CString &realm, const CString &nonce, const CString &method, const CString &uri)
//{
//	CString auth, response;
//
//	//计算response
//	if (!build_digest_response(response, realm, nonce, uri, method, username, passwd))
//		return FALSE;
//	//构建auth
//	auth.Format(_T("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"\r\n"),
//		username, realm, nonce, uri, response);
//	return auth;
//}
//
////basic认证（base64（user：passwd））
//CString CRtspClient::build_basic_authorization(const CString &usernmae, const CString &passwd)
//{
//	CString auth;
//
//	CString basic_src, base64_dst;
//	basic_src.Format(_T("%s:%s"), m_user, m_passwd);
//	base64_dst = CRtspClient::base64_encode(basic_src, basic_src.GetLength());
//	if (base64_dst.IsEmpty())
//		return FALSE;
//	auth.Format(_T("Basic %s\r\n"), base64_dst);
//
//	return auth;
//}

//digest 认证
CString CRtspClient::build_digest_authorization(const CString &method)
{
	CString auth, response, uri;

	uri.Format(_T("rtsp://%s:%d"), m_strCameraIP, m_usCameraPort);
	//计算response
	if (!build_digest_response(response, m_realm, m_nonce, uri, method, m_user, m_passwd))
		return FALSE;
	//构建auth
	auth.Format(_T("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""),
		m_user, m_realm, m_nonce, uri, response);
	return auth;
}

//basic认证（base64（user：passwd））
CString CRtspClient::build_basic_authorization()
{
	CString auth;

	CString basic_src, base64_dst;
	basic_src.Format(_T("%s:%s"), m_user, m_passwd);
	base64_dst = CRtspClient::base64_encode(basic_src, basic_src.GetLength());
	if (base64_dst.IsEmpty())
		return FALSE;
	auth.Format(_T("Basic %s\r\n"), base64_dst);

	return auth;
}


BOOL get_sdp(CSDP &r_sdp, const RTSP_MESSAGE & mess)
{
	if (NULL == mess.szData)
		return FALSE;

	char data[RTSP_MESSAGE_SIZE] = { 0 };

	memcpy(data, mess.szData, mess.nLen);
	char *sdp = strstr(data, "\r\n\r\nv=");
	if (NULL == sdp)
		return FALSE;
	sdp += 4;
	int rtsp_head_len = sdp - data;
	int sdp_len = mess.nLen - rtsp_head_len;
	if (!r_sdp.from_buffer(sdp, sdp_len))
		return FALSE;


	return TRUE;
}

//链接摄像头
BOOL CRtspClient::open_url(CString strUrl)
{
	RTSP_MESSAGE requestMess, respondMess;
	int nCount = 0,nRepCseq = 0;
	BOOL bRet = FALSE;
	RESPOND_STATUS rtspStatus = other;
	CString auth, url;
	//unsigned short usPort;

	//m_strRtspUrl = strUrl;
	//解析用户名，密码，地址，端口，链接摄像头
	if (process_url(strUrl, m_user, m_passwd, m_strCameraIP, m_usCameraPort) == false)
		return false;
	if (m_TcpSockRtsp.Connect(m_strCameraIP, m_usCameraPort) ==false)
		return false;

	//发送 options 消息
	url.Format(_T("rtsp://%s:%d"), m_strCameraIP, m_usCameraPort);
	m_nCSeq++;
	if (!buildOptionsMessage(requestMess, m_nCSeq, url))
		return bRet;
	nCount = m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	if (nCount < 0)
		return bRet;
	Sleep(500);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
		return bRet;
	respondMess.nLen = nCount;
	//检查响应消息状态
	if (!ProcessRespondMessage(respondMess, rtspStatus, nRepCseq) || nRepCseq != m_nCSeq)
			return bRet;
	if (rtspStatus != ok)
		return bRet;

	//发送 describe 消息，得到摄像头的sdp
	//可能需要认证
	m_nCSeq++;
	if (!buildDescribeMessage(requestMess, m_nCSeq, url, auth))
		return bRet;
	nCount = m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	if (nCount < 0)
		return bRet;
	Sleep(500);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
		return bRet;
	respondMess.nLen = nCount;
	//检查响应消息状态是不是ok
	if (!ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
		return FALSE;
	if (nRepCseq != m_nCSeq)
		return bRet;

	if (rtspStatus == ok)
	{
		//提取sdp
		if (!get_sdp(m_CameraSdp, respondMess))
			return bRet;
	}
	else if (rtspStatus == Unauthorized)//需要认证
	{
		//确定认证方法
		char *p = NULL;
		p = strstr(respondMess.szData, "Digest");
		if (p != NULL)//digest
		{
			m_auth_md = digest;

			//获取realm nonce
			CString realm, nonce;
			if (!proc_realm_nonce(realm, nonce, respondMess.szData))
				return FALSE;
			m_realm = realm;
			m_nonce = nonce;
			//计算auth
			auth = build_digest_authorization(_T("DESCRIBE"));
		}
		else
		{
			p = strstr(respondMess.szData, "Basic");
			if (NULL == p)
				return FALSE;
			m_auth_md = basic;
			auth = build_basic_authorization();
		}
		//构建认证消息
		m_nCSeq++;
		if (!buildDescribeMessage(requestMess, m_nCSeq, url, auth))
			return bRet;
		//发送
		nCount = m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		if (nCount < 0)
			return bRet;
		//接收
		Sleep(500);
		nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (nCount < 0)
			return bRet;
		respondMess.nLen = nCount;
		//解析 获取sdp
		if (!ProcessRespondMessage(respondMess, rtspStatus, nRepCseq) || nRepCseq != m_nCSeq)
			return bRet;
		if (rtspStatus != ok)
			return bRet;
		if (!get_sdp(m_CameraSdp, respondMess))
			return bRet;
	}
	else
	{
		return bRet;
	}

	//发送setup消息
	int i = 0;
	CString addr, session;
	WORD port, rtcp_port;
	if (m_CameraSdp.m_bAudioMedia)//如果sdp中有音频信息，
	{
		if (!m_udpAudio.Create(m_a_port, SOCK_DGRAM))
			return FALSE;
		if (!m_udpAudio.GetSockName(addr, port))
			return FALSE;
		if (!m_udpAudio_rtcp.Create(m_a_port_rtcp, SOCK_DGRAM))
			return FALSE;
		if (!m_udpAudio_rtcp.GetSockName(addr, rtcp_port))
			return FALSE;
		
		m_a_port = port;
		m_a_port_rtcp = rtcp_port;

		//url需要修改
		i = m_CameraSdp.m_strAudioControl.Find(_T("rtsp://"), 0);
		if (i >= 0)
			url = m_CameraSdp.m_strAudioControl;
		else
			url.Format(_T("rtsp://%s:%d/%s"), m_strCameraIP, m_usCameraPort, m_CameraSdp.m_strAudioControl);
		//digest需要重新计算 auth
		if (m_auth_md == digest)
			auth = build_digest_authorization(_T("SETUP"));

		m_nCSeq++;

		if (!buildSetUpMessage(requestMess, url, m_nCSeq, auth, port, rtcp_port, session))
			return bRet;

		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(500);
		nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (nCount < 0)
			return bRet;
		//检查响应消息状态是不是ok
		if (!ProcessRespondMessage(respondMess, rtspStatus, nRepCseq) || nRepCseq != m_nCSeq)
			return bRet;
		if (rtspStatus != ok)
			return bRet;
		//获取session(音频和视频的session应该是一样的)
		if (!GetSession(respondMess, m_strSession))
			return bRet;
		//创建接收线程
		m_hRecvAudioThread = ::CreateThread(NULL, 0, ReceiveAudioThread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_hRecvAudioThread)
			return FALSE;
	}

	if (m_CameraSdp.m_bVideoMedia)//视频
	{
		if (!m_udpVideo.Create(m_v_port, SOCK_DGRAM))
			return FALSE;
		if (!m_udpVideo.GetSockName(addr, port))
			return FALSE;
		if (!m_udpVideo_rtcp.Create(m_v_port_rtcp, SOCK_DGRAM))
			return FALSE;
		if (!m_udpVideo_rtcp.GetSockName(addr, rtcp_port))
			return FALSE;

		m_v_port = port;
		m_v_port_rtcp = rtcp_port;


		m_nCSeq++;
		i = m_CameraSdp.m_strVideoControl.Find(_T("rtsp://"), 0);
		if (i >= 0)
			url = m_CameraSdp.m_strVideoControl;
		else
			url.Format(_T("rtsp://%s:%d/%s"), m_strCameraIP, m_usCameraPort, m_CameraSdp.m_strVideoControl);
		//digest需要重新计算 auth
		if (m_auth_md == digest)
			auth = build_digest_authorization(_T("SETUP"));
		if (!buildSetUpMessage(requestMess, url, m_nCSeq, auth, m_v_port, m_v_port_rtcp, m_strSession))
			return bRet;

		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(500);
		nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (nCount < 0)
		{
			return bRet;
		}
		//检查响应消息状态是不是ok
		if (!ProcessRespondMessage(respondMess, rtspStatus, nRepCseq) || nRepCseq != m_nCSeq)
			return bRet;
		if (rtspStatus != ok)
			return bRet;
		//创建接收线程
		m_hRecvVideoThread = ::CreateThread(NULL, 0, ReceiveVideoThread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_hRecvVideoThread)
		{
			return FALSE;
		}
	}


	//发送play消息
	m_nCSeq++;
	url.Format(_T("rtsp://%s:%d"), m_strCameraIP, m_usCameraPort);
	if (m_auth_md == digest)
		auth = build_digest_authorization(_T("PLAY"));
	if (!buildPlayMessage(requestMess, m_nCSeq, url, m_strSession, auth))
	{
		return bRet;
	}

	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(500);
	nCount = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
	if (nCount < 0)
	{
		i = GetLastError();
		return bRet;
	}
	//检查响应消息状态是不是ok
	if (ProcessRespondMessage(respondMess, rtspStatus, nRepCseq))
	{
		if (rtspStatus != ok)
		{
			return bRet;
		}
	}

	::ResumeThread(m_hRecvAudioThread);
	::ResumeThread(m_hRecvVideoThread);

	::ResumeThread(m_hSendHeartbeatThread);
	bRet = TRUE;

	return bRet;
}

//拆除链接
BOOL CRtspClient::teardown()
{
	RTSP_MESSAGE requestMess, respondMess;
	int nCount = 0, nRepCseq = 0;
	BOOL bRet = false;
	RESPOND_STATUS rtspStatus = other;
	CString url, auth;

	m_nCSeq++;
	url.Format(_T("rtsp://%s:%d"), m_strCameraIP, m_usCameraPort);
	if (m_auth_md == digest)
		auth = build_digest_authorization(_T("TEARDEWN"));
	if (buildTeardownMessage(requestMess, m_nCSeq, url, m_strSession, auth) == false)
		return FALSE;

	m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
	Sleep(500);
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
		if (count > 0 && recv_ip == m_strCameraIP)
		{
			for (int i = 0; i < m_arrCache.GetSize(); i++)
			{
				if (m_arrCache[i])
				{
					CRtpPacketPtr p = new RTP_PACKET;
					memcpy(p->szData, buf, count);
					p->usPackLen = count;
					p->enType = audio;
					m_arrCache[i]->AddPacket(p);
				}

			}
			
		}
		else
		{
			Sleep(10);
		}
	}

	if (NULL != buf)
	{
		delete [] buf;
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
		m_udpVideo.GetSockName(recv_address, recv_port);

		count = m_udpVideo.ReceiveFrom(buf, RTP_BUF_SIZE, recv_address, recv_port);
		if (count > 0 && recv_address == m_strCameraIP)
		{
			for (int i = 0; i < m_arrCache.GetSize(); i++)
			{
				if (m_arrCache[i])
				{
					CRtpPacketPtr p = new RTP_PACKET;
					memcpy(p->szData, buf, count);
					p->usPackLen = count;
					p->enType = video;
					m_arrCache[i]->AddPacket(p);
				}
			}
		}
		else
		{
			Sleep(10);
		}

	}

	if (NULL != buf)
	{
		delete [] buf;
		buf = NULL;
	}


	return 0;
}

//发送心跳包，并接受回应
DWORD CRtspClient::DoSendHearbeat()
{
	Sleep(500);
	int count = 0, nCSeq = 0;
	RTSP_MESSAGE requestMess, respondMess ;
	RESPOND_STATUS repStatus;

	while (m_bWork)
	{
		m_nCSeq++;
		CString auth, url;
		url.Format(_T("rtsp://%s:%d"), m_strCameraIP, m_usCameraPort);
		if (m_auth_md == digest)
			auth = build_digest_authorization(_T("GET_PARAMETER"));
		if (!buildGetParamemter(requestMess, m_nCSeq, url, m_strSession, auth))
			break;
		m_TcpSockRtsp.Send(requestMess.szData, requestMess.nLen);
		Sleep(500);
		count = m_TcpSockRtsp.Receive(respondMess.szData, RTSP_MESSAGE_SIZE);
		if (count > 0)
		{
			//检查响应消息状态ok
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


