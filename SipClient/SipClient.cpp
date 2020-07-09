#include "stdafx.h"
#include "SipClient.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define  SERVER_TIMEOUT     60000 //sip消息等待时间
#define	 ANSWER_TIMEOUT     60000 //对方客户端接听时间
#define  SIP_BUF_SIZE		4096
#define  TEMP_BUF_SIZE		1024
#define  AUTH_COUNT	3



CSipClient::CSipClient()
{
	m_bwork = FALSE;
	m_client_status = uninitialized;


	m_send_cache = NULL;
	m_recv_h = NULL;
	m_proc_h = NULL;
	m_incoming_call = NULL;
	m_call_info = NULL;
}

CSipClient::~CSipClient()
{
	m_bwork = FALSE;
	m_client_status = uninitialized;

	WaitForSingleObject(m_recv_h, INFINITE);
	WaitForSingleObject(m_proc_h, INFINITE);
	CloseHandle(m_recv_h);
	CloseHandle(m_proc_h);


}


BOOL CSipClient::init(const CString &username, const CString &passwd, const CString &sev_addr,
	WORD sev_port, WORD l_sip_port)
{

	BOOL ret = FALSE;
	CString addr;
	WORD port;

	m_user = username;
	m_password = passwd;
	m_sev_addr = sev_addr;
	m_sev_port = sev_port;

	//创建sock
	if (!m_sock.Create(l_sip_port, SOCK_DGRAM))
		return ret;
	if (!m_sock.GetSockName(addr, port))
		return ret;
	m_local_addr = _T("192.168.1.82");
	m_l_sip_port = port;


	//创建接收线程
	if (NULL == m_recv_h)
	{
		m_recv_h = ::CreateThread(NULL, 0, ReceiveSipThread, this, CREATE_SUSPENDED, NULL);
		ASSERT(NULL != m_recv_h);
		if (NULL == m_recv_h)
			return FALSE;
	}
	//创建解析sip消息线程
	if (NULL == m_proc_h)
	{
		m_proc_h = ::CreateThread(NULL, 0, SipPacketProcessThread, this, CREATE_SUSPENDED, NULL);
		ASSERT(NULL != m_proc_h);
		if (NULL == m_proc_h)
			return FALSE;
	}

	////发送媒体
	//if (NULL == m_send_rtp_h)
	//{
	//	m_send_rtp_h = ::CreateThread(NULL, 0, send_media_thread, this, CREATE_SUSPENDED, NULL);
	//	ASSERT(NULL != m_send_rtp_h);
	//	if (NULL == m_send_rtp_h)
	//		return FALSE;
	//}
	////接收媒体
	//if (NULL == m_recv_rtp_h)
	//{
	//	m_recv_rtp_h = ::CreateThread(NULL, 0, recv_media_thread, this, CREATE_SUSPENDED, NULL);
	//	ASSERT(NULL != m_recv_rtp_h);
	//	if (NULL == m_recv_rtp_h)
	//		return FALSE;
	//}

	m_reg_cseq = 0;
	m_inv_cseq = 0;

	m_client_status = init_ok;
	m_bwork = TRUE;


	ret = TRUE;

	return ret;
}


//构建并发送注册消息 
#define SEV_TIME_OUT  2000
BOOL CSipClient::register_account()
{
	if (m_client_status != init_ok )
		return FALSE;

	BOOL register_ok = FALSE, register_auth = FALSE;
	//构建消息
	CSipPacket reg_request, reg_status;
	CSipPacketInfo request_info, status_info;
	CString auth, optional, strPeerIP;
	int nCheckResult = 0, ret = 0, send_num = 2;
	WORD uPeerPort = 0;
	BYTE pBuffer[SIP_BUF_SIZE] = { 0 };

	if (!build_register_message(reg_request, auth, optional))
		return FALSE;

	while (send_num)
	{
		if (register_auth)
		{
			auth = build_auth_string(Register, Unauthorized, &status_info);
			if (auth.IsEmpty())
				break;
			if (!reg_request.add_auth(auth))
				break;

		}

		if (!request_info.from_packet(&reg_request))
			break;
		if (!send_packet(&reg_request))
			break;
		send_num--;
		Sleep(200);

		nCheckResult = m_sock.CheckReceive();
		if (nCheckResult > 0)
		{
			ret = m_sock.ReceiveFrom(pBuffer, SIP_BUF_SIZE, strPeerIP, uPeerPort);
			if (ret > 0 && uPeerPort == m_sev_port
				&& strPeerIP.CompareNoCase(m_sev_addr) == 0)
			{
				if (!reg_status.from_buffer((char *)pBuffer, ret))
					break;
				if (!status_info.from_packet(&reg_status))
					break;
				if (!compare_packet(request_info, status_info))
					break;
				if (status_info.get_status_code() == OK)
				{
					register_ok = TRUE;
					break;
				}
				else if (status_info.get_status_code() == Unauthorized)
				{
					register_auth = TRUE;
					continue;
				}
				else
					break;
			}
		}

	}

	//注册成功后 开启接收和处理线程
	if (register_ok)
	{
		m_reg_cseq++;
		m_client_status = wait;
		if (NULL != m_recv_h)
			::ResumeThread(m_recv_h);
		if (NULL != m_proc_h)
			::ResumeThread(m_proc_h);
	}

	return register_ok;
}

//1 检查本地sdp，2初始化call info，3构建并发送邀请消息
BOOL CSipClient::make_call(const CString & strCallName, WORD a_port, WORD v_port )
{

	if (m_client_status != wait )
		return FALSE;

	BOOL make_call_ok = FALSE;
	CSipPacket packet;
	CString auth, optional;

	//初始化call info
	if (NULL == m_call_info)
	{
		m_call_info = new CALL_INFO();
		if (m_call_info == NULL)
			return FALSE;
	}

	if (!m_call_info->init(m_sdp, m_local_addr, a_port, v_port))
	{
		m_call_info->close_call_info();
		return FALSE;
	}


	//构造inv packet
	if (!build_invite_message(packet, strCallName, m_call_info->localSdp, auth, optional))
		return FALSE;
	//packet info
	if (!m_call_info->request_info.from_packet(&packet))
		return FALSE;
	//发送
	if (!send_packet(&packet))
		goto end;

	make_call_ok = TRUE;
	m_inv_cseq++;
	m_client_status = inviteing;
	m_call_info->call_name = strCallName;
	m_call_info->sta = INVITE_SEND;


end:
	if (!make_call_ok)
		m_call_info->close_call_info();

	return make_call_ok;
}

//只发送bye消息
BOOL CSipClient::hangup()
{

	if (NULL == m_call_info || m_call_info->sta != INVITE_CALLING)
		return FALSE;

	//构建消息
	CSipPacket packet;
	CSipPacketInfo packet_info;

	if (!build_bye_message(packet))
		return FALSE;

	if (!packet_info.from_packet(&packet))
		return FALSE;

	//发送
	if (!send_packet(&packet))
		return FALSE;


	m_call_info->request_info = packet_info;
	m_inv_cseq++;


	return TRUE;
}

//sdp协商， 回复ok消息
BOOL CSipClient::call_answer(CSipPacketInfo *packet_info)
{

	if (m_client_status != wait || NULL == packet_info)
		return FALSE;

	//查看sdp
	CSDP rSdp;
	if (!packet_info->get_sdp_info(rSdp))
		return FALSE;

	if (rSdp.m_bVideoMedia)
	{
		rSdp.m_strVideoRtpMap.Find(_T("H264"))
	}



	//if (m_call_stu != INVITE_RECV || NULL == packet_info)
	//	return FALSE;

	//CSipPacket invite_ok_packet;
	////CSDP *sdp;
	//CString peer_addr;
	//WORD peer_port = 0;

	////本地sdp
	//if (NULL == m_local_sdp)
	//	return FALSE;

	////保存对方sdp
	//if (NULL == m_sdp)
	//{
	//	m_sdp = new CSDP();
	//	if (NULL == m_sdp)
	//		return FALSE;
	//}
	//*m_sdp = packet_info->m_sdp_info;




	//if (m_local_sdp->m_bAudioMedia && m_sdp->m_bAudioMedia)
	//{
	//	if (NULL == m_sock_a)
	//	{
	//		m_sock_a = new CNetSocket();
	//		if (NULL == m_sock_a)
	//			return FALSE;
	//	}

	//	if (!m_sock_a->Create(0, SOCK_DGRAM))
	//		return FALSE;
	//	if (!m_sock_a->GetSockName(peer_addr, peer_port))
	//		return FALSE;
	//	m_local_sdp->m_usAudioPort = peer_port;
	//	m_local_sdp->m_strAudioIP = m_local_addr;

	//}

	//if (m_local_sdp->m_bAudioMedia && m_sdp->m_bAudioMedia)
	//{
	//	if (NULL == m_sock_v)
	//	{
	//		m_sock_v = new CNetSocket();
	//		if (NULL == m_sock_v)
	//			return FALSE;
	//	}
	//	if (!m_sock_v->Create(0, SOCK_DGRAM))
	//		return FALSE;
	//	if (!m_sock_v->GetSockName(peer_addr, peer_port))
	//		return FALSE;
	//	m_local_sdp->m_usVideoPort = peer_port;
	//	m_local_sdp->m_strVideoIP = m_local_addr;

	//}

	//m_call_info->pLocalSdp = sdp;

	////call info
	//m_call_stu = INVITE_SDP_OK;
	//m_call_id = packet_info->get_call_id();
	//m_contact = packet_info->get_to().to_user;
	//if (m_call_info->pSdp->m_bAudioMedia)
	//{
	//	if (!m_call_info->udp_audio.Create(0, SOCK_DGRAM))
	//		return FALSE;
	//	if (!m_call_info->udp_audio.GetSockName(peer_addr, peer_port))
	//		return FALSE;
	//	m_local_sdp->m_usAudioPort = peer_port;
	//	m_local_sdp->m_strAudioIP = m_strLocalSipAddr;

	//}
	//if (m_call_info->pSdp->m_bVideoMedia)
	//{
	//	if (!m_call_info->udp_video.Create(0, SOCK_DGRAM))
	//		return FALSE;
	//	if (!m_call_info->udp_video.GetSockName(peer_addr, peer_port))
	//		return FALSE;
	//	m_local_sdp->m_usVideoPort = peer_port;
	//	m_local_sdp->m_strVideoIP = m_strLocalSipAddr;
	//}


/*	m_local_sdp->m_strAddress = m_strLocalSipAddr;
	m_local_sdp->m_bAudioMedia = FALSE;
	m_local_sdp->m_bVideoMedia = TRUE;
	m_local_sdp->m_strVideoIP = m_strLocalSipAddr;
	m_local_sdp->m_nVideoLoadType = 96;
	m_local_sdp->m_strVideoRtpMap = _T("96 H264/90000");
	m_local_sdp->m_strVideoFmtp = _T("96 packetization-mode=1;profile-level-id=4D002A;sprop-parameter-sets=Z00AKp2oHgCJ+WbgICAgQA==,aO48gA==");



	//回复ok消息
	//REQUEST_LINE req_par;
	//if (!invite_ok_packet.build_OK_packet(req_par))
	//	return FALSE;
	//if (!send_packet(&invite_ok_packet))
	//	return FALSE;

   


	return TRUE;
	*/
}

void CSipClient::set_coming_call_function(incoming_call_back function)
{
	m_incoming_call = function;
}

CRtpPacketCache* CSipClient::get_recv_cache()
{

	CRtpPacketCache *cache = NULL;
	if (NULL != m_call_info)
		cache = &(m_call_info->rtp_cache);

	return cache;
}

void CSipClient::set_send_cache(CRtpPacketCache * cache)
{
	if (NULL != cache)
		m_send_cache = cache;

	return;
}

BOOL CSipClient::set_sdp(const CSDP & sdp)
{
	//sdp

	m_sdp = sdp;
	//修改地址
	m_sdp.m_strAddress = m_local_addr;
	m_sdp.m_usAudioPort = 0;
	m_sdp.m_strAudioIP = m_local_addr;
	m_sdp.m_usVideoPort = 0;
	m_sdp.m_strVideoIP = m_local_addr;

	return TRUE;
}

CLIENT_STATUS CSipClient::get_client_status()
{
	return m_client_status;
}

CSDP CSipClient::get_sdp()
{
	return m_sdp;
}


DWORD CSipClient::ReceiveSipThread(LPVOID lpParam)
{
	CSipClient *pObject = (CSipClient*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->DoReceiveSip();
}

DWORD CSipClient::SipPacketProcessThread(LPVOID lpParam)
{
	CSipClient *pObject = (CSipClient*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->DoSipPacketProcess();
}


//接收sip消息
DWORD CSipClient::DoReceiveSip()
{

	char * pBuffer = new char [SIP_BUF_SIZE]();
	int nCheckResult = 0, ret = 0;
	CString strPeerIP;
	WORD uPeerPort = 0;
	CSipPacket *pack = NULL;

	while (m_bwork)
	{
		nCheckResult = m_sock.CheckReceive();
		if (nCheckResult > 0)
		{
			ret = m_sock.ReceiveFrom(pBuffer, SIP_BUF_SIZE, strPeerIP, uPeerPort);
			if (ret > 0 && uPeerPort == m_sev_port
				&& strPeerIP.CompareNoCase(m_sev_addr) == 0)
			{
				pack = new CSipPacket();
				if (pack != NULL)
				{
					if (pack->from_buffer(pBuffer, ret))
					{
						m_recv_lock.Lock();
						m_recv_packet_arr.Add(pack);
						m_recv_lock.Unlock();
					}

				}

			}
		}
		else
		{
			Sleep(50);
		}
	}

	delete [] pBuffer;
	pBuffer = NULL;

	return 0;
}

DWORD CSipClient::DoSipPacketProcess()
{
	CSipPacket *packet = NULL;
	CSipPacketInfo *packet_info = NULL;
	DWORD proc_time = 0;


	//循环处理消息
	while (m_bwork)
	{
		m_recv_lock.Lock();
		if (m_recv_packet_arr.GetSize() > 0)
		{
			packet = m_recv_packet_arr[0];
			m_recv_packet_arr.RemoveAt(0);
		}
		m_recv_lock.Unlock();


		if (packet != NULL)
		{
			proc_sip_mess(packet);
			delete packet;
			packet = NULL;
		}
		//else
		//{
		//	//处理send packet 队列
		//	m_req_info_lock.Lock();
		//	if (m_request_info_arr.GetSize() > 0)
		//	{
		//		packet_info = m_request_info_arr[0];
		//		if (NULL != packet_info)
		//		{
		//			proc_time = ::GetTickCount();
		//			if (proc_time - packet_info->get_build_time() > SERVER_TIMEOUT)
		//			{
		//				if (packet_info->get_request().method == Invite)
		//					m_client_status = wait;
		//				delete packet_info;
		//				packet_info = NULL;
		//				m_request_info_arr.RemoveAt(0);
		//			}
		//		}
		//	}
		//	m_req_info_lock.Unlock();
		//	
		//	Sleep(10);
		//}
	}

	return 0;

}


//DWORD CSipClient::send_media_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_send_media();
//
//}



//DWORD CSipClient::do_send_media()
//{
//	if (NULL == m_call_info || NULL == m_send_cache)
//		return 1;
//
//	CRtpPacketPtr rtp_pack;
//
//	CString audio_addr, video_addr;
//	WORD audio_port = 0, video_port = 0;
//	BOOL a_media = FALSE, v_media = FALSE;
//
//	if (m_call_info->sdp.m_bAudioMedia && m_sdp.m_bAudioMedia)
//	{
//		a_media = TRUE;
//		audio_port = m_call_info->sdp.m_usAudioPort;
//		if (m_call_info->sdp.m_strAudioIP.IsEmpty())
//			audio_addr = m_call_info->sdp.m_strAddress;
//		else
//			audio_addr = m_call_info->sdp.m_strAudioIP;
//	}
//
//	if (m_call_info->sdp.m_bVideoMedia && m_sdp.m_bVideoMedia)
//	{
//		v_media = TRUE;
//		video_port = m_call_info->sdp.m_usVideoPort;
//		if (m_call_info->sdp.m_strVideoIP.IsEmpty())
//			video_addr = m_call_info->sdp.m_strAddress;
//		else
//			video_addr = m_call_info->sdp.m_strVideoIP;
//	}
//
//	
//
//	while (m_bwork)
//	{
//		rtp_pack = m_send_cache->GetNextPacket();
//
//		if (NULL != rtp_pack)
//		{
//			if (rtp_pack->enType == audio && a_media)
//			{
//				m_call_info->udp_a.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//					audio_port, audio_addr);
//			}
//			else if (rtp_pack->enType == video && video)
//			{
//				m_call_info->udp_v.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//					video_port, video_addr);
//			}
//		}
//		else
//		{
//			Sleep(10);
//		}
//	}
//
//	return 0;
//}



//DWORD CSipClient::do_recv_video_media()
//{
//	if (NULL == m_call_info)
//		return 1;
//
//
//	int ret = 0;
//	CString recv_addr, peer_addr;
//	WORD recv_port, peer_port = 0;
//	unsigned char *buf = new unsigned char[4096]();
//	CRtpPacketPtr rtp_pack = NULL;
//
//	recv_addr = m_call_info->sdp.m_strVideoIP;
//	recv_port = m_call_info->sdp.m_usVideoPort;
//
//
//	while (m_bwork)
//	{
//		ret = m_call_info->udp_v.ReceiveFrom(buf, 4096, peer_addr, peer_port);
//		if (ret > 0 && recv_port == peer_port
//			&& recv_addr.Compare(peer_addr) == 0)
//		{
//			rtp_pack = new RTP_PACKET();
//			memcpy_s(rtp_pack->szData, RTP_PACKET_SIZE, buf, ret);
//			rtp_pack->usPackLen = ret;
//			rtp_pack->enType = video;
//			if (m_call_info!=NULL)
//				m_call_info->rtp_cache.AddPacket(rtp_pack);
//		}
//		
//	}
//
//	delete[] buf;
//	buf = NULL;
//	return 0;
//}
//
//DWORD CSipClient::do_recv_audio_media()
//{
//	if (NULL == m_call_info)
//		return 1;
//
//
//	int ret = 0;
//	CString recv_addr, peer_addr;
//	WORD recv_port, peer_port = 0;
//	unsigned char *buf = new unsigned char[4096]();
//	CRtpPacketPtr rtp_pack = NULL;
//
//	recv_addr = m_call_info->sdp.m_strAudioIP;
//	recv_port = m_call_info->sdp.m_usAudioPort;
//
//
//	while (m_bwork)
//	{
//		ret = m_call_info->udp_a.ReceiveFrom(buf, 4096, peer_addr, peer_port);
//		if (ret > 0 && recv_port == peer_port
//			&& recv_addr.Compare(peer_addr) == 0)
//		{
//			rtp_pack = new RTP_PACKET();
//			memcpy_s(rtp_pack->szData, RTP_PACKET_SIZE, buf, ret);
//			rtp_pack->usPackLen = ret;
//			rtp_pack->enType = audio;
//			
//			m_call_info->rtp_cache.AddPacket(rtp_pack);
//		}
//
//	}
//
//	delete[] buf;
//	buf = NULL;
//	return 0;
//}


//计算摘要认证的response的值
//注册认证方法： 1 HASH1=MD5(username:realm:password) 2 HASH2 = MD5(method:uri) 3 Response = MD5(HA1:nonce:HA2)
BOOL builf_auth_response(CString & response, const CString &username, const CString &passwd,
	const CString &realm, const CString &nonce, REQUEST_METHOD method, SIP_URI uri)
{
	char *p = NULL;
	CString  str_temp, hash1, hash2, hash3, str_method, str_uri;

	switch (method)
	{
	case Register:
		str_method.Format(_T("REGISTER"));
		break;
	case Invite:
		str_method.Format(_T("INVITE"));
		break;
	case Ack:
		str_method.Format(_T("ACK"));
		break;
	case Bye:
		str_method.Format(_T("BYE"));
		break;
	default:
		return FALSE;
	}

	if (uri.user.IsEmpty())
	{
		str_uri.Format(_T("sip:%s"), uri.host);
	}
	else
	{
		str_uri.Format(_T("sip:%s@%s"), uri.user, uri.host);

	}
	

	str_temp.Format(_T("%s:%s:%s"), username, realm, passwd);
	USES_CONVERSION;
	p = T2A(str_temp);
	if (NULL == p)
		return FALSE;
	if (!CRtspClient::build_md5((unsigned char *)p, str_temp.GetLength(), hash1))
		return FALSE;

	str_temp.Format(_T("%s:%s"), str_method, str_uri);
	p = T2A(str_temp);
	if (NULL == p)
		return FALSE;
	if (!CRtspClient::build_md5((unsigned char *)p, str_temp.GetLength(), hash2))
		return FALSE;

	str_temp.Format(_T("%s:%s:%s"), hash1, nonce, hash2);
	p = T2A(str_temp);
	if (NULL == p)
		return FALSE;
	if (!CRtspClient::build_md5((unsigned char *)p, str_temp.GetLength(), hash3))
		return FALSE;

	response = hash3;

	return TRUE;


}


//int CSipClient::find_send_pack_index(const CString &via_branch)
//{
//	if (via_branch.IsEmpty())
//		return -1;
//
//	int index = -1;
//	CString req_branch;
//
//	m_req_info_lock.Lock();
//	for (int i = 0; i < m_request_info_arr.GetSize(); i++)
//	{
//		if (NULL != m_request_info_arr[i])
//		{
//			req_branch = m_request_info_arr[i]->get_via().branch;
//			if (req_branch == via_branch)
//			{
//				index = i;
//				break;
//			}
//		}
//	}
//	m_req_info_lock.Unlock();
//
//
//	return  index;
//}


CString CSipClient::build_auth_string(REQUEST_METHOD request_method, STATUS_CODE code, CSipPacketInfo *status_info)
{

	CString response, realm, nonce, str_uri, auth;
	SIP_URI uri;

	if (code != 401 && code != 407)
		return auth;
	//计算response值
	realm = status_info->get_realm();
	nonce = status_info->get_nonce();
	if (realm.IsEmpty() || nonce.IsEmpty())
		return auth;
	if (request_method == Invite)
		uri.user = status_info->get_to().to_user;
	uri.host = m_sev_addr;
	if (uri.user.IsEmpty())
		str_uri.Format(_T("sip:%s"), uri.host);
	else
		str_uri.Format(_T("sip:%s@%s"), uri.user, uri.host);

	if (!builf_auth_response(response, m_user, m_password, realm, nonce, request_method, uri))
		return auth;

	if (code == 401)
		auth.Format(_T("Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\",algorithm=MD5\r\n"),
			m_user, realm, nonce, str_uri, response);
	else if(code == 407)
		auth.Format(_T("Proxy-Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\",algorithm=MD5\r\n"),
			m_user, realm, nonce, str_uri, response);

	return auth;
}

//CString CSipClient::get_self_sip_uri()
//{
//	CString sip_uri;
//	sip_uri.Format(_T("sip:%s@%s:%d"), m_user, m_local_addr, m_l_sip_port);
//	return sip_uri;
//}



////构建 注册认证 消息
//BOOL build_register_auth_packet(CSipPacket &packet, CSipPacketInfo *request_info,
//	const CString &str_auth, int cseq)
//{
//	if (NULL == request_info)
//		return FALSE;
//
//	//CSipPacket packet_new;
//
//	//构造packet
//	REQUEST_LINE request = request_info->get_request();
//	HEADER_VIA via_par = request_info->get_via();
//	via_par.branch = CSipPacket::build_via_branch();
//	if(via_par.branch.IsEmpty())
//		return FALSE;
//
//	HEADER_FROM from_par = request_info->get_from();
//	HEADER_TO to_par = request_info->get_to();
//	CString call_id = request_info->get_call_id();
//	int max_forwards = request_info->get_max_forwards();
//	HEADER_CSEQ cseq_par;
//	HEADER_CONTACT cont_par;
//	cseq_par.cseq = cseq;
//	cseq_par.method = Register;
//	cont_par = request_info->get_contact();
//
//	if (!packet.build_request_packet(request, via_par,from_par,to_par,
//		call_id, cseq_par, &cont_par, NULL, str_auth, NULL))
//		return FALSE;
//	
//
//	return TRUE;
//}



BOOL CSipClient::build_ack_message(CSipPacket &packet, CSipPacketInfo * status_info)
{
	//只处理了invite的ack
	if (NULL == status_info || Invite != status_info->get_cseq().method)
		return FALSE;

	STATUS_CODE stu_code = status_info->get_status_code();
	if (stu_code != 200 && stu_code != 407)
		return FALSE;

	REQUEST_LINE request_par;
	HEADER_CONTACT cont;

	request_par.method = Ack;
	if (status_info->get_contact(cont))
	{
		request_par.request_uri = cont.contact_uri;
		request_par.rinstance = cont.rinstance;

	}
	else
	{
		request_par.request_uri.host = m_sev_addr;

	}

	CPtrViaArray viaArr;
	HEADER_VIA via;
	via.sent_address = m_local_addr;
	via.sent_port = m_l_sip_port;
	via.branch = CSipPacket::build_via_branch();
	if (via.branch.IsEmpty())
		return FALSE;
	viaArr.Add(&via);

	int max_forwards = 70;

	HEADER_FROM for_par;
	for_par = status_info->get_from();

	HEADER_TO to_par;
	to_par = status_info->get_to();

	HEADER_CONTACT contact_par, *con_p = NULL;
	if (stu_code == 200)
	{
		contact_par.contact_uri.user = m_user;
		contact_par.contact_uri.host = m_local_addr;
		contact_par.contact_uri.port = m_l_sip_port;
		con_p = &contact_par;
	}


	CString call_id = status_info->get_call_id();

	HEADER_CSEQ cseq_par;
	cseq_par.method = Ack;
	cseq_par.cseq = m_inv_cseq;

	CString auth, optional;
	if (stu_code == 200)
		auth = m_call_info->request_info.get_auth();

	HEADER_ROUTE route, *p_route = NULL;
	if (stu_code == 200)
	{
		if (!status_info->get_route(route))
			return FALSE;
		p_route = &route;
	}

	if (!packet.build_ack_request(request_par, viaArr, max_forwards, p_route, con_p, to_par, for_par,
		call_id, cseq_par, auth, optional))
		return FALSE;

	return TRUE;
}

BOOL call_info::init(const CSDP &lsdp, const CString &localAddr, WORD audioPort, WORD videoPort)
{
	BOOL initOk = FALSE;
	CString peerAddr;
	WORD peerPort = 0;

	//初始化socket
	if (!udp_a.Create(audioPort, SOCK_DGRAM))
		return initOk;
	if (!udp_v.Create(videoPort, SOCK_DGRAM))
		return initOk;

	//设置本地sdp
	localSdp = lsdp;
	localSdp.m_strAddress = localAddr;
	localSdp.m_strAudioIP = localAddr;
	localSdp.m_strVideoIP = localAddr;

	if (!udp_a.GetSockName(peerAddr, peerPort))
		return initOk;
	localSdp.m_usAudioPort = peerPort;
	if (!udp_v.GetSockName(peerAddr, peerPort))
		return initOk;
	localSdp.m_usVideoPort = peerPort;

	sta = INVITE_START;

	initOk = TRUE;


	return initOk;
}


BOOL call_info::start_media_transport(CRtpPacketCache *sendCache)
{

	if (sendCache == NULL)
		return FALSE;

	local_cache = sendCache;


	//创建线程
	if (NULL == send_handle)
	{

		send_handle = ::CreateThread(NULL, 0, send_media_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == send_handle)
			return FALSE;
	}

	//接收媒体
	//初始化recv cache
	if (sdp.m_bAudioMedia && localSdp.m_bAudioMedia && NULL == recv_audio_handle)
	{
		recv_audio_handle = ::CreateThread(NULL, 0, recv_audio_media_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == recv_audio_handle)
			return FALSE;
	}

	if (sdp.m_bVideoMedia && localSdp.m_bAudioMedia && NULL == recv_video_handle)
	{
		recv_video_handle = ::CreateThread(NULL, 0, recv_video_media_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == recv_video_handle)
			return FALSE;
	}


	::ResumeThread(send_handle);
	::ResumeThread(recv_audio_handle);
	::ResumeThread(recv_video_handle);


	return TRUE;
}


//BOOL call_info::stop_media_transport()
//{
//
//	sta = INVITE_DISCONNECTED;
//
//
//	return 0;
//}

BOOL call_info::close_call_info()
{


	if (NULL != send_handle)
	{
		if (WAIT_OBJECT_0 != ::WaitForSingleObject(send_handle, 10000))
		{
			::WriteLog(_T("PowerClient"), LogType_Warning, __LINE__, _T("Terminate Receive thread!"));
			::TerminateThread(send_handle, 1);
		}
		::CloseHandle(send_handle);
		send_handle = NULL;
	}

	if (NULL != recv_audio_handle)
	{
		if (WAIT_OBJECT_0 != ::WaitForSingleObject(recv_audio_handle, 10000))
		{
			::WriteLog(_T("PowerClient"), LogType_Warning, __LINE__, _T("Terminate Receive thread!"));
			::TerminateThread(recv_audio_handle, 1);
		}
		::CloseHandle(recv_audio_handle);
		recv_audio_handle = NULL;
	}

	if (NULL != recv_video_handle)
	{
		if (WAIT_OBJECT_0 != ::WaitForSingleObject(recv_video_handle, 10000))
		{
			::WriteLog(_T("PowerClient"), LogType_Warning, __LINE__, _T("Terminate Receive thread!"));
			::TerminateThread(recv_video_handle, 1);
		}
		::CloseHandle(recv_video_handle);
		recv_video_handle = NULL;
	}

	sta = INVITE_DISCONNECTED;
	local_cache = NULL;


	return TRUE;


}

DWORD call_info::send_media_thread(LPVOID lpParam)
{
	CALL_INFO *pObject = (CALL_INFO*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->do_send_media();
}

DWORD call_info::recv_audio_media_thread(LPVOID lpParam)
{
	CALL_INFO *pObject = (CALL_INFO*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->do_recv_audio_media();
}

DWORD call_info::recv_video_media_thread(LPVOID lpParam)
{
	CALL_INFO *pObject = (CALL_INFO*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->do_recv_video_media();
}

DWORD call_info::do_send_media()
{
	//CRtpPacketCache *sendCache = (CRtpPacketCache*)lpParam;

	CRtpPacketPtr rtp_pack;

	CString audio_addr, video_addr;
	WORD audio_port = 0, video_port = 0;
	BOOL a_media = FALSE, v_media = FALSE;

	if (sdp.m_bAudioMedia && localSdp.m_bAudioMedia)
	{
		a_media = TRUE;
		audio_port = sdp.m_usAudioPort;
		if (sdp.m_strAudioIP.IsEmpty())
			audio_addr = sdp.m_strAddress;
		else
			audio_addr = sdp.m_strAudioIP;
	}

	if (sdp.m_bVideoMedia && localSdp.m_bVideoMedia)
	{
		v_media = TRUE;
		video_port = sdp.m_usVideoPort;
		if (sdp.m_strVideoIP.IsEmpty())
			video_addr = sdp.m_strAddress;
		else
			video_addr = sdp.m_strVideoIP;
	}



	while (1)
	{
		if (local_cache != NULL)
			rtp_pack = local_cache->GetNextPacket();

		if (NULL != rtp_pack)
		{
			if (rtp_pack->enType == audio && a_media)
			{
				udp_a.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
					audio_port, audio_addr);
			}
			else if (rtp_pack->enType == video && v_media)
			{
				udp_v.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
					video_port, video_addr);
			}
		}
		else
		{
			Sleep(10);
		}
	}


	return 0;
}

DWORD call_info::do_recv_video_media()
{
	int ret = 0;
	CString recv_addr, peer_addr;
	WORD recv_port, peer_port = 0;
	CRtpPacketPtr rtp_pack = NULL;
	unsigned char *buf = new unsigned char[4096]();
	if (buf == NULL)
		return 1;

	recv_addr = sdp.m_strVideoIP;
	recv_port = sdp.m_usVideoPort;


	while (1)
	{
		ret = udp_v.ReceiveFrom(buf, 4096, peer_addr, peer_port);
		if (ret > 0 && recv_port == peer_port
			&& recv_addr.Compare(peer_addr) == 0)
		{
			rtp_pack = new RTP_PACKET();
			memcpy_s(rtp_pack->szData, RTP_PACKET_SIZE, buf, ret);
			rtp_pack->usPackLen = ret;
			rtp_pack->enType = video;

			rtp_cache.AddPacket(rtp_pack);
		}
	}

	delete[] buf;
	buf = NULL;


	return 0;
}

DWORD call_info::do_recv_audio_media()
{

	int ret = 0;
	CString recv_addr, peer_addr;
	WORD recv_port, peer_port = 0;
	CRtpPacketPtr rtp_pack = NULL;
	unsigned char *buf = new unsigned char[4096]();
	if (buf == NULL)
		return 1;

	recv_addr = sdp.m_strAudioIP;
	recv_port = sdp.m_usAudioPort;


	while (1)
	{
		ret = udp_a.ReceiveFrom(buf, 4096, peer_addr, peer_port);
		if (ret > 0 && recv_port == peer_port
			&& recv_addr.Compare(peer_addr) == 0)
		{
			rtp_pack = new RTP_PACKET();
			memcpy_s(rtp_pack->szData, RTP_PACKET_SIZE, buf, ret);
			rtp_pack->usPackLen = ret;
			rtp_pack->enType = audio;

			rtp_cache.AddPacket(rtp_pack);
		}

	}
	delete[] buf;
	buf = NULL;


	return 0;
}

//初始化call info
//BOOL CSipClient::init_call_info(WORD audioPort, WORD videoPort)
//{
//	BOOL initOk = FALSE;
//
//
//	if (NULL == m_call_info)
//	{
//		m_call_info = new CALL_INFO();
//		if (NULL == m_call_info)
//			goto end;
//
//		if (NULL == m_call_info->localSdp)
//		{
//			m_call_info->localSdp = new CSDP();
//			if (NULL == m_call_info->localSdp)
//				goto end;
//		}
//
//		if (NULL == m_call_info->sdp)
//		{
//			m_call_info->sdp = new CSDP();
//			if (NULL == m_call_info->sdp)
//				goto end;
//		}
//
//		if (NULL == m_call_info->request_info)
//		{
//			m_call_info->request_info = new CSipPacketInfo();
//			if (NULL == m_call_info->request_info)
//				goto end;
//		}
//
//		if (NULL == m_call_info->rtp_cache)
//		{
//			m_call_info->rtp_cache = new CRtpPacketCache();
//			if (NULL == m_call_info->rtp_cache)
//				goto end;
//		}
//		
//	}
//
//	//初始化socket
//	if(!m_call_info->udp_a.Create(audioPort, SOCK_DGRAM))
//		goto end;
//	if (!m_call_info->udp_v.Create(videoPort, SOCK_DGRAM))
//		goto end;
//
//	//设置本地sdp
//	*(m_call_info->localSdp) = *(m_sdp);
//
//	m_call_info->localSdp->m_strAddress = m_local_addr;
//
//
//	initOk = TRUE;
//
//end:
//	if (!initOk)
//		free_call_info();
//
//
//	return initOk;
//}

//void CSipClient::free_call_info()
//{
//	if (NULL != m_call_info)
//	{
//		if (NULL != m_call_info->localSdp)
//		{
//			delete m_call_info->localSdp;
//			m_call_info->localSdp = NULL;
//		}
//
//		if (NULL != m_call_info->sdp)
//		{
//			delete m_call_info->sdp;
//			m_call_info->sdp = NULL;
//		}
//
//		if (NULL != m_call_info->request_info)
//		{
//			delete m_call_info->request_info;
//			m_call_info->request_info = NULL;
//		}
//
//		if (NULL != m_call_info->rtp_cache)
//		{
//			delete m_call_info->rtp_cache;
//			m_call_info->rtp_cache = NULL;
//		}
//
//		delete m_call_info;
//		m_call_info = NULL;
//	}
//}

//DWORD CSipClient::recv_audio_media_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_recv_audio_media();
//
//	return 0;
//}
//
//DWORD CSipClient::recv_video_media_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_recv_video_media();
//
//	return 0;
//}


////构造带认证的邀请消息
//BOOL build_auth_invite_packet(CSipPacket &invite_packet, CSipPacketInfo *old_request_info,
//	const CString &auth, int cseq)
//{
//
//	CString call_id, guid_str;
//	//REQUEST_METHOD method;
//	REQUEST_LINE request_par;
//	HEADER_VIA via_par;
//	int max_forwards = 70;
//	HEADER_FROM from_par;
//	HEADER_TO to_par;
//	HEADER_CONTACT con_par;
//	HEADER_CSEQ cseq_par;
//	CSDP sdp;
//
//	//构造inv packet
//	request_par = old_request_info->get_request();
//	via_par = old_request_info->get_via();
//	via_par.branch = CSipPacket::build_via_branch();
//	if (via_par.branch.IsEmpty())
//		return FALSE;
//	from_par = old_request_info->get_from();
//	to_par = old_request_info->get_to();
//	con_par = old_request_info->get_contact();
//	//****/con_par.contact_uri.host = _T("192.168.100.82");
//	call_id = old_request_info->get_call_id();
//	cseq_par.cseq = cseq;
//	cseq_par.method = Invite;
//
//	sdp = old_request_info->get_sdp_info();
//
//	if (!invite_packet.build_request_packet(request_par, via_par, from_par,
//		to_par, call_id, cseq_par, &con_par, NULL, auth, &sdp))
//		return FALSE;
//
//	return TRUE;
//}

//void CSipClient::proc_status_bye_ok(CSipPacketInfo *staInfo)
//{
//	if (staInfo == NULL || m_call_info == NULL || m_call_info->sta!= INVITE_CALLING)
//		return;
//
//	m_call_info->close_call_info();
//
//
//
//
//
//}

//收到invite 407的处理
void CSipClient::proc_invite_proxy_auth(CSipPacketInfo *status_inv)
{

	if (NULL == status_inv)
		return ;
	//构建ack
	CSipPacket ack_request;
	if (!build_ack_message(ack_request, status_inv))
		return ;
	//构建带认证的invite
	if (m_call_info == NULL )
		return;
	CSipPacket invite_request;
	REQUEST_LINE request_par;
	CPtrViaArray via_par;
	int max_forwards = 70;
	HEADER_CONTACT con_par;
	HEADER_TO to_par;
	HEADER_FROM from_par;
	HEADER_CSEQ cseq;
	CString call_id, auth, optional;
	CSDP sdp;

	request_par = m_call_info->request_info.get_request();

	m_call_info->request_info.get_via(via_par);
	via_par.GetAt(0)->branch = CSipPacket::build_via_branch();

	if (!m_call_info->request_info.get_contact(con_par))
		return;
	to_par = m_call_info->request_info.get_to();
	from_par = m_call_info->request_info.get_from();
	cseq = m_call_info->request_info.get_cseq();
	cseq.cseq = m_inv_cseq + 1;
	call_id = m_call_info->request_info.get_call_id();
	auth = build_auth_string(Invite, Proxy_Authentication, status_inv);
	if (auth.IsEmpty())
		return;
	if (!m_call_info->request_info.get_sdp_info(sdp))
		return;
	if (!m_call_info->request_info.get_contact(con_par))
		return ;
	if (!invite_request.build_inviter_request(request_par, via_par, max_forwards,
		 con_par, to_par, from_par, call_id, cseq, sdp,  auth, optional))
		return ;
	//保存call_info
	if (!m_call_info->request_info.from_packet(&invite_request))
		return;

	//发送
	if (!send_packet(&ack_request))
		return ;
	if (!send_packet(&invite_request))
		return ;

	m_inv_cseq++;

}

BOOL CSipClient::compare_packet(const CSipPacketInfo &request, const CSipPacketInfo &status)
{
	CPtrViaArray reqVia, staVia;

	request.get_via(reqVia);
	status.get_via(staVia);

	if (reqVia.GetSize() != staVia.GetSize())
		return FALSE;

	BOOL find_dif = FALSE;

	for (int i = 0; i < reqVia.GetSize(); i++)
	{
		if (reqVia.GetAt(i) != NULL && staVia.GetAt(i) != NULL)
		{
			if (reqVia.GetAt(i)->branch != staVia.GetAt(i)->branch)
			{
				find_dif = TRUE;
				break;

			}
		}
	}



	return !find_dif;
}


void proc_bye_request(CSipPacket *bye_req)
{
	//回复ok消息，停止媒体传输，回收资源
	
	if (NULL == bye_req)
		return;

	CSipPacket status_ok(*bye_req);

	//status_ok.build_status(OK, )


}


//处理来电请求
void CSipClient::proc_invite_request(CSipPacketInfo *inv_request)
{
	if (inv_request == NULL|| m_client_status != wait)
		return ;

	//检查sdp
	CSDP sdp;
	if (!inv_request->get_sdp_info(sdp))
		return;

	int i = 0;
	if (!sdp.m_bVideoMedia)
		return;
	i = sdp.m_strVideoRtpMap.Find(_T("H264"));
	if (i < 0)
		return;

	//初始化call info
	if (m_call_info == NULL)
	{
		m_call_info = new CALL_INFO();
		if (m_call_info == NULL)
			return;
		if (!m_call_info->init(m_sdp, m_local_addr))
			return ;
	}



}

//解析回应ok消息
void CSipClient::proc_intite_status_ok(CSipPacketInfo *inv_status)
{
	//协商sdp， 回应ack，开启媒体传输
	if (inv_status == NULL || m_call_info == NULL || m_call_info->sta < INVITE_SEND)
		return;

	CSDP sdp;
	int i = 0;

	if (!inv_status->get_sdp_info(sdp))
		return;
	if (sdp.m_bVideoMedia)
	{
		i = sdp.m_strVideoRtpMap.Find(_T("H264"));
		if (i < 0)
			return;
	}
	m_call_info->sdp = sdp;
	m_call_info->sta = INVITE_SDP_OK;

	//构建ack
	CSipPacket ack_packet;
	CString auth;
	auth = m_call_info->request_info.get_auth();
	if (!build_ack_message(ack_packet, inv_status))
		return;
	if (!send_packet(&ack_packet))
		return;
	m_call_info->request_info = *inv_status;
	m_call_info->sta = INVITE_ACK_OK;

	//保存对方信息
	HEADER_CONTACT contact;
	m_call_info->id = inv_status->get_call_id();
	if (!inv_status->get_contact(contact))
		return;
	m_call_info->contact_uri = contact.contact_uri;
	//开启媒体传输
	if (!m_call_info->start_media_transport(m_send_cache))
		return;

	m_call_info->sta = INVITE_CALLING;
	m_client_status = calling;


	return;


}


//**************************************************
//*功能：处理接收的sip消息主要线程
//*参数：
//*返回：
//**************************************************
void CSipClient::proc_sip_mess(CSipPacket *recv_pack)
{
	if (recv_pack == NULL)
		return;

	CSipPacketInfo recv_packet_info;
	if (!recv_packet_info.from_packet(recv_pack))
		return;


	if (recv_packet_info.get_type() == sip_status)//sip响应消息
	{
		if (NULL == m_call_info)
			return;

		//响应消息，找到对应的请求消息
		if (!compare_packet(m_call_info->request_info, recv_packet_info))
			return;


		switch (m_call_info->request_info.get_request().method)
		{
		case Register:
			//switch (recv_packet_info.get_status_code())
			//{
			//case Trying:
			//	break;
			//case Ringing:
			//	break;
			//case OK:
			//	if (m_client_status == init_ok)
			//		m_client_status = wait;
			//	break;
			//case Unauthorized:  //注册认证
			//{
			//	if (m_client_status != init_ok || m_auth_count > AUTH_COUNT)
			//		break;
			//	BOOL reg_auth_ok = FALSE;
			//	//计算认证字符串
			//	CString str_auth = build_auth_string(Register, Unauthorized, &recv_packet_info);
			//	if (str_auth.IsEmpty())
			//		break;
			//	//构建新的注册包
			//	CSipPacket auth_packet;
			//	if (!build_register_auth_packet(auth_packet, req_info, str_auth, m_reg_cseq))
			//		break;
			//	//构建新的packet info
			//	CSipPacketInfo *auth_info = new CSipPacketInfo();
			//	if (!auth_info->from_packet(&auth_packet))
			//		goto reg_auth_end;
			//	m_request_info_arr.Add(auth_info);
			//	//发送
			//	if (!send_packet(&auth_packet))
			//		goto reg_auth_end;
			//	m_reg_cseq++;
			//	reg_auth_ok = TRUE;
			//reg_auth_end:
			//	if (!reg_auth_ok)
			//	{
			//		if (auth_info)
			//		{
			//			delete auth_info;
			//			auth_info = NULL;
			//		}
			//	}
			//}
			//	break;
			//case Proxy_Authentication:
			//	break;
			//default:
			//	break;
			//}
			break;
		case Invite:
			switch (recv_packet_info.get_status_code())
			{
			case Trying:
				break;
			case Ringing:
				break;
			case OK:
			{
				proc_intite_status_ok(&recv_packet_info);

				////解析sdp
				//if (m_client_status != inviteing)
				//	break;
				//if (NULL == m_call_info->sdp)
				//	m_call_info->sdp = new CSDP();
				//if (!recv_packet_info.get_sdp_info(*(m_call_info->sdp)))
				//	break;
				//if (m_call_info->sdp->m_bVideoMedia)
				//{
				//	int i = m_call_info->sdp->m_strVideoRtpMap.Find(_T("H264"));
				//	if (i < 0)
				//		break;
				//}
				//m_call_info->sta = INVITE_SDP_OK;
				////构建ack 
				//CSipPacket ack_packet;
				//CString auth;
				//auth = m_call_info->request_info.get_auth();
				//if (!build_ack_message(ack_packet, &recv_packet_info))
				//	break;
				//if (!send_packet(&ack_packet))
				//	break;
				//m_ack_cseq++;
				//m_call_info->sta = INVITE_ACK_OK;
				//*(m_call_info->request_info) = recv_packet_info;
				////开始媒体传输
				////发送媒体数据
				//m_call_info->send_handle = ::CreateThread(NULL, 0, send_media_thread, this, CREATE_SUSPENDED, NULL);
				//ASSERT(NULL != m_call_info->send_handle);
				//if (NULL == m_call_info->send_handle)
				//	break;
				////接收媒体
				////初始化recv cache
				//if (NULL == m_call_info->rtp_cache)
				//{
				//	m_call_info->rtp_cache = new CRtpPacketCache();
				//	if (NULL == m_call_info->rtp_cache)
				//		break;
				//}
				//if (m_call_info->sdp->m_bAudioMedia)
				//{
				//	m_call_info->recv_audio_handle = ::CreateThread(NULL, 0,
				//		recv_audio_media_thread, this, CREATE_SUSPENDED, NULL);
				//	ASSERT(NULL != m_call_info->recv_audio_handle);
				//	if (NULL == m_call_info->recv_audio_handle)
				//		break;
				//}
				//if (m_call_info->sdp->m_bVideoMedia)
				//{
				//	m_call_info->recv_video_handle = ::CreateThread(NULL, 0,
				//		recv_video_media_thread, this, CREATE_SUSPENDED, NULL);
				//	ASSERT(NULL != m_call_info->recv_video_handle);
				//	if (NULL == m_call_info->recv_video_handle)
				//		break;
				//}
				////保存信息
				//HEADER_CONTACT sta_con;
				//recv_packet_info.get_contact(sta_con);
				//m_call_info->contact_uri = sta_con.contact_uri;
				//::ResumeThread(m_call_info->send_handle);
				//::ResumeThread(m_call_info->recv_audio_handle);
				//::ResumeThread(m_call_info->recv_video_handle);
				//m_call_info->sta = INVITE_CALLING;
				//m_client_status = calling;

				break;
			}
			case Unauthorized:
				break;
			case Proxy_Authentication:
			{
				proc_invite_proxy_auth(&recv_packet_info);

				//if (m_call_info == NULL || m_call_info->localSdp == NULL
				//	|| NULL == m_call_info->request_info)
				//	break;
				////发送ack
				//CSipPacket ack_packet, auth_invite_packet;
				//CSipPacketInfo packet_info;
				//CString auth, optional;
				//if (!build_ack_message(ack_packet,  &recv_packet_info))
				//	break;
				//if (send_packet(&ack_packet))
				//	m_ack_cseq++;
				////构建 认证邀请消息
				//auth = build_auth_string(Invite, Proxy_Authentication, &recv_packet_info);
				//if (auth.IsEmpty())
				//	break;
				////构造packet
				////if (!build_invite_message(auth_invite_packet, m_call_info->call_name,
				////	*(m_call_info->localSdp), auth, optional))
				////	break;
				//if (!packet_info.from_packet(&auth_invite_packet))
				//	break;
				//*(m_call_info->request_info) = packet_info;
				//if (!send_packet(&auth_invite_packet))
				//	break;
				//m_inv_cseq++;
			}
				break;
			default:
				break;
			}
			break;
		case Ack:
			break;
		case Bye:
			switch (recv_packet_info.get_status_code())
			{
			case Trying:
				break;
			case Ringing:
				break;
			case OK:

				if (NULL != m_call_info && m_call_info->sta == INVITE_CALLING)
					m_call_info->close_call_info();
				if (m_call_info->sta == INVITE_DISCONNECTED)
					m_client_status = wait;


				//proc_status_bye_ok(&recv_packet_info);
				//结束通话
				//if (NULL == m_call_info && m_call_info->sta != INVITE_CALLING)
				//	break;
				//结束线程
				//m_call_info->sta = INVITE_DISCONNECTED;
				//回收资源

				break;
			case Unauthorized:
				break;
			case Proxy_Authentication:
				break;
			default:
				break;
			}
			break;
		}

	}
	else if (recv_packet_info.get_type() == sip_request)
	{
		if (recv_packet_info.get_request().method == Invite)
		{
			//收到通话邀请
			//proc_invite_request();
			if (m_incoming_call != NULL)
				m_incoming_call(&recv_packet_info);


		}
		else if (recv_packet_info.get_request().method == Bye)
		{
			//proc_bye_request(&recv_packet_info);

		}
	}



	//if (find_index >= 0)//找到下标
		//{
		//	send_packet_info = m_send_info_arr[find_index];
		//	//根据请求消息，做相应处理
		//	if (send_packet_info->get_request_method() == Register)//注册请求
		//	{
		//		if (recv_packet_info.get_status_code() == 200)
		//		{
		//			m_client_status = wait;
		//		}
		//		else if (recv_packet_info.get_status_code() == 401)	//需要认证
		//		{
		//			CString auth_string, via_branch;
		//			if (NULL == send_packet_info)
		//				return ;
		//			if (m_auth_count < AUTH_NUMBER && build_auth_string(auth_string, recv_pack))
		//			{
		//				//构建和发送认证注册包
		//				CSipPacket *pack = recv_pack->clone_packet();
		//				CSipPacketInfo *resp_packet_info = new  CSipPacketInfo();
		//				if (pack && pack->modify_via_branch(via_branch))
		//				{
		//					pack->add_entry(auth_string);
		//					send_packet(pack);
		//					if (!send_packet_info->from_packet(pack))
		//						return;
		//					m_send_info_arr.Add(send_packet_info);
		//					m_auth_count++;
		//				}
		//				if (pack)
		//					delete pack;
		//			}
		//		}
		//		remove_request = TRUE;
		//	}
		//	else if (send_packet_info->get_request_method() == Invite)//邀请请求
		//	{
		//		if (recv_packet_info.get_status_code() == 200)
		//		{
		//			if (m_client_status == inviteing && recv_packet_info.get_call_id()== m_call_id)
		//			{
		//				if (invite_ok_process(&recv_packet_info))
		//				{
		//					m_client_status = calling;
		//					remove_request = TRUE;
		//				}
		//				else
		//					m_client_status = wait;
		//			}
		//		}
		//		else if (recv_packet_info.get_status_code() == 407)	//需要认证
		//		{
		//		}
		//	}
		//}
		//if (remove_request)
		//{
		//	if (NULL != m_send_info_arr[find_index])
		//	{
		//		delete m_send_info_arr[find_index];
		//		m_send_info_arr.RemoveAt(find_index);
		//	}
		//}
		//m_send_lock.Unlock();
	//if (recv_packet_info.m_type == sip_request)
	//{
	//	if (SipInvite == recv_packet_info.m_method)//收到来电
	//	{
	//		//保存sdp 发送ok
	//		if (register_ok == m_client_status)
	//		{
	//			m_call_stu = INVITE_RECV;
	//			if (NULL != m_incoming_call)
	//				m_incoming_call(&recv_packet_info);
	//		}
	//	}
	//	else if (SipAck == recv_packet_info.m_method)
	//	{
	//		//发送rtp
	//		if (m_call_id == recv_packet_info.m_call_id &&
	//			m_call_stu == INVITE_SDP_OK)
	//		{
	//			m_call_stu = INVITE_ACK_OK;
	//		}
	//	}
	//}
	//else if(recv_packet_info.m_type == sip_status)//sip响应消息
	//{
	//	//HEADER_VIA via_par, send_via_par;
	//	//if (!recv_packet_info.get_via(via_par, 0))
	//	//	return;
	//	//int i = 0;
	//	//for (i = 0; i < m_send_arr.GetSize(); i++)
	//	//{
	//	//	send_pack = m_send_arr.GetAt(i);
	//	//	if (NULL == send_pack)
	//	//		continue;
	//	//	if (!send_packet_info.from_packet(send_pack))
	//	//		continue;
	//	//	if (send_packet_info.get_via(send_via_par, 0))
	//	//	{
	//	//		if (send_via_par.branch == via_par.branch)
	//	//		{
	//	//			find_request = TRUE;
	//	//			break;
	//	//		}
	//	//	}
	//	//}
	//	//if (find_request)
	//	//{
	//	//	STATUS_CODE status_code = recv_packet_info.get_status_code();
	//	//	REQUEST_METHOD method = send_packet_info.get_request_para().method;
	//	//	if (method  == SipRegister)
	//	//	{
	//	//		if (status_code == 200)
	//	//		{
	//	//			if (m_client_status == init_ok)
	//	//			{
	//	//				HEADER_CONTACT contact_par;
	//	//				if (send_packet_info.get_contact(contact_par, 0))
	//	//					m_contact_user = contact_par.contact_uri.user;
	//	//				m_client_status = register_ok;
	//	//				remove_request = TRUE;
	//	//			}
	//	//		}
	//	//		else if (status_code == 401)
	//	//		{
	//	//			m_auth_count++;
	//	//			if (m_auth_count <= 3)
	//	//			{
	//	//				CSipPacket pack;
	//	//				CString realm, nonce, uri, response;
	//	//				if (!get_nonce_realm(recv_pack, realm, nonce))
	//	//					return;
	//	//				uri.Format(_T("sip:%s"), m_sev_addr);
	//	//				if (!builf_auth_response(response, m_user, m_password, realm,
	//	//					_T("REGISTER"), uri, nonce))
	//	//					return ;
	//	//				if (!pack.build_REG_packet())
	//	//					return;
	//	//				if (!send_packet(&pack))
	//	//					return;
	//	//				
	//	//			}
	//	//		}
	//	//	}
	//	//	else if (method == SipInvite)
	//	//	{
	//	//		if (status_code == 200)
	//	//		{
	//	//			if (m_client_status == inviteing &&
	//	//				recv_packet_info.get_call_id() == m_call_id)
	//	//			{
	//	//				if (invite_ok_process(&recv_packet_info))
	//	//				{
	//	//					m_client_status = calling;
	//	//					remove_request = TRUE;
	//	//				}
	//	//				else
	//	//					m_client_status = register_ok;
	//	//				
	//	//			}
	//	//		}
	//	//	}
	//	//	if (remove_request)
	//	//	{
	//	//		if (send_pack != NULL)
	//	//		{
	//	//			delete send_pack;
	//	//			send_pack = NULL;
	//	//		}
	//	//	}
	//	//}
	//	//m_send_arr.RemoveAt(i);
	//	//m_send_lock.Unlock();
	//}

	return;
}




BOOL CSipClient::build_register_message(CSipPacket &packet, const CString & auth, const CString &optional)
{
	CString call_id;
	REQUEST_LINE request_par;
	HEADER_VIA via_par;
	HEADER_FROM from_par;
	HEADER_TO to_par;
	HEADER_CONTACT con_par;
	HEADER_CSEQ cseq_par;

	//request
	request_par.method = Register;
	request_par.request_uri.host = m_sev_addr;

	//via
	CPtrViaArray viaArr;
	via_par.sent_address = m_local_addr;
	via_par.sent_port = m_l_sip_port;
	via_par.branch = CSipPacket::build_via_branch();
	if (via_par.branch.IsEmpty())
		return FALSE;
	viaArr.Add(&via_par);

	int max_forwards = 70;

	//contact
	con_par.contact_uri.user = m_user;
	con_par.contact_uri.host = m_local_addr;
	con_par.contact_uri.port = m_l_sip_port;
	con_par.rinstance = CSipPacket::NewGUIDString();
	if (con_par.rinstance.IsEmpty())
		return FALSE;
	//to
	to_par.display_info = m_user;
	to_par.to_user = m_user;
	to_par.to_host = m_sev_addr;
	//from
	from_par.display_user = m_user;
	from_par.user = m_user;
	from_par.host = m_sev_addr;
	from_par.tag = CSipPacket::NewGUIDString();
	if (from_par.tag.IsEmpty())
		return FALSE;
	//call id
	call_id = CSipPacket::NewGUIDString();
	if (call_id.IsEmpty())
		return FALSE;
	//cseq
	cseq_par.method = Register;
	cseq_par.cseq = m_reg_cseq + 1;



	if (!packet.build_register_request(request_par, viaArr, max_forwards, con_par,
		to_par, from_par, call_id, cseq_par, auth, optional))
		return FALSE;


	return TRUE;
}

BOOL CSipClient::build_invite_message(CSipPacket & packet, const CString &call_name,
	const CSDP &sdp, const CString & auth, const CString & optional)
{
	CString call_id;
	REQUEST_LINE request_par;
	HEADER_VIA via_par;
	HEADER_FROM from_par;
	HEADER_TO to_par;
	HEADER_CONTACT con_par;
	HEADER_CSEQ cseq_par;

	//request
	request_par.method = Invite;
	request_par.request_uri.user = call_name;
	request_par.request_uri.host = m_sev_addr;

	CPtrViaArray viaArr;
	via_par.sent_address = m_local_addr;
	via_par.sent_port = m_l_sip_port;
	via_par.branch = CSipPacket::build_via_branch();
	if (via_par.branch.IsEmpty())
		return FALSE;
	viaArr.Add(&via_par);

	int max_forwards = 70;

	con_par.contact_uri.user = m_user;
	con_par.contact_uri.host = m_local_addr;
	con_par.contact_uri.port = m_l_sip_port;

	from_par.display_user = m_user;
	from_par.user = m_user;
	from_par.host = m_sev_addr;
	from_par.tag = CSipPacket::NewGUIDString();
	if (from_par.tag.IsEmpty())
		return FALSE;

	to_par.display_info = call_name;
	to_par.to_user = call_name;
	to_par.to_host = m_sev_addr;



	call_id = CSipPacket::NewGUIDString();
	if (call_id.IsEmpty())
		return FALSE;

	cseq_par.cseq = m_inv_cseq + 1;
	cseq_par.method = Invite;



	if (!packet.build_inviter_request(request_par, viaArr, max_forwards, con_par,
		to_par, from_par, call_id, cseq_par, sdp, auth, optional))
		return FALSE;


	return TRUE;
}

BOOL CSipClient::build_bye_message(CSipPacket & packet)
{

	if (NULL == m_call_info )
		return FALSE;



	REQUEST_LINE req_par;
	HEADER_VIA via_par;
	HEADER_FROM from_par;
	HEADER_TO to_par;
	HEADER_CONTACT con_par, req_con;
	HEADER_CSEQ cseq_par;
	HEADER_ROUTE route_par;
	CString str_auth, call_id, optional;

	if (!m_call_info->request_info.get_contact(req_con))
		return FALSE;

	req_par.method = Bye;
	req_par.request_uri = req_con.contact_uri;
	req_par.rinstance = req_con.rinstance;

	CPtrViaArray viaArr;
	via_par.sent_address = m_local_addr;
	via_par.sent_port = m_l_sip_port;
	via_par.branch = CSipPacket::build_via_branch();
	if (via_par.branch.IsEmpty())
		return FALSE;
	viaArr.Add(&via_par);

	int max_forwards = 70;

	if (!m_call_info->request_info.get_route(route_par))
		return FALSE;

	con_par.contact_uri.host = m_local_addr;
	con_par.contact_uri.port = m_l_sip_port;
	con_par.contact_uri.user = m_user;

	to_par = m_call_info->request_info.get_to();
	from_par = m_call_info->request_info.get_from();

	cseq_par.cseq = m_inv_cseq + 1;
	cseq_par.method = Bye;

	call_id = m_call_info->id;

	str_auth = m_call_info->request_info.get_auth();

	if (!packet.build_bye_request(req_par, viaArr, max_forwards, &route_par, con_par, to_par,
		from_par, call_id, cseq_par, str_auth, optional))
		return FALSE;


	return TRUE;
}

//向服务器发送sip消息
BOOL CSipClient::send_packet(CSipPacket *pack)
{
	if (pack == NULL)
		return FALSE;

	int ret = 0, flag = 0;
	BYTE buf[4096] = { 0 };

	int len = pack->get_data(buf, 4096);
	if (len < 0)
		return FALSE;
	//BYTE *p = buf;

	while (len)
	{
		ret = m_sock.SendTo(buf + flag, len, m_sev_port, m_sev_addr);
		if (ret < 0)
			return FALSE;
		flag += ret;
		len -= ret;
	}


	/*if (strData.IsEmpty())
		return FALSE;

	int flag = 0, ret = 0, data_len = 0;
	BYTE * pbData = NULL;

	pbData = new BYTE [data_len];
	if (NULL == pbData)
		return FALSE;
	data_len = strData.GetLength();
	memcpy(pbData, strData.GetBuffer(data_len), data_len);


	while (data_len)
	{
		ret = m_udpSipSock.SendTo(pbData + flag, data_len, m_usServerPort, m_strSipServerAddr);
		if (ret < 0)
			return FALSE;
		flag += ret;
		data_len -= ret;
	}*/


	return TRUE;

}

//获取 nonce realm
//BOOL get_nonce_realm(CSipPacket *pPacket, CString &strNonce, CString &realm)
//{
//	if (NULL == pPacket)
//		return FALSE;
//
//	int i = 0, j = 0;
//	CString str_data;
//	BYTE buf[4096] = { 0 };
//
//	i = pPacket->get_data(buf, 4096);
//	if (i < 0)
//		return FALSE;
//	str_data = buf;
//
//	i = str_data.Find(_T("realm="));
//	if (i < 0)
//		return FALSE;
//	i += strlen("realm=\"");
//	j = str_data.Find('\"', i);
//	if (j < 0)
//		return FALSE;
//	realm = str_data.Mid(i, j - i);
//
//	i = str_data.Find(_T("nonce="));
//	if (i < 0)
//		return FALSE;
//	i += strlen("nonce=\"");
//	j = str_data.Find('\"', i);
//	if (j < 0)
//		return FALSE;
//	strNonce = str_data.Mid(i, j - i);
//
//
//
//	return TRUE;
//}


//开启媒体传输
//1创建socket 2打开rtp线程
//BOOL CSipClient::start_rtp_transport()
//{
//	if (NULL == m_sdp && NULL == m_local_sdp)
//		return FALSE;
//
//	CString peer_addr;
//	WORD peer_port;
//
//	if (m_local_sdp->m_bAudioMedia && m_sdp->m_bAudioMedia)
//	{
//		if (NULL == m_sock_a)
//		{
//			m_sock_a = new CNetSocket();
//			if (NULL == m_sock_a)
//				return FALSE;
//		}
//
//		if (!m_sock_a->Create(0, SOCK_DGRAM))
//			return FALSE;
//		if (!m_sock_a->GetSockName(peer_addr, peer_port))
//			return FALSE;
//		m_local_sdp->m_usAudioPort = peer_port;
//		m_local_sdp->m_strAudioIP = m_local_addr;
//	}
//
//	if (m_local_sdp->m_bAudioMedia && m_sdp->m_bAudioMedia)
//	{
//		if (NULL == m_sock_v)
//		{
//			m_sock_v = new CNetSocket();
//			if (NULL == m_sock_v)
//				return FALSE;
//		}
//		if (!m_sock_v->Create(0, SOCK_DGRAM))
//			return FALSE;
//		if (!m_sock_v->GetSockName(peer_addr, peer_port))
//			return FALSE;
//		m_local_sdp->m_usVideoPort = peer_port;
//		m_local_sdp->m_strVideoIP = m_local_addr;
//	}
//
//	::ResumeThread(m_send_rtp_h);
//	::ResumeThread(m_recv_rtp_h);
//
//
//	
//
//	return TRUE;
//}

//BOOL CSipClient::start_rtp_transport()
//{
//	if (NULL == m_sdp && NULL == m_local_sdp)
//		return FALSE;
//
//
//
//
//
//
//	return 0;
//}


//收到invite ok的回应
//1初始化call_info， 2发送ack， 3开启媒体传输
//BOOL CSipClient::invite_ok_process(CSipPacketInfo *pack_info)
//{
//	if (pack_info == NULL)
//		return FALSE;
//
//	//发送ack
//	CSipPacket ack_packet;
//	SIP_URI request_uri;
//	HEADER_VIA via_par; 
//	int max_forward = 70; 
//	HEADER_FROM from_par;
//	HEADER_TO to_par; 
//	HEADER_CSEQ cseq;
//	CString call_id;
//	//CString optional;
//	if (!ack_packet.build_ack_packet(&request_uri, &via_par, max_forward, &from_par,
//		&to_par, &cseq, call_id, NULL))
//		return FALSE;
//
//	if (!send_packet(&ack_packet))
//		return FALSE;
//
//	//创建媒体传输线程
//	m_call_info->send_handle = ::CreateThread(NULL, 0, send_media_thread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_call_info->send_handle);
//	if (NULL == m_call_info->send_handle)
//		return FALSE;
//	//接收媒体
//	m_call_info->recv_handle = ::CreateThread(NULL, 0, recv_media_thread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_call_info->recv_handle);
//	if (NULL == m_call_info->recv_handle)
//		return FALSE;
//
//	::ResumeThread(m_call_info->send_handle);
//	::ResumeThread(m_call_info->recv_handle);
//
//
//
//	return TRUE;
//}


//DWORD CSipClient::recv_media_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_recv_media();
//}

//DWORD CSipClient::do_send_media()
//{
//	if (NULL == m_call_info || NULL == m_sdp )
//		return 1;
//
//	CRtpPacketPtr rtp_pack ;
//
//	while (m_bwork)
//	{
//		if (NULL != m_send_cache)
//			rtp_pack = m_send_cache->GetNextPacket();
//
//		if (rtp_pack)
//		{
//			if (rtp_pack->enType == audio && m_sdp->m_bAudioMedia)
//			{
//				//m_call_info->udp_a.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//				//	m_sdp->m_usAudioPort, m_sdp->m_strAudioIP);
//				m_call_info->udp_a.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//					m_call_info->m_usAudioPort, m_sdp->m_strAudioIP);
//			}
//			else if (rtp_pack->enType == video && m_sdp->m_bVideoMedia)
//			{
//				m_call_info->udp_v.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//						m_sdp->m_usVideoPort, m_sdp->m_strVideoIP);
//			}
//		}
//		else
//		{
//			Sleep(10);
//		}
//	}
//
//	return 0;
//}

//查找packet中是否含有sdp， 如果有返回TRUE，并返回sdp
//BOOL find_sdp(CSipPacket *packet, CSDP &sdp)
//{
//	if (NULL == packet)
//		return FALSE;
//
//	//查找content-type字段
//	CSDP new_sdp;
//	BOOL find_sdp = FALSE;
//	int i = 0, content_len = 0;
//	char value[128] = { 0 }, *sdp_falg = NULL, *sdp_buf = NULL;
//
//	char *data = (char *)packet->get_data();
//	if (NULL == data)
//		return FALSE;
//	char *content = strstr(data, "Content-Type");
//	if (NULL == content)
//		return FALSE;
//	content += strlen("Content-Type: ");
//	while (content[i]!='\r')
//	{
//		value[i] = content[i];
//		i++;
//	}
//	if (strcmp(value, "application/sdp") != 0)
//		return FALSE;
//	//查找sdp位置
//	sdp_falg = strstr(data, "\r\n\r\nv=");
//	if (NULL == sdp_falg)
//		return FALSE;
//
//	//获取content-length长度
//	content = strstr(data, "Content-Length");
//	if (NULL == content)
//		return FALSE;
//	content += strlen("Content-Length:");
//	i = 0;
//	while (content[i]!='\r')
//	{
//		if (content[i] >= 48 && content[i] <= 57)
//			content_len = content_len * 10 + (content[i] - 48);
//		i++;
//	}
//	if (content_len <= 0)
//		return FALSE;
//	//赋值
//	if (!new_sdp.from_buffer(sdp_falg, content_len))
//		return FALSE;
//	sdp = new_sdp;
//
//	return TRUE;
//
//}

//BOOL CSipClient::start_rtp_transport()
//{
//	m_hSendRtpThread = ::CreateThread(NULL, 0, send_rtp_thread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_hSendRtpThread);
//	if (NULL == m_hSendRtpThread)
//	{
//		return FALSE;
//	}
//	m_hRecvRtpThread = ::CreateThread(NULL, 0, recv_rtp_thread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_hRecvRtpThread);
//	if (NULL == m_hRecvRtpThread)
//	{
//		return FALSE;
//	}
//
//	::ResumeThread(m_hRecvRtpThread);
//	::ResumeThread(m_hSendRtpThread);
//}

//BOOL build_md5(const BYTE * pbData, int nDataLen, CString &strMd5Hash)
//{
//	HCRYPTPROV hProv;
//	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
//		return FALSE;
//
//	HCRYPTHASH hHash;
//	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
//	{
//		CryptReleaseContext(hProv, 0);
//		return FALSE;
//	}
//
//	if (!CryptHashData(hHash, pbData, nDataLen, 0))
//	{
//		CryptDestroyHash(hHash);
//		CryptReleaseContext(hProv, 0);
//		return FALSE;
//	}
//
//	DWORD dwSize;
//	DWORD dwLen = sizeof(dwSize);
//	CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)(&dwSize), &dwLen, 0);
//
//	BYTE* pHash = new BYTE[dwSize];
//	dwLen = dwSize;
//	CryptGetHashParam(hHash, HP_HASHVAL, pHash, &dwLen, 0);
//
//	strMd5Hash = _T("");
//	for (DWORD i = 0; i<dwLen; i++)
//		strMd5Hash.AppendFormat(_T("%02X"), pHash[i]);
//	delete[] pHash;
//
//
//	CryptDestroyHash(hHash);
//	CryptReleaseContext(hProv, 0);
//
//	return TRUE;
//}


////包中添加认证
//BOOL CSipClient::add_auth(CSipPacket *packet, const CString &username, const CString &realm,
//	const CString &nonce, const CString &uri, REQUEST_METHOD method)
//{
//	if (NULL == packet)
//		return FALSE;
//
//	CString auth, response, str_method;
//	DIGEST_AUTH_PAR auth_par;
//	switch (method)
//	{
//	case other_method:
//		return FALSE;
//		break;
//	case SipRegister:
//		str_method.Format(_T("REGISTER"));
//		break;
//	case SipInvite:
//		str_method.Format(_T("REGISTER"));
//		break;
//	case SipAck:
//		str_method.Format(_T("REGISTER"));
//		break;
//	case SipBye:
//		str_method.Format(_T("REGISTER"));
//		break;
//	}
//
//
//
//	//计算response
//	if (!builf_auth_response(response, username, m_password, realm, str_method, uri, nonce))
//		return FALSE;
//	auth_par.name = username;
//	auth_par.nonce = nonce;
//	auth_par.realm= realm;
//	auth_par.response = response;
//	auth_par.uri= uri;
//
//
//
//	auth = packet->generate_digest_auth_line(&auth_par);
//	packet->add_entry(auth);
//
//	//修改via
//	if (!packet->build_via_branch(auth))
//		return FALSE;
//
//	if (!packet->modify_via_branch(auth))
//		return FALSE;
//
//
//
//	return TRUE;
//}

//查找发送消息队列中 via_branch 相同的包。返回下标
//int CSipClient::find_send_pack_index(const CString &via_branch)
//{
//	CSipPacketInfo send_pack_info;
//	int index = -1;
//
//	if (via_branch.IsEmpty())
//		return index;
//
//	m_send_lock.Lock();
//	for (int i = 0; i < m_send_packet_arr.GetSize(); i++)
//	{
//		if (send_pack_info.from_packet(m_send_packet_arr[i]))
//		{
//			if (send_pack_info.get_via().branch == via_branch)
//			{
//				index = i;
//				break;
//			}
//		}
//	}
//	m_send_lock.Unlock();
//
//	return index;
//
//}

//CSipPacketInfo* CSipClient::find_send_pack_index(int &index, const CString &via_branch)
//{
//	if (via_branch.IsEmpty())
//		return NULL;
//
//	BOOL find = FALSE;
//	CSipPacketInfo *info = new CSipPacketInfo();
//	if (NULL == info)
//		return info;
//
//	m_send_lock.Lock();
//	for (int i = 0; i < m_send_packet_arr.GetSize(); i++)
//	{
//		if (info->from_packet(m_send_packet_arr[i]))
//		{
//			if (info->get_via().branch == via_branch)
//			{
//				index = i;
//				find = TRUE;
//				break;
//			}
//		}
//	}
//	m_send_lock.Unlock();
//
//	if (!find)
//	{
//		index = -1;
//		if (NULL != info)
//		{
//			delete info;
//			info = NULL;
//		}
//	}
//
//
//	return  info;
//}


//BOOL CSipClient::build_ack_message(CSipPacket & packet, CSipPacketInfo * status_info)
//{
//	if (NULL == status_info)
//		return FALSE;
//
//
//	//REQUEST_METHOD req_method = request_info->get_request_method();
//	STATUS_CODE stu_code = status_info->get_status_code();
//
//
//
//	SIP_URI req_uri;
//	if (stu_code == OK)
//	{
//		req_uri.user = status_info->get_contact().contact_uri.user;
//		req_uri.host = status_info->get_contact().contact_uri.host;
//		req_uri.port = status_info->get_contact().contact_uri.port;
//		req_uri.rinstance = status_info->get_contact().contact_uri.rinstance;
//	}
//	else if (stu_code == Proxy_Authentication)
//	{
//		req_uri.user = status_info->get_to().to_user;
//		req_uri.host = status_info->get_to().to_host;
//	}
//
//
//	HEADER_VIA via_par;
//	via_par.sent_address = status_info->get_via().sent_address;
//	via_par.sent_port = status_info->get_via().sent_port;
//	if (!CSipPacket::build_via_branch(via_par.branch))
//		return FALSE;
//
//	int max_forward = 0;
//
//	HEADER_CONTACT contact_par, *contact = NULL;
//	if (stu_code == OK)
//	{
//		contact_par.contact_uri.user = m_user;
//		contact_par.contact_uri.host = status_info->get_via().received_address;
//
//	}
//
//	HEADER_FROM for_par;
//	for_par = status_info->get_from();
//
//	HEADER_TO to_par;
//	to_par = status_info->get_to();
//
//	HEADER_CSEQ cseq_par;
//	cseq_par.method = Ack;
//	cseq_par.cseq = cseq;
//
//	CString call_id = status_info->get_call_id();
//	CString auth;
//
//
//	if (!packet.build_ack_packet(&req_uri, &via_par, max_forward,
//		&for_par, &to_par, &cseq_par, call_id, NULL, auth))
//		return FALSE;
//
//
//
//	return TRUE;
//
//
//}


//DWORD CSipClient::send_rtp_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_send_rtp();
//}
//
//DWORD CSipClient::send_rtp_audio_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_send_rtp();
//
//
//
//	return 0;
//}
//
//DWORD CSipClient::send_rtp_video_thread(LPVOID lpParam)
//{
//	
//
//
//
//	return 0;
//}
//
//DWORD CSipClient::recv_rtp_audio_thread(LPVOID lpParam)
//{
//	return 0;
//}
//
//DWORD CSipClient::recv_rtp_video_thread(LPVOID lpParam)
//{
//	return 0;
//}
//
//DWORD CSipClient::do_send_audio_rtp()
//{
//	if (NULL == m_send_cache)
//		return 1;
//
//
//	m_send_cache->GetNextPacket()->enType
//	
//
//
//
//
//
//	while ()
//	{
//		if (audio)
//		{
//
//		}
//	}
//
//
//	return 0;
//}
//
//DWORD CSipClient::do_send_video_rtp()
//{
//	return 0;
//}
//
//DWORD CSipClient::do_recv_audio_rtp()
//{
//	return 0;
//}
//
//DWORD CSipClient::do_recv_video_rtp()
//{
//	return 0;
//}
//
//DWORD CSipClient::recv_rtp_thread(LPVOID lpParam)
//{
//	CSipClient *pObject = (CSipClient*)lpParam;
//	ASSERT(NULL != pObject);
//	return pObject->do_recv_rtp();
//}
//
//DWORD CSipClient::do_send_rtp()
//{
//	int ret = 0;
//	CRtpPacketPtr rtp_pack = NULL;
//	CString audio_address, video_address, sdp_address;
//	unsigned short audio_port = 0, video_port = 0;
//	BOOL bAudio, bVideo;
//
//	if (NULL == m_call_info->sdp )
//		return 1;
//
//	bAudio = m_call_info->sdp->get_audio_media();
//	bVideo = m_call_info->sdp->get_video_media();
//	audio_address = m_call_info->sdp->get_audio_address();
//	video_address = m_call_info->sdp->get_video_address();
//	audio_port = m_call_info->sdp->get_audio_port();
//	video_port = m_call_info->sdp->get_video_port();
//	sdp_address = m_call_info->sdp->get_address();
//	if (audio_address.IsEmpty())
//		audio_address = sdp_address;
//	if (video_address.IsEmpty())
//		video_address = sdp_address;
//	
//
//
//	while (m_bwork)
//	{
//		if (NULL != m_send_cache)
//			rtp_pack = m_send_cache->GetNextPacket();
//		if (rtp_pack)
//		{
//			if (rtp_pack->enType == audio && bAudio )
//			{
//				ret = m_call_info->udp_audio.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//					audio_port, audio_address);
//				if (ret < 0)
//					int err = WSAGetLastError();
//
//			}
//			else if (rtp_pack->enType == video && bVideo )
//			{
//				ret = m_call_info->udp_video.SendTo(rtp_pack->szData, rtp_pack->usPackLen,
//					video_port, video_address);
//				if (ret < 0)
//					int err = WSAGetLastError();
//			}
//		}
//		else
//		{
//			Sleep(10);
//		}
//	}
//
//
//
//
//	return 0;
//}
//
//DWORD CSipClient::do_recv_rtp()
//{
//	int ret = 0;
//	CString recv_addr;
//	WORD recv_port;
//	unsigned char *buf= new unsigned char [RTP_BUFFER];
//	CRtpPacketPtr rtp_pack = NULL;
//	CString audio_address, video_address, sdp_address;
//	unsigned short audio_port = 0, video_port = 0;
//	BOOL bAudio, bVideo;
//
//	if (NULL == m_call_info->sdp)
//		return 1;
//	bAudio = m_local_sdp->get_audio_media();
//	bVideo = m_local_sdp->get_video_media();
//	audio_address = m_call_info->sdp->get_audio_address();
//	video_address = m_call_info->sdp->get_video_address();
//	audio_port = m_call_info->sdp->get_audio_port();
//	video_port = m_call_info->sdp->get_video_port();
//	sdp_address = m_call_info->sdp->get_address();
//	if (audio_address.IsEmpty())
//		audio_address = sdp_address;
//	if (video_address.IsEmpty())
//		video_address = sdp_address;
//
//	while (m_bwork)
//	{
//		if (bAudio)
//		{
//			ret = m_call_info->udp_audio.ReceiveFrom(buf, RTP_BUFFER, recv_addr, recv_port);
//			if (ret > 0 && recv_port == audio_port &&
//				recv_addr.Compare(audio_address) == 0)
//			{
//				rtp_pack = new RTP_PACKET;
//				memcpy(rtp_pack->szData, buf, ret);
//				rtp_pack->usPackLen = ret;
//				rtp_pack->enType = audio;
//				if (m_call_info->rtp_cache)
//					m_call_info->rtp_cache->AddPacket(rtp_pack);
//			}
//
//		}
//
//		if (bVideo)
//		{
//			ret = m_call_info->udp_video.ReceiveFrom(buf, RTP_BUFFER, recv_addr, recv_port);
//			if (ret > 0 && recv_port == video_port
//				&& recv_addr.Compare(video_address) == 0)
//			{
//				rtp_pack = new RTP_PACKET;
//				memcpy(rtp_pack->szData, buf, ret);
//				rtp_pack->usPackLen = ret;
//				rtp_pack->enType = video;
//				if (m_call_info->rtp_cache)
//					m_call_info->rtp_cache->AddPacket(rtp_pack);
//			}
//		}
//	}
//
//
//	delete [] buf;
//	buf = NULL;
//
//	//FILE *sdp_file = fopen("sip.sdp","w+");
//	//if (NULL == sdp_file)
//	//	return 0;
//	//CString str_sdp = m_sdp.to_buffer();
//	//USES_CONVERSION;
//	//char * sdp_buf = T2A(str_sdp);
//	//if (NULL == sdp_buf)
//	//	return 0;
//	//int sdp_buf_len = str_sdp.GetLength();
//	//int write_len = fwrite(sdp_buf, sdp_buf_len, 1, sdp_file);
//	//fflush(sdp_file);
//
//	return 0;
//}

//DWORD CSipClient::do_recv_media()
//{
//	if (NULL == m_call_info || NULL == m_sdp)
//		return 1;
//
//	int ret = 0;
//	CString recv_addr;
//	WORD recv_port;
//	unsigned char *buf = new unsigned char[4096]();
//	CRtpPacketPtr rtp_pack = NULL;
//
//
//	if (!m_call_info->udp_a.EnableNonBlocking(TRUE))
//		return 2;
//	if (!m_call_info->udp_v.EnableNonBlocking(TRUE))
//		return 3;
//
//	CString audio_addr, video_addr;
//	WORD audio_port = 0, video_port = 0;
//	if (m_call_info->sdp)
//	{
//		audio_port = m_call_info->sdp->m_usAudioPort;
//		video_port = m_call_info->sdp->m_usVideoPort;
//
//		if (m_call_info->sdp->m_strAudioIP.IsEmpty())
//			audio_addr = m_call_info->sdp->m_strAddress;
//		else
//			audio_addr = m_call_info->sdp->m_strAudioIP;
//
//		if (m_call_info->sdp->m_strVideoIP.IsEmpty())
//			video_addr = m_call_info->sdp->m_strAddress;
//		else
//			video_addr = m_call_info->sdp->m_strVideoIP;
//	}
//
//	while (m_bwork)
//	{
//		/*if (m_sdp->m_bAudioMedia )
//		{
//			ret = m_call_info->udp_a.ReceiveFrom(buf, 4096, recv_addr, recv_port);
//			if (ret > 0 && recv_port == audio_port &&
//				recv_addr.Compare(audio_addr) == 0)
//			{
//				rtp_pack = new RTP_PACKET();
//				if (NULL == rtp_pack)
//					continue;
//				memcpy_s(rtp_pack->szData, 1500, buf, ret);
//				rtp_pack->usPackLen = ret;
//				rtp_pack->enType = audio;
//				if (m_call_info->rtp_cache)
//					m_call_info->rtp_cache->AddPacket(rtp_pack);
//			}
//
//		}*/
//
//		if (m_sdp->m_bVideoMedia)
//		{
//			ret = m_call_info->udp_v.ReceiveFrom(buf, 4096, recv_addr, recv_port);
//			if (ret > 0 && recv_port == video_port
//				&& recv_addr.Compare(video_addr) == 0)
//			{
//				rtp_pack = new RTP_PACKET();
//				memcpy_s(rtp_pack->szData, 1500, buf, ret);
//				rtp_pack->usPackLen = ret;
//				rtp_pack->enType = video;
//				if (m_call_info->rtp_cache)
//					m_call_info->rtp_cache->AddPacket(rtp_pack);
//			}
//		}
//
//
//
//		delete[] buf;
//		buf = NULL;
//
//
//		return 0;
//	}
//}


//**************************************************
//*功能：创建remove packet
//*参数：需要修改的包
//*返回：成功返回新包指针，失败返回NULL
//**************************************************
//CSipPacket* remove_binding(CSipPacket *packet)
//{
//	if (NULL == packet)
//		return NULL;
//
//	CString via_branch;
//	int cseq = 0;
//	BOOL ret = FALSE;
//	CSipPacket *new_packet = packet->clone_packet();
//	if (NULL == new_packet)
//		return NULL;
//
//	//修改 via branch, from tag, cseq++, 添加 expires=0
//	if (!CSipPacket::build_via_branch(via_branch))
//		goto end;
//	if (!new_packet->set_via_branch(via_branch))
//		goto end;
//
//	if (!CSipPacket::NewGUIDString(via_branch))
//		goto end;
//	if (!new_packet->set_from_tag(via_branch))
//		goto end;
//
//	cseq++;
//	if (!new_packet->set_cseq(cseq))
//		goto end;
//
//	via_branch.Format(_T("Expires: 0\r\n"));
//	if (!new_packet->add_entry(via_branch))
//		goto end;
//	ret = TRUE;
//
//end:
//	if (!ret)
//	{
//		if (NULL != new_packet)
//		{
//			delete new_packet;
//			new_packet = NULL;
//		}
//	}
//
//
//	return new_packet;
//}

//计算response 构建认证字符串
//BOOL CSipClient::build_auth_string(CString &auth_string,  CSipPacket * packet)
//{
//
//	//计算认证回应
//	DIGEST_AUTH_PAR auth_par;
//	CString realm, nonce, response;
//	REQUEST_METHOD method;
//	SIP_URI uri;
//
//
//	if (!get_nonce_realm(packet,nonce, realm))
//		return FALSE;
//	method = Register;
//	uri.host = m_sev_addr;
//	if (!builf_auth_response(response, m_user, m_password, realm, nonce, method, uri))
//		return FALSE;
//auth_par.name = m_user;
//auth_par.nonce = nonce;
//auth_par.realm = realm;
//auth_par.uri.Format(_T("sip:%s"), m_sev_addr);
//auth_par.response = response;
//auth_string = CSipPacket::generate_digest_auth_line(&auth_par);
//return TRUE;

//构建注册认证包
//CSipPacket auth_packet;
//SIP_URI  request_uri;
//HEADER_VIA  via_par;
//int max_forward;
//HEADER_FROM  from_par;
//HEADER_TO  to_par;
//HEADER_CSEQ  cseq;
//CString  call_id;
//CString  optional;
////auth_packet = packet->
//request_uri = packet_info->get_request_uri();
//via_par = packet_info->get_via();
//if (!auth_packet.build_via_branch(via_par.branch))
//	return FALSE;
//max_forward = packet_info->get_max_forwards;
//from_par = packet_info->get_from();
//to_par = packet_info->get_to();
//cseq = packet_info->get_cseq();
//call_id = packet_info->get_call_id();
//DIGEST_AUTH_PAR auth_par;
//auth_par.name = m_user;
//auth_par.nonce = 
//optional = auth_packet.generate_digest_auth_line()
//auth_packet.build_register_packet(&request_uri, &via_par, max_forward,  &from_par,&to_par, 
//	&cseq, call_id, auth)

//}

//CSipPacket* build_new_packet(CSipPacketInfo *packet_info)
//{
//
//	if (NULL == packet_info)
//		return NULL;
//	CSipPacket *packet = new CSipPacket();
//	if (NULL == packet)
//		return NULL;
//
//
//
//	if (packet_info->get_type() == sip_request)
//	{
//		switch (packet_info->get_request_method())
//		{
//		case Register:
//
//			break;
//		case Invite:
//			break;
//		case Ack:
//			break;
//		}
//	}
//	else if (packet_info->get_type() == sip_status)
//	{
//
//	}
//
//
//
//
//
//}

//构建 inv ok ack消息
//BOOL build_invite_ack_message(CSipPacket &packet, CSipPacketInfo *status_info, int cseq, const CString &auth_string)
//{
//	if (NULL == status_info)
//		return FALSE;
//
//
//
//
//	SIP_URI req_uri;
//	HEADER_VIA via_par;
//	HEADER_FROM for_par;
//	HEADER_TO to_par;
//	HEADER_CSEQ cseq_par;
//	HEADER_CONTACT con_par, *p_con = NULL;
//
//	CString call_id, auth_str, string_t;
//	int max_forward = 70;
//
//
//	req_uri = status_info->get_contact().contact_uri;
//	req_uri.rinstance = status_info->get_contact().rinstance;
//
//	via_par.sent_address = status_info->get_via().sent_address;
//	via_par.sent_port = status_info->get_via().sent_port;
//	if (!CSipPacket::build_via_branch(via_par.branch))
//		return FALSE;
//
//	con_par.contact_uri.user = status_info->get_from().user;
//	con_par.contact_uri.host = status_info->get_via().received_address;
//	con_par.contact_uri.port = status_info->get_via().recvived_port;
//	con_par.next = NULL;
//
//	for_par = status_info->get_from();
//	to_par = status_info->get_to();
//
//	call_id = status_info->get_call_id();
//
//	cseq_par.method = Ack;
//	cseq_par.cseq = cseq;
//
//
//
//	if (!packet.build_ack_packet(&req_uri, &via_par, max_forward,
//		&for_par, &to_par, &cseq_par, call_id, &con_par, auth_string))
//		return FALSE;
//
//
//	return TRUE;
//}

//构建 ack消息
//BOOL build_ack_message(CSipPacket &packet, CSipPacketInfo *request_info,
//	CSipPacketInfo *status_info, int cseq, const CString auth)
//{
//	if (NULL == status_info || NULL == request_info )
//		return FALSE;
//
//
//	REQUEST_LINE request_par;
//	request_par.method = Ack;
//
//	request_par.request_uri.user = status_info->get_contact().contact_uri.user;
//	request_par.request_uri.host = status_info->get_contact().contact_uri.host;
//	request_par.request_uri.port = status_info->get_contact().contact_uri.port;
//	request_par.rinstance = status_info->get_contact().rinstance;
//
//
//	HEADER_VIA via_par;
//	//via_par.sent_address = status_info->get_via().sent_address;
//	via_par.sent_address = _T("192.168.100.82");
//	via_par.sent_port = status_info->get_via().sent_port;
//	via_par.branch = CSipPacket::build_via_branch();
//	if (via_par.branch.IsEmpty())
//		return FALSE;
//
//	int max_forward = 70;
//
//	HEADER_CONTACT contact_par;
//	contact_par.contact_uri.user = status_info->get_from().user;
//	contact_par.contact_uri.host = status_info->get_via().received_address;
//	contact_par.contact_uri.port = status_info->get_via().sent_port;
//
//	HEADER_FROM for_par;
//	for_par = status_info->get_from();
//
//	HEADER_TO to_par;
//	to_par = status_info->get_to();
//
//	HEADER_CSEQ cseq_par;
//	cseq_par.method = Ack;
//	cseq_par.cseq = cseq;
//
//	CString call_id = status_info->get_call_id();
//
//
//
//
//	if (!packet.build_request_packet(request_par, via_par, for_par, to_par,
//		call_id, cseq_par, &contact_par, auth, NULL, max_forward))
//		return FALSE;
//
//
//	//packet.
//
//
//
//	return TRUE;
//}


//初始化
//BOOL CSipClient::init(const CString &strServerAddress, unsigned short usServerPort,
//	const CString &strLocalAddress, unsigned short usLocalSipPort)
//{
//	CString strIP;
//	unsigned short usPort = 0;
//
//	m_send_cache = new CRtpPacketCache();
//	if (NULL == m_send_cache)
//		return FALSE;
//	//m_local_sdp = new CSDP();
//	//if (NULL == m_local_sdp)
//	//	return FALSE;
//	m_call_info = new CALL_INFO();
//	if (NULL == m_call_info)
//		return FALSE;
//	//m_call_info->rtp_cache = new CRtpPacketCache();
//	//if (NULL == m_call_info->rtp_cache)
//	//	return FALSE;
//
//	m_strSipServerAddr = strServerAddress;
//	m_usServerPort = usServerPort;
//	m_strLocalSipAddr = strLocalAddress;
//	//初始化sock
//	if (!m_udpSipSock.Create(usLocalSipPort, SOCK_DGRAM))
//		return FALSE;
//	if (!m_udpSipSock.GetSockName(strIP, usPort))
//		return FALSE;
//	if (!m_udpSipSock.EnableNonBlocking(TRUE))
//		return FALSE;
//	m_usLocalSipPort = usPort;
//
//	//创建接收线程
//	m_recv_h = ::CreateThread(NULL, 0, ReceiveSipThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_recv_h);
//	if (NULL == m_recv_h)
//	{
//		return FALSE;
//	}
//	//创建解析sip消息线程
//	m_proc_h = ::CreateThread(NULL, 0, SipPacketProcessThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_proc_h);
//	if (NULL == m_proc_h)
//	{
//		return FALSE;
//	}
//
//	m_client_status = init_ok;
//	m_bwork = TRUE;
//	::ResumeThread(m_recv_h);
//	::ResumeThread(m_proc_h);
//
//	return true;
//}

//BOOL CSipClient::init(const CSDP & sdp, const CString & strServerAddress, unsigned short usServerPort,
//	const CString & strLocalAddress, unsigned short usLocalSipPort)
//{
//	init(strServerAddress, usServerPort, strLocalAddress, usLocalSipPort);
//	set_local_sdp(sdp);
//
//	return 0;
//}

//BOOL CSipClient::init(const CSDP &sdp, const CString &strServerAddress, unsigned short usServerPort,
//	const CString &strLocalAddress, unsigned short usLocalSipPort, unsigned short audio_port,
//	unsigned short video_port)
//{
//	CString strIP;
//	unsigned short usPort = 0;
//
//	m_strServerIP = strServerAddress;
//	m_usServerPort = usServerPort;
//	m_strLocalIP = strLocalAddress;
//	//初始化sock
//	if (!m_udpSipSock.Create(usLocalSipPort, SOCK_DGRAM))
//		return FALSE;
//	if (!m_udpSipSock.GetSockName(strIP, usPort))
//		return FALSE;
//	if (!m_udpSipSock.EnableNonBlocking(TRUE))
//		return FALSE;
//	m_usLocalSipPort = usPort;
//
//	if (!m_udpRtpAudio.Create(audio_port, SOCK_DGRAM))
//		return FALSE;
//	if (!m_udpRtpAudio.GetSockName(strIP, usPort))
//		return FALSE;
//	if (!m_udpRtpAudio.EnableNonBlocking(TRUE))
//		return FALSE;
//	m_usLocalAudioPort = usPort;
//
//	if (!m_udpRtpVideo.Create(video_port, SOCK_DGRAM))
//		return FALSE;
//	if (!m_udpRtpVideo.GetSockName(strIP, usPort))
//		return FALSE;
//	if (!m_udpRtpAudio.EnableNonBlocking(TRUE))
//		return FALSE;
//	m_usLocalVideoPort = usPort;
//
//	//local sdp
//	m_local_sdp = sdp;
//	m_local_sdp.set_address(strLocalAddress);
//	m_local_sdp.set_audio_address(strLocalAddress);
//	m_local_sdp.set_audio_port(m_usLocalAudioPort);
//	m_local_sdp.set_video_address(strLocalAddress);
//	m_local_sdp.set_video_port(m_usLocalVideoPort);
//
//
//
//	//创建接收线程
//	m_recv_h = ::CreateThread(NULL, 0, ReceiveSipThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_recv_h);
//	if (NULL == m_recv_h)
//	{
//		return FALSE;
//	}
//	//创建解析sip消息线程
//	m_proc_h = ::CreateThread(NULL, 0, SipPacketProcessThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_proc_h);
//	if (NULL == m_proc_h)
//	{
//		return FALSE;
//	}
//
//	m_client_status = init_ok;
//	m_bwork = TRUE;
//	::ResumeThread(m_recv_h);
//	::ResumeThread(m_proc_h);
//
//	return true;
//}



//CSDP CSipClient::get_sdp()
//{
//	return m_sdp;
//}

//BOOL CSipClient::register_account(const CString &strUserName, const CString &strPassword)
//{
//	if (init_ok > m_client_status || m_bwork == FALSE)
//		return FALSE;
//	
//	CSipPacket packet;
//	CSipPacketInfo *packet_info = NULL;
//	CString strLineData, strGuid;
//	CStringArray arrLineData;
//
//	//构建注册消息
//	//request-line
//	REQUEST_LINE stuRequsetPar;
//	stuRequsetPar.method = SipRegister;
//	stuRequsetPar.request_uri.host = m_strSipServerAddr;
//	stuRequsetPar.request_uri.port = 0;
//	stuRequsetPar.request_uri.user = strUserName;
//	if (!packet.generate_request_line(strLineData, stuRequsetPar))
//		return FALSE;
//	arrLineData.Add(strLineData);
//
//	//via
//	HEADER_VIA stuViaPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	stuViaPar.branch = _T("z9hG4bK");
//	stuViaPar.branch += strGuid;
//	stuViaPar.recvived_port = 0;
//	stuViaPar.sent_address = m_strLocalSipAddr;
//	stuViaPar.sent_port = m_usLocalSipPort;
//	strLineData = packet.generate_via_line(stuViaPar);
//	arrLineData.Add(strLineData);
//
//	//max forwards
//	strLineData = packet.generate_max_forwards_line(70);
//	arrLineData.Add(strLineData);
//
//	//contact //联系人 注册时是自己
//	HEADER_CONTACT stuContactPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	m_strContactUser.Format(_T("%d"), packet.new_random_user());
//	stuContactPar.contact_uri.host = m_strLocalSipAddr;
//	stuContactPar.contact_uri.port = m_usLocalSipPort;
//	stuContactPar.contact_uri.user = m_strContactUser;
//	stuContactPar.parameter = _T("rinstance");
//	stuContactPar.parameter += strGuid;
//	strLineData = packet.generate_contact_line(stuContactPar);
//	arrLineData.Add(strLineData);
//
//	//to
//	HEADER_TO stuToPar;
//	//if (!packet.NewGUIDString(strGuid))
//	//	return FALSE;
//	stuToPar.display_info = strUserName;
//	stuToPar.to_user = strUserName;
//	stuToPar.to_host = m_strSipServerAddr;
//	//stuToPar.to_tag = strGuid;
//	strLineData = packet.generate_to_line(stuToPar);
//	arrLineData.Add(strLineData);
//
//	//from
//	HEADER_FROM stuFromPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	stuFromPar.display_info = strUserName;
//	stuFromPar.from_user = strUserName;
//	stuFromPar.from_host = m_strSipServerAddr;
//	stuFromPar.from_tag = strGuid;
//	strLineData = packet.generate_from_line(stuFromPar);
//	arrLineData.Add(strLineData);
//
//	//call-id
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	strLineData = packet.generate_callid_line(strGuid);
//	arrLineData.Add(strLineData);
//
//	//cseq
//	HEADER_CSEQ stuCSeqPar;
//	stuCSeqPar.cseq = m_nRegisterCSeq;
//	stuCSeqPar.method = SipRegister;
//	if (!packet.generate_cseq_line(strLineData, stuCSeqPar))
//		return FALSE;
//	arrLineData.Add(strLineData);
//
//	//结束
//	arrLineData.Add(_T("\r\n"));
//
//	packet.build_packet(arrLineData);
//
//	//发送
//	if (!send_packet(&packet))
//		return FALSE;
//
//	//packet info
//	packet_info = new CSipPacketInfo();
//	if (NULL == packet_info)
//		return FALSE;
//	if (!packet_info->from_packet(&packet))
//		return FALSE;
//	//保存信息
//	m_strUserName = strUserName;
//	m_strPassword = strPassword;
//
//	m_last_send_time = ::GetTickCount();
//	packet_info->set_time(m_last_send_time);
//	m_send_packet_arrLock.Lock();
//	m_arrRequest_PackInfo.Add(packet_info);
//	m_send_packet_arrLock.Unlock();
//
//	return TRUE;
//}

//BOOL CSipClient::register_account(const CString &strUserName, const CString &strPassword)
//{
//	if (init_ok > m_client_status || m_bwork == FALSE)
//	{
//		return false;
//	}
//
//	int ret = 0;
//	CSipPacket packet;
//	CString request_line, via, max_forwards, from, to, call_id_line, cseq, contact;
//	CString via_branch, from_tag, contact_rinstance, call_id, str_null;
//
//	if (!packet.generate_request_line(request_line, SipRegister, str_null, m_strServerIP, 0, str_null))
//	{
//		return FALSE;
//	}
//	if (!NewGUIDString(via_branch))
//	{
//		return FALSE;
//	}
//	via_branch.Insert(0, _T("z9hG4bK"));
//	via = packet.generate_via(m_strLocalIP, m_usLocalSipPort, via_branch, str_null, str_null);
//	max_forwards = packet.generate_max_forwards(70);
//	if (!NewGUIDString(from_tag))
//		return FALSE;
//	from = packet.generate_from(strUserName, strUserName, m_strServerIP, from_tag);
//	to = packet.generate_to(str_null, strUserName, m_strServerIP, str_null);
//	if (!NewGUIDString(contact_rinstance))
//		return FALSE;
//	contact = packet.generate_contact(strUserName, m_strLocalIP, m_usLocalSipPort, contact_rinstance);
//	if (!NewGUIDString(call_id))
//		return FALSE;
//	call_id_line = packet.generate_call_id(call_id);
//	m_nRegisterCSeq++;
//	cseq = packet.generate_cseq(m_nRegisterCSeq, SipRegister);
//
//	packet.build_register_pack(request_line, via, max_forwards, from, to, contact, call_id_line, cseq);
//
//	//需要回应
//	CSipPacketInfo *pack_info = new CSipPacketInfo();
//	if (!pack_info->from_packet(&packet))
//	{
//		delete pack_info;
//		return FALSE;
//	}
//	m_RequestInfoArrLock.Lock();
//	m_arrRequestPackInfo.Add(pack_info);
//	m_RequestInfoArrLock.Unlock();
//
//	//发送sip消息
//	if (!send_sip_packet(&packet))
//		return FALSE;
//
//	//保存信息
//	m_strUserName = strUserName;
//	m_strPassword = strPassword;
//
//
//	return TRUE;
//
//}

//BOOL CSipClient::make_call(const CString &strCallName, BOOL audio_media, WORD audio_port,
//	BOOL video_media, WORD video_port)
//{
//	if (!m_bwork || m_client_status < register_ok)
//		return false;
//
//	CSipPacket packet;
//	CSipPacketInfo *packet_info = NULL;
//	CString addr, str_sdp, strLineData, strGuid, strCallId;
//	CStringArray arrLineData;
//	WORD port;
//	
//	//修改sdp (端口，地址)
//	//m_local_sdp->set_address(m_strLocalSipAddr);
//	//m_local_sdp->set_audio_media(audio_media);
//	//m_local_sdp->set_video_media(video_media);
//	//if (audio_media)
//	//{
//	//	m_call_info->udp_audio = new CNetSocket();
//	//	if (NULL == m_call_info->udp_audio)
//	//		return FALSE;
//	//	if (!m_call_info->udp_audio->Create(audio_port, SOCK_DGRAM))
//	//		return FALSE;
//	//	if (!m_call_info->udp_audio->GetSockName(addr, port))
//	//		return FALSE;
//	//	m_local_sdp->set_audio_media(TRUE);
//	//	m_local_sdp->set_audio_port(port);
//	//	m_local_sdp->set_audio_address(m_strLocalSipAddr);
//	//}
//	//if (video_media)
//	//{
//	//	m_call_info->udp_video = new CNetSocket();
//	//	if (NULL == m_call_info->udp_video)
//	//		return FALSE;
//	//	if (!m_call_info->udp_video->Create(video_port, SOCK_DGRAM))
//	//		return FALSE;
//	//	if (!m_call_info->udp_video->GetSockName(addr, port))
//	//		return FALSE;
//	//	m_local_sdp->set_video_media(TRUE);
//	//	m_local_sdp->set_video_port(port);
//	//	m_local_sdp->set_video_address(m_strLocalSipAddr);
//	//}
//
//	//构建invite消息
//	//request-line
//	REQUEST_LINE stuRequsetPar;
//	stuRequsetPar.method = SipInvite;
//	stuRequsetPar.request_uri.host = m_strSipServerAddr;
//	stuRequsetPar.request_uri.port = 0;
//	stuRequsetPar.request_uri.user = strCallName;
//	if (!packet.generate_request_line(strLineData, stuRequsetPar))
//		return FALSE;
//	arrLineData.Add(strLineData);
//
//	//via
//	HEADER_VIA stuViaPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	stuViaPar.branch = _T("z9hG4bK");
//	stuViaPar.branch += strGuid;
//	stuViaPar.recvived_port = 0;
//	stuViaPar.sent_address = m_strLocalSipAddr;
//	stuViaPar.sent_port = m_usLocalSipPort;
//	strLineData = packet.generate_via_line(stuViaPar);
//	arrLineData.Add(strLineData);
//
//	//max forwards
//	strLineData = packet.generate_max_forwards_line(70);
//	arrLineData.Add(strLineData);
//
//	//contact 
//	HEADER_CONTACT stuContactPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	stuContactPar.contact_uri.host = m_strLocalSipAddr;
//	stuContactPar.contact_uri.port = m_usLocalSipPort;
//	stuContactPar.contact_uri.user = m_strContactUser;
//	stuContactPar.parameter = _T("rinstance");
//	stuContactPar.parameter += strGuid;
//	strLineData = packet.generate_contact_line(stuContactPar);
//	arrLineData.Add(strLineData);
//
//	//to
//	HEADER_TO stuToPar;
//	//if (!packet.NewGUIDString(strGuid))
//	//	return FALSE;
//	stuToPar.display_info.Empty();
//	stuToPar.to_user = strCallName;
//	stuToPar.to_host = m_strSipServerAddr;
//	//stuToPar.to_tag = strGuid;
//	strLineData = packet.generate_to_line(stuToPar);
//	arrLineData.Add(strLineData);
//
//	//from
//	HEADER_FROM stuFromPar;
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	stuFromPar.display_info = m_strUserName;
//	stuFromPar.from_user = m_strUserName;
//	stuFromPar.from_host = m_strSipServerAddr;
//	stuFromPar.from_tag = strGuid;
//	strLineData = packet.generate_from_line(stuFromPar);
//	arrLineData.Add(strLineData);
//
//	//call-id
//	if (!packet.NewGUIDString(strGuid))
//		return FALSE;
//	strLineData = packet.generate_callid_line(strGuid);
//	strCallId = strGuid;
//	arrLineData.Add(strLineData);
//
//	//cseq
//	HEADER_CSEQ stuCSeqPar;
//	stuCSeqPar.cseq = m_nRegisterCSeq;
//	stuCSeqPar.method = SipRegister;
//	if (!packet.generate_cseq_line(strLineData, stuCSeqPar))
//		return FALSE;
//	arrLineData.Add(strLineData);
//	arrLineData.Add(_T("\r\n\r\n"));
//
//	//message body (sdp)
//	CSDP *pSdp = new CSDP;
//	*pSdp = *m_local_sdp;
//	pSdp->m_bAudioMedia = audio_media;
//	pSdp->m_usAudioPort = audio_port;
//	pSdp->m_bVideoMedia = video_media;
//	pSdp->m_usVideoPort = video_port;
//	CString strSdp = pSdp->to_string();
//	arrLineData.Add(strSdp);
//
//	//组包
//	packet.build_packet(arrLineData);
//
//	//发送sip消息
//	if (!send_packet(&packet))
//		return FALSE;
//
//	//保存信息
//	//call_info
//	if (NULL != m_call_info)
//	{
//		m_call_info->call_status = INVITE_START;
//		m_call_info->call_name = strCallName;
//		m_call_info->call_id = strCallId;
//		m_call_info->pLocalSdp = pSdp;
//	}
//	//packet info
//	packet_info = new CSipPacketInfo();
//	if (NULL == packet_info)
//		return FALSE;
//	if (!packet_info->from_packet(&packet))
//		return FALSE;
//	m_last_send_time = ::GetTickCount();
//	packet_info->set_time(m_last_send_time);
//	m_send_packet_arrLock.Lock();
//	m_arrRequest_PackInfo.Add(packet_info);
//	m_send_packet_arrLock.Unlock();
//	CSipPacketInfo *pack_info = new CSipPacketInfo();
//	if (!pack_info->from_packet(&packet))
//	{
//		delete pack_info;
//		return FALSE;
//	}
//	pack_info->set_time(::GetTickCount());
//	m_send_packet_arrLock.Lock();
//	m_arrRequest_PackInfo.Add(pack_info);
//	m_send_packet_arrLock.Unlock();
//
//	m_client_status = inviteing;
//	return TRUE;
//}

//BOOL CSipClient::make_call(int &status_code, const CString &strCallName,
//	BOOL bAuidoMedia, BOOL bVideoMedia)
//{
//	if (!m_bwork || m_client_status < register_ok)
//		return false;
//
//
//	int ret = 0;
//	CSipPacket packet;
//	CString str_local_sdp;
//	CString request_line, via, max_forwards, from, to, call_id_line, cseq, contact;
//	CString via_branch, from_tag, call_id, str_null;
//
//
//	if (!packet.generate_request_line(request_line, SipInvite, strCallName, m_strServerIP, 0, str_null))
//	{
//		return FALSE;
//	}
//	if (!NewGUIDString(via_branch))
//	{
//		return FALSE;
//	}
//	via_branch.Insert(0, _T("z9hG4bK"));
//	via = packet.generate_via(m_strLocalIP, m_usLocalSipPort, via_branch, str_null, str_null);
//	max_forwards = packet.generate_max_forwards(70);
//	if (!NewGUIDString(from_tag))
//		return FALSE;
//	from = packet.generate_from(m_strUserName, m_strUserName, m_strServerIP, from_tag);
//	to = packet.generate_to(str_null, strCallName, m_strServerIP, str_null);
//	contact = packet.generate_contact(m_strUserName, m_strLocalIP, m_usLocalSipPort, str_null);
//	m_nInviteCSeq++;
//
//	if (!NewGUIDString(call_id))
//		return FALSE;
//	call_id_line = packet.generate_call_id(call_id);
//	m_nInviteCSeq++;
//	cseq = packet.generate_cseq(m_nInviteCSeq, SipInvite);
//
//	if (!bAuidoMedia)
//		m_local_sdp.set_audio_media(FALSE);
//	if (!bVideoMedia)
//		m_local_sdp.set_video_media(FALSE);
//	//修改sdp
//	m_local_sdp.set_address(m_strLocalIP);
//	m_local_sdp.set_audio_port(m_usLocalAudioPort);
//	m_local_sdp.set_audio_address(m_strLocalIP);
//	m_local_sdp.set_video_port(m_usLocalVideoPort);
//	m_local_sdp.set_video_address(m_strLocalIP);
//
//
//	str_local_sdp = m_local_sdp.to_buffer();
//	
//
//
//	packet.build_invite_pack(request_line, via, max_forwards, from, to, contact, call_id_line, cseq, str_local_sdp);
//
//	//需要回应
//	CSipPacketInfo *pack_info = new CSipPacketInfo();
//	if (!pack_info->from_packet(&packet))
//	{
//		delete pack_info;
//		return FALSE;
//	}
//	m_RequestInfoArrLock.Lock();
//	m_arrRequestPackInfo.Add(pack_info);
//	m_RequestInfoArrLock.Unlock();
//
//
//	//发送sip消息
//	if (!send_sip_packet(&packet))
//		return FALSE;
//
//	m_strCallName = strCallName;
//	m_str_call_id = call_id;
//	m_client_status = inviteing;
//	return TRUE;
//}

//BOOL CSipClient::hangup(const CString &strCallName)
//{
//
//	//
//	//1,发送bye到服务器
//	//build_bye_request()
//	//build_ack_request
//	//2，拆除 发送和接收 rtp线程
//	//3，移除 callinfo
//
//	//m_client_status = register_ok;
//
//	return 0;
//}

//CSipPacketInfo::CSipPacketInfo()
//{
//
//}
//
////CSipPacketInfo::CSipPacketInfo(CSipPacket *packet)
////{
////	char *data = NULL;
////	int i = 0, j = 0, data_len = 0;
////	char line_buf[TEMP_BUF_SIZE] = { 0 }, value[TEMP_BUF_SIZE] = { 0 };
////
////
////
////	if (NULL == packet)
////		return;
////	data = (char *)packet->get_data();
////	if (NULL == data)
////		return;
////	data_len = packet->get_data_len();
////	while (i < TEMP_BUF_SIZE && i< data_len)
////	{
////		if ('\r' == data[i])
////			break;
////		line_buf[i] = data[i];
////		i++;
////	}
////
////	j = 0;
////	while (j <= i)
////	{
////		if (' ' == line_buf[j])
////			break;
////		value[j] = line_buf[j];
////		j++;
////	}
////	if (strncmp(value, "SIP/2.0", strlen("SIP/2.0")) == 0)//type == status
////	{
////		m_type = sip_status;
////		j++;//跳过空格
////		n = 0;
////		while (j <= i)
////		{
////			if (data[j] >= 48 && data[j] <= 57)
////			{
////				n = n * 10 + (data[j] - 48);
////			}
////			j++;
////		}
////
////		switch (n)
////		{
////		case 100:
////			m_status = trying;
////			break;
////		case 180:
////			m_status = ringing;
////			break;
////		case 200:
////			m_status = ok;
////			break;
////		default:
////			m_status = not_proc_status;
////			break;
////		}
////	}
////	else
////	{
////		m_type = sip_request;
////
////		if (strncmp(value, "REGISTER", strlen("REGISTER")) == 0)
////		{
////			m_method = SipRegister;
////		}
////		else if (strncmp(value, "INVITE", strlen("INVITE")) == 0)
////		{
////			m_method = SipInvite;
////		}
////		else if (strncmp(value, "ACK", strlen("ACK")) == 0)
////		{
////			m_method = SipAck;
////		}
////		else if (strncmp(value, "BYE", strlen("BYE")) == 0)
////		{
////			m_method = SipBye;
////		}
////		else
////		{
////			m_method = UnknownMethod;
////		}
////	}
////
////}
//
//
//CSipPacketInfo::~CSipPacketInfo()
//{
//}
//
//
//BOOL CSipPacketInfo::from_packet(CSipPacket * packet)
//{
//	if (packet == NULL)
//		return FALSE;
//
//
//	char value[TEMP_BUF_SIZE] = { 0 }, line[TEMP_BUF_SIZE] = { 0 };
//	char *flag = NULL, *temp = NULL, *data = NULL;
//	int i = 0, j = 0, n = 0, data_len = 0;
//
//	data =(char *) packet->get_data();
//	data_len = packet->get_data_len();
//	if (NULL == data || data_len <= 0)
//		return FALSE;
//
//	//request/strtus line
//	while (i < TEMP_BUF_SIZE && i< data_len)
//	{
//		if ('\r' == data[i])
//			break;
//		line[i] = data[i];
//		i++;
//	}
//
//	//取第一个空格前的内容
//	j = 0;
//	while (j<=i)
//	{
//		if (' ' == line[j])
//			break;
//		value[j] = line[j];
//		j++;
//	}
//	if (strncmp(value, "SIP/2.0", strlen("SIP/2.0")) == 0)//type == status
//	{
//		m_type = sip_status;
//		j++;//跳过空格
//		n = 0;
//		while (j<=i)
//		{
//			if (data[j] >= 48 && data[j] <= 57)
//			{
//				n = n * 10 + (data[j] - 48);
//			}
//			j++;
//		}
//
//		switch (n)
//		{
//		case 100:
//			m_status_code = trying;
//			break;
//		case 180:
//			m_status_code = ringing;
//			break;
//		case 200:
//			m_status_code = ok;
//			break;
//		default:
//			m_status_code = other_status;
//			break;
//		}
//
//	}
//	else
//	{
//		m_type = sip_request;
//
//		if (strncmp(value, "REGISTER", strlen("REGISTER")) == 0)
//		{
//			m_method = SipRegister;
//		}
//		else if (strncmp(value, "INVITE", strlen("INVITE")) == 0)
//		{
//			m_method = SipInvite;
//		}
//		else if (strncmp(value, "ACK", strlen("ACK")) == 0)
//		{
//			m_method = SipAck;
//		}
//		else if (strncmp(value, "BYE", strlen("BYE")) == 0)
//		{
//			m_method = SipBye;
//		}
//		else
//		{
//			m_method = other_method;
//		}
//
//		//未完成
//		memset(value, 0, TEMP_BUF_SIZE);
//		strstr(line, "sip:");
//	}
//
//	//via branch
//
//	flag = strstr(data, "Via");
//	if (NULL != flag)
//	{
//		memset(line, 0, TEMP_BUF_SIZE);
//		i = 0;
//		while (i < TEMP_BUF_SIZE && i < data_len)
//		{
//			if ('\r' == flag[i])
//				break;
//			line[i] = flag[i];
//			i++;
//		}
//		
//
//		temp = strstr(line," ");
//		if (NULL != temp)
//		{
//			memset(value, 0, TEMP_BUF_SIZE);
//			j = 0;
//			while (j < TEMP_BUF_SIZE && j< i)
//			{
//				if ('\r' == temp[j] || ':' == temp[j])
//					break;
//				value[j] = temp[j];
//				j++;
//			}
//			m_via_branch = value;
//		}
//
//	}
//
//	//m_from_tag
//	flag = strstr(data, "From");
//	if (flag != NULL)
//	{
//		memset(line, 0, TEMP_BUF_SIZE);
//		i = 0;
//		while (flag[i] != '\r'&& i<TEMP_BUF_SIZE)
//		{
//			line[i] = flag[i];
//			i++;
//		}
//		m_from = line;
//
//		flag = strstr(line, "tag=");
//		if (flag != NULL)
//		{
//			memset(value, 0, TEMP_BUF_SIZE);
//			i = 0;
//			flag += strlen("tag=");
//			while (i<TEMP_BUF_SIZE)
//			{
//				if (flag[i] == '\0' || flag[i] == ';')
//				{
//					break;
//				}
//				value[i] = flag[i];
//				i++;
//			}
//			m_from_tag = value;
//		}
//
//	}
//
//	//to tag
//	flag = strstr(data, "To");
//	if (flag != NULL)
//	{
//		memset(line, 0, TEMP_BUF_SIZE);
//		i = 0;
//		while (flag[i] != '\r'&& i<TEMP_BUF_SIZE)
//		{
//			line[i] = flag[i];
//			i++;
//		}
//		m_to = line;
//
//		flag = strstr(line, "tag=");
//		if (flag != NULL)
//		{
//			memset(value, 0, TEMP_BUF_SIZE);
//			i = 0;
//			flag += strlen("tag=");
//			while (i<TEMP_BUF_SIZE)
//			{
//				if (flag[i] == '\0' || flag[i] == ';')
//				{
//					break;
//				}
//				value[i] = flag[i];
//				i++;
//			}
//			m_to_tag = value;
//
//		}
//
//	}
//
//	//call id
//	flag = strstr(data, "Call-ID");
//	if (flag != NULL)
//	{
//		memset(value, 0, TEMP_BUF_SIZE);
//		i = 0;
//		flag += strlen("Call-ID: ");
//		while (flag[i] != '\r'&&i<TEMP_BUF_SIZE)
//		{
//			value[i] = flag[i];
//			i++;
//		}
//		m_call_id = value;
//	}
//
//	//contact  user address port ranstance
//	flag = strstr(data, "Contact");
//	if (flag != NULL)
//	{
//		memset(line, 0, TEMP_BUF_SIZE);
//		i = 0;
//		while (flag[i] != '\r'&& i<TEMP_BUF_SIZE)
//		{
//			line[i] = flag[i];
//			i++;
//		}
//
//		//user
//		memset(value, 0, TEMP_BUF_SIZE);
//		i = 0;
//		flag += strlen("Contact: <sip:");
//		while (i<TEMP_BUF_SIZE)
//		{
//			if (flag[i] == '\r' || flag[i] == '@')
//			{
//				break;
//			}
//			value[i] = flag[i];
//			i++;
//		}
//		m_contact_user = value;
//		//address
//		i++;//跳过‘@’
//		j = 0;
//		memset(value, 0, 1024);
//		while (i<TEMP_BUF_SIZE)
//		{
//			if (flag[i] == '\r' || flag[i] == ':')
//			{
//				break;
//			}
//			value[j] = flag[i];
//			i++;
//			j++;
//		}
//		m_contact_address = value;
//		//port
//		i++;//跳过‘：’
//		memset(value, 0, 1024);
//		n = 0;
//		while (i<TEMP_BUF_SIZE)
//		{
//			if (flag[i] == '\r' || flag[i] == '>' || flag[i] == ';')
//			{
//				break;
//			}
//			if (flag[i] >= 48 && flag[i] <= 57)
//			{
//				n = n * 10 + (flag[i] - 48);
//			}
//			i++;
//		}
//		m_contact_port = n;
//
//		//rinstance
//		flag = strstr(line, "rinstance");
//		if (flag != NULL)
//		{
//			memset(value, 0, 1024);
//			i = 0;
//			flag += strlen("rinstance=");
//			while (i<TEMP_BUF_SIZE)
//			{
//				if (flag[i] == '\r' || flag[i] == '>')
//				{
//					break;
//				}
//				value[i] = flag[i];
//				i++;
//			}
//			m_contact_rinstance = value;
//		}
//	}
//
//	//cseq
//	flag = strstr(data, "CSeq");
//	if (flag != NULL)
//	{
//		memset(value, 0, 1024);
//		i = 0;
//		n = 0;
//		flag += strlen("CSeq: ");
//		while (i<TEMP_BUF_SIZE)
//		{
//			if (flag[i] == ' ' || flag[i] == '\r')
//			{
//				break;
//			}
//			if (flag[i] >= 48 && flag[i] <= 57)
//			{
//				n = n * 10 + (flag[i] - 48);
//			}
//			i++;
//		}
//		m_cseq_value = n;
//	}
//
//	//flag = strstr(data, "\r\n\r\nv=");
//	//if (flag != NULL)
//	//{
//	//	if (!m_sdp_info.from_buffer(flag))
//	//	{
//	//		return FALSE;
//	//	}
//	//}
//
//	//if (!CRtspClient::build_sdp_info(m_sdp_info, flag))
//	//{
//	//	return FALSE;
//	//}
//	////mess body(sdp)
//	//flag = strstr(data, "\r\n\r\nv=");
//	//if (flag == NULL)
//	//{
//	//	return TRUE;
//	//}
//	//flag += strlen("\r\n\r\n");
//	////取出ip地址
//	//temp = strstr(flag, "IN IP4");
//	//if (temp != NULL)
//	//{
//	//	memset(value, 0, 1024);
//	//	i = 0;
//	//	temp += strlen("IN IP4 ");
//	//	while (*temp != '\r')
//	//	{
//	//		value[i] = *temp;
//	//		temp++;
//	//		i++;
//	//	}
//	//	m_sdp_info.strIP = value;
//	//}
//	////有音频sdp
//	//temp = strstr(flag, "m=audio");
//	//if (temp != NULL)
//	//{
//	//	m_sdp_info.bAudioMedia = TRUE;
//	//	//提取port
//	//	temp += strlen("m=audio ");
//	//	n = 0;
//	//	while (*temp != ' ')
//	//	{
//	//		if (*temp >= 48 && *temp <= 57)
//	//		{
//	//			n = n * 10 + (*temp - 48);
//	//		}
//	//		temp++;
//	//	}
//	//	m_sdp_info.usAudioPort = n;
//	//	//提取load type
//	//	n = 0;
//	//	temp += strlen(" RTP/AVP ");
//	//	while (*temp != '\r')
//	//	{
//	//		if (*temp >= 48 && *temp <= 57)
//	//		{
//	//			n = n * 10 + (*temp - 48);
//	//		}
//	//		temp++;
//	//	}
//	//	m_sdp_info.nAudioLoadType = n;
//	//	//取出ip地址
//	//	temp = strstr(flag, "c=IN IP4");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("c=IN IP4 ");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//			i++;
//	//		}
//	//		m_sdp_info.strAudioIP = value;
//	//	}
//	//	//提取rtpmap
//	//	temp = strstr(flag, "rtpmap");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("rtpmap:");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//			i++;
//	//		}
//	//		m_sdp_info.strAudioRtpMap = value;
//	//	}
//	//	//提取fmpt
//	//	temp = strstr(flag, "fmtp");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("fmtp:");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//			i++;
//	//		}
//	//		m_sdp_info.strAudioFmtp = value;
//	//	}
//	//}
//	////有视频sdp
//	//temp = strstr(flag, "m=video");
//	//if (temp != NULL)
//	//{
//	//	m_sdp_info.bAudioMedia = TRUE;
//	//	//提取port
//	//	temp += strlen("m=video ");
//	//	n = 0;
//	//	while (*temp != ' ')
//	//	{
//	//		if (*temp >= 48 && *temp <= 57)
//	//		{
//	//			n = n * 10 + (*temp - 48);
//	//		}
//	//		temp++;
//	//	}
//	//	m_sdp_info.usVideoPort = n;
//	//	//提取load type
//	//	n = 0;
//	//	temp += strlen(" RTP/AVP ");
//	//	while (*temp != '\r')
//	//	{
//	//		if (*temp >= 48 && *temp <= 57)
//	//		{
//	//			n = n * 10 + (*temp - 48);
//	//		}
//	//		temp++;
//	//	}
//	//	m_sdp_info.nVideoLoadType = n;
//	//	//取出ip地址
//	//	temp = strstr(flag, "c=IN IP4");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("c=IN IP4 ");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//			i++;
//	//		}
//	//		m_sdp_info.strVideoIP = value;
//	//	}
//	//	//提取rtpmap
//	//	temp = strstr(flag, "rtpmap");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("rtpmap:");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//		}
//	//		m_sdp_info.strVideoRtpMap = value;
//	//	}
//	//	//提取fmpt
//	//	temp = strstr(flag, "fmtp");
//	//	if (temp != NULL)
//	//	{
//	//		memset(value, 0, 1024);
//	//		i = 0;
//	//		temp += strlen("fmtp:");
//	//		while (*temp != '\r')
//	//		{
//	//			value[i] = *temp;
//	//			temp++;
//	//			i++;
//	//		}
//	//		m_sdp_info.strVideoFmtp = value;
//	//	}
//	//}
//
//	return TRUE;
//}
//
//MESSAGE_TYPE CSipPacketInfo::get_type()
//{
//	return m_type;
//}
//
//
//STATUS_CODE CSipPacketInfo::get_status()
//{
//	return m_status_code;
//}
//
//REQUEST_METHOD CSipPacketInfo::get_method()
//{
//	return m_method;
//}
//
//
//
//CString CSipPacketInfo::get_via_branch()
//{
//	return m_via_branch;
//}
//
//CString CSipPacketInfo::get_from_tag()
//{
//	return m_from_tag;
//}
//
//CString CSipPacketInfo::get_to_tag()
//{
//	return m_to_tag;
//}
//
//CString CSipPacketInfo::get_call_id()
//{
//	return m_call_id;
//}
//
//
//CString CSipPacketInfo::get_contact_rinstance()
//{
//	return m_contact_rinstance;
//}
//
//CString CSipPacketInfo::get_contact_user()
//{
//	return m_contact_user;
//}
//
//CString CSipPacketInfo::get_contact_address()
//{
//	return m_contact_address;
//}
//
//int CSipPacketInfo::get_contact_port()
//{
//	return m_contact_port;
//}
//
//int CSipPacketInfo::get_cseq()
//{
//	return m_cseq_value;
//}



//int CSipPacketInfo::get_via_array_length()
//{
//	return 0;
//}
//
//SIP_VIA CSipPacketInfo::get_via(int index)
//{
//	return SIP_VIA();
//}
//
//int CSipPacketInfo::get_contact_array_length()
//{
//	return 0;
//}
//
//SIP_CONTACT CSipPacketInfo::get_contact(int index)
//{
//	return SIP_CONTACT();
//}
//SIP_FROM CSipPacketInfo::get_from()
//{
//	return SIP_FROM();
//}
//
//SIP_TO CSipPacketInfo::get_to()
//{
//	return SIP_TO();
//}
//
//SIP_CSEQ CSipPacketInfo::get_cseq()
//{
//	return SIP_CSEQ();
//}
//REQUEST_LINE CSipPacketInfo::get_request_line()
//{
//	return REQUEST_LINE();
//}
//
//STATUS_LINE CSipPacketInfo::get_status_line()
//{
//	return STATUS_LINE();
//}



//CSDP CSipPacketInfo::get_sdp_info()
//{
//	return m_sdp_info;
//}
//
//
//CSipPacket::CSipPacket()
//{
//	m_data_len = 0;
//	m_data = NULL;
//}
//
//CSipPacket::CSipPacket(unsigned int packet_length)
//{
//	if (packet_length > 0)
//	{
//		m_data = new unsigned char[packet_length];
//		m_data_len = packet_length;
//	}
//}
//
////CSipPacket::CSipPacket(const CSipPacket & oldPacket)
////{
////	if (oldPacket.m_data_len > 0)
////	{
////		if (m_data != NULL)
////			delete m_data;
////
////		m_data = new unsigned char[oldPacket.m_data_len];
////		memcpy(m_data, oldPacket.m_data, oldPacket.m_data_len);
////		m_data_len = oldPacket.m_data_len;
////	}
////
////}
//
//CSipPacket::~CSipPacket()
//{
//	if (m_data != NULL)
//	{
//		delete m_data;
//		m_data = NULL;
//	}
//
//	m_data_len = 0;
//}
//
//BOOL CSipPacket::FromBuffer(unsigned char * data, int data_len)
//{
//	if (data_len <= 0 || NULL == data)
//	{
//		return FALSE;
//	}
//
//	if (m_data != NULL)
//	{
//		delete m_data;
//	}
//	m_data = new unsigned char[data_len];
//	memcpy(m_data, data, data_len);
//	m_data_len = data_len;
//
//	return TRUE;
//}
//
//BOOL CSipPacket::build_register_request(CString str_server_addr, WORD server_port, CString str_local_addr, WORD local_port, CString username, CString password)
//{
//
//
//
//
//	return 0;
//}
//
////BOOL CSipPacket::build_register_pack(CString str_username, CString str_password,
////	CString server_addr, unsigned short server_port,
////	CString sent_addr, unsigned short sent_port)
////{
////	//REQUEST_LINE request_line;
////	//SIP_VIA via;
////	//int max_forwards;
////	//SIP_FROM from;
////	//SIP_TO to;
////	//SIP_CONTACT contact;
////	//SIP_CSEQ cseq;
////	//CString call_id;
////	//request_line.method = SipRegister;
////	//request_line.request_uri.host = server_addr;
////	//request_line.request_uri.port = 0;
////	//via.sent_address = 
////	CString str_packet, str_temp, str_parameter;
////	char *packet_pointer = NULL;
////
////	
////	str_temp.Format(_T("REGISTER sip:%s SIP/2.0"), server_addr);
////	str_packet += str_temp;
////
////	if (!NewGUIDString(str_parameter))
////		return FALSE;
////	str_parameter.Insert(0, _T("z9hG4bK"));
////	str_temp.Format(_T("SIP/2.0/UDP %s:%d;rport;branch=%s\r\n"), sent_addr, sent_port, str_parameter);
////	str_packet += str_temp;
////
////	m_data_len = str_packet.GetLength();
////	m_data = new unsigned char[m_data_len];
////	USES_CONVERSION;
////	packet_pointer = T2A(str_packet);
////	if (packet_pointer)
////		memcpy(m_data, packet_pointer, m_data_len);
////
////
////	return TRUE;
////}
////#define SIP_DEFAULT_DATA_SIZE 4096
////BOOL CSipPacket::build_register_pack(REQUEST_LINE request_line, SIP_VIA * via, int via_num,
////	int max_forwards, SIP_FROM from, SIP_TO to, SIP_CONTACT * contact, int contact_num,
////	CString call_id, SIP_CSEQ CSeq)
////{
////	if (NULL != m_data)
////		delete m_data;
////
////	CString str_via, str_line;
////
////	str_line.Format(_T(""));
////
////
////
////
////}
//
//void CSipPacket::build_register_request(CString request_line, CString via, CString max_forwards, CString from,
//	CString to, CString contact, CString call_id, CString CSeq)
//{
//	CString packet;
//
//	packet += request_line;
//	packet += via;
//	packet += max_forwards;
//	packet += from;
//	packet += to;
//	packet += contact;
//	packet += call_id;
//	packet += CSeq;
//	packet += _T("\r\n");
//
//	m_data_len = packet.GetLength();
//	if (m_data != NULL)
//	{
//		delete m_data;
//	}
//	m_data = new unsigned char[m_data_len];
//	USES_CONVERSION;
//	char *data = T2A(packet);
//	memcpy(m_data, data, m_data_len);
//
//
//	return ;
//}
//
//void CSipPacket::build_invite_request(CString request_line, CString via, CString max_forwards,
//	CString from, CString to, CString contact, CString call_id, CString CSeq, CString sdp)
//{
//	CString packet;
//	CString content_type, content_length;
//
//	int sdp_len = sdp.GetLength();
//	content_type.Format(_T("Content-Type: application/sdp\r\n"));
//	content_length.Format(_T("Content-Length: %d\r\n"), sdp_len);
//
//	packet += request_line;
//	packet += via;
//	packet += max_forwards;
//	packet += from;
//	packet += to;
//	packet += contact;
//	packet += call_id;
//	packet += CSeq;
//	packet += content_type;
//	packet += content_length;
//	packet += _T("\r\n");
//
//	packet += sdp;
//
//
//	m_data_len = packet.GetLength();
//	if (m_data != NULL)
//	{
//		delete m_data;
//	}
//	m_data = new unsigned char[m_data_len];
//	USES_CONVERSION;
//	char *data = T2A(packet);
//	memcpy(m_data, data, m_data_len);
//
//
//	return;
//}
//
//void CSipPacket::build_ack_request(CString request_line, CString via, CString max_forwards, CString from,
//	CString to, CString call_id, CString CSeq)
//{
//	CString packet;
//
//	packet += request_line;
//	packet += via;
//	packet += max_forwards;
//	packet += from;
//	packet += to;
//	packet += call_id;
//	packet += CSeq;
//	packet += _T("Route: <sip:192.168.100.60;lr>\r\n");
//	packet += _T("Content-Length:  0\r\n");
//	packet += _T("\r\n");
//
//
//	m_data_len = packet.GetLength();
//	if (m_data != NULL)
//	{
//		delete m_data;
//	}
//	m_data = new unsigned char[m_data_len];
//	USES_CONVERSION;
//	char *data = T2A(packet);
//	memcpy(m_data, data, m_data_len);
//
//
//	return;
//}
//
//void CSipPacket::build_ok_status(CString status_line, CString via, CString max_forwards, CString from, CString to, CString call_id, CString CSeq, CString sdp_buf)
//{
//
//}
//
//unsigned char * CSipPacket::build_invite_status(CSipPacketInfo * packet, STATUS_CODE status_code,
//	unsigned char * content, int content_len)
//{
//	if (NULL == packet)
//		return NULL;
//
//
//
//
//
//
//}
//
//
//
//BOOL CSipPacket::build_status_pack(CSipPacket * packet, STATUS_CODE status_code, unsigned char * content, int content_len)
//{
//	if (NULL == packet)
//		return FALSE;
//
//	CSipPacketInfo old_packet_info;
//
//	if (!old_packet_info.from_packet(packet))
//		return FALSE;
//
//	if (sip_request != old_packet_info.get_type())
//		return FALSE;
//
//	switch (old_packet_info.get_method())
//	{
//	case SipInvite:
//
//		break;
//	case SipAck:
//		break;
//	case SipBye:
//		break;
//	default:
//		break;
//	}
//
//
//	return TRUE;
//}
//
//CString CSipPacket::generate_request_line(REQUEST_LINE request)
//{
//	CString str_value, str_temp;
//
//	switch (request.method)
//	{
//	case SipRegister:
//		str_value.Format(_T("REGISTER sip:"));
//		break;
//	}
//	if (!request.request_uri.user.IsEmpty())
//	{
//		str_value += request.request_uri.user;
//		str_value += '@';
//	}
//	str_value += request.request_uri.host;
//	if (request.request_uri.port > 0)
//	{
//		str_temp.Format(_T(":%d"), request.request_uri.port);
//		str_value += str_temp;
//	}
//
//	str_value += " SIP/2.0\r\n";
//
//	return str_value;
//}
//
//
//
//BOOL CSipPacket::generate_request_line(CString & request_line, REQUEST_METHOD method, const CString &user,
//	const CString & address, unsigned short port, const CString &parameterl)
//{
//	CString str_method, str_temp;
//
//	switch (method)
//	{
//	case SipRegister:
//		str_method = _T("REGISTER");
//		break;
//	case SipInvite:
//		str_method = _T("INVITE");
//		break;
//	case SipAck:
//		str_method = _T("ACK");
//		break;
//	case SipBye:
//		str_method = _T("BYE");
//		break;
//	default:
//		return FALSE;
//		break;
//	}
//
//	request_line += str_method;
//	request_line += _T(" sip:");
//	if (!user.IsEmpty())
//	{
//		str_temp.Format(_T("%s@"), user);
//		request_line += str_temp;
//	}
//	request_line += address;
//	if (port > 0)
//	{
//		str_temp.Format(_T(":%d"), port);
//		request_line += str_temp;
//	}
//	if (!parameterl.IsEmpty())
//	{
//		str_temp.Format(_T(";%s"), parameterl);
//		request_line += str_temp;
//	}
//	request_line += _T(" SIP/2.0\r\n");
//	//m_request_line = request_line;
//
//	return TRUE;
//}
//
////BOOL CSipPacket::generate_respond_status_line(CString & status_line, RESPOND_STATUS status)
////{
////	CString status_string;
////
////	switch (status)
////	{
////	case trying:
////		status_string.Format(_T("100 Giving a try"));
////		break;
////	case ringing:
////		status_string.Format(_T("180 Ringing"));
////		break;
////	case ok:
////		status_string.Format(_T("200 OK"));
////		break;
////	default:
////		return FALSE;
////		break;
////	}
////
////	status_line.Format(_T("SIP/2.0 "));
////	status_line += status_string;
////	//m_status_line = status_line;
////	return TRUE;
////
////}
//
//CString CSipPacket::generate_via(const CString & sent_address, unsigned short port, const CString & branch, const CString & rport, const CString & received)
//{
//	CString via;
//
//	via.Format(_T("Via: SIP/2.0/UDP %s:%d;branch=%s;rport\r\n"), sent_address, port, branch);
//	//m_via = via;
//
//	return via;
//}
//
//CString CSipPacket::generate_max_forwards(int max_f)
//{
//	CString max_forwards;
//
//	max_forwards.Format(_T("Max-Forwards: %d\r\n"), max_f);
//	//m_max_forwards = max_forwards;
//
//	return max_forwards;
//}
//
//CString CSipPacket::generate_from(const CString & display_name, const CString & sip_user, const CString & sip_address, const CString & tag)
//{
//	CString from;
//
//	from.Format(_T("From: \"%s\"<sip:%s@%s>;tag=%s\r\n"), display_name,
//		sip_user, sip_address, tag);
//	//m_from = from;
//
//	return from;
//}
//
//CString CSipPacket::generate_to(const CString & display_name, const CString & to_name, const CString & to_address, const CString & tag)
//{
//	CString to, temp;
//
//	to.Format(_T("To: "));
//	if (!display_name.IsEmpty())
//	{
//		temp.Format(_T("\"%s\" "), display_name);
//		to += temp;
//	}
//
//	temp.Empty();
//	temp.Format(_T("<sip:%s@%s>"), to_name, to_address);
//	to += temp;
//
//	if (!tag.IsEmpty())
//	{
//		temp.Empty();
//		temp.Format(_T(";tag=%s"), tag);
//		to += temp;
//	}
//
//	to += _T("\r\n");
//	//m_to = to;
//
//	return to;
//
//}
//
//CString CSipPacket::generate_call_id(const CString & call_id)
//{
//	CString str_call_id;
//
//	str_call_id.Format(_T("Call-ID: %s\r\n"), call_id);
//	//m_call_id = str_call_id;
//
//	return str_call_id;
//}
//
//CString CSipPacket::generate_cseq(int cseq, REQUEST_METHOD method)
//{
//	CString str_cseq, str_method;
//
//	switch (method)
//	{
//	case SipRegister:
//		str_method = _T("REGISTER");
//		break;
//	case SipInvite:
//		str_method = _T("INVITE");
//		break;
//	case SipAck:
//		str_method = _T("ACK");
//		break;
//	case SipBye:
//		str_method = _T("BYE");
//		break;
//	default:
//		break;
//	}
//
//	str_cseq.Format(_T("CSeq: %d %s\r\n"), cseq, str_method);
//	//m_cseq = str_cseq;
//
//	return str_cseq;
//}
//
//CString CSipPacket::generate_contact(const CString & name, const CString & address, unsigned short port,
//	const CString & parameter)
//{
//	CString contact, temp;
//
//	contact.Format(_T("Contact: <sip:%s@%s:%d"), name, address, port);
//	if (parameter.IsEmpty())
//	{
//		contact += _T(">\r\n");
//	}
//	else
//	{
//		temp.Format(_T(";rinstance=%s>\r\n"), parameter);
//		contact += temp;
//	}
//	//m_contact = contact;
//
//	return contact;
//}
//
//
////BOOL CSipPacket::build_register_pack(const CString & server_address, const CString & local_address,
////	unsigned short local_port, const CString & username, int invite_cseq)
////{
////	CString pack, line, via_branch, from_tag, str_call_id, str_null;
////
////
////
////	CString request_line;
////	if (!generate_request_line(request_line, SipRegister, str_null, server_address, 0, str_null))
////	{
////		return false;
////	}
////	if (!NewGUIDString(via_branch))
////	{
////		return false;
////	}
////	via_branch.Insert(0, _T("z9hG4bK"));
////	CString via = generate_via(local_address, local_port, via_branch, str_null, str_null);
////	CString max_forwards = generate_max_forwards(70);
////	if (!NewGUIDString(via_branch))
////	{
////		return false;
////	}
////	CString contact = generate_contact(username, local_address, local_port, via_branch);
////	CString to_tag;
////	CString to = generate_to(username, server_address, to_tag);
////	if (!NewGUIDString(from_tag))
////	{
////		return false;
////	}
////	CString from = generate_from(username, username, server_address, from_tag);
////	if (!NewGUIDString(str_call_id))
////	{
////		return false;
////	}
////	CString call_id = generate_call_id(str_call_id);
////	CString cseq = generate_cseq(invite_cseq, SipRegister);
////
////
////	pack += request_line;
////	pack += via;
////	pack += max_forwards;
////	pack += contact;
////	pack += to;
////	pack += from;
////	pack += call_id;
////	pack += cseq;
////	pack += _T("\r\n");
////
////
////	if (pack.GetLength() > 0)
////	{
////		m_data_len = pack.GetLength();
////		m_data = new unsigned char[m_data_len];
////		USES_CONVERSION;
////		char *data = T2A(pack);
////		memcpy(m_data, data, m_data_len);
////	}
////
////	return TRUE;
////}
////
////BOOL CSipPacket::build_invite_pack(const CString call_name, const CString & server_address, const CString & local_address,
////	unsigned short local_port, const CString & username, int invite_cseq, const CString sdp)
////{
////
////	CString packet, via_branch, from_tag, str_call_id, str_null;
////
////
////	CString request_line;
////	if (!generate_request_line(request_line, SipInvite, call_name, server_address, 0, str_null))
////	{
////		return false;
////	}
////
////	//header
////	if (!NewGUIDString(via_branch))
////	{
////		return false;
////	}
////	via_branch.Insert(0, _T("z9hG4bK"));
////	CString via = generate_via(local_address, local_port, via_branch, str_null, str_null);
////	
////	CString max_forwards = generate_max_forwards(70);
////	
////	if (!NewGUIDString(from_tag))
////	{
////		return false;
////	}
////	CString from = generate_from(username, username, server_address, from_tag);
////
////	CString to = generate_to(str_null, server_address, str_null);
////
////	CString contact = generate_contact(username, local_address, local_port, str_null);
////
////	if (!NewGUIDString(str_call_id))
////	{
////		return false;
////	}
////	CString call_id = generate_call_id(str_call_id);
////
////	CString cseq = generate_cseq(invite_cseq, SipInvite);
////
////	//sdp
////	packet += request_line;
////	packet += via;
////	packet += max_forwards;
////	packet += from;
////	packet += to;
////	packet += contact;
////	packet += call_id;
////	packet += cseq;
////	packet += _T("\r\n");
////	packet += sdp;
////
////	if (packet.GetLength() > 0)
////	{
////		m_data_len = packet.GetLength();
////		m_data = new unsigned char[m_data_len];
////		USES_CONVERSION;
////		char *data = T2A(packet);
////		memcpy(m_data, data, m_data_len);
////	}
////
////	return TRUE;
////
////}
////
////BOOL CSipPacket::build_ack_pack(const CString &contact_user, const CString & contact_address,
////	unsigned short contact_port, const CString &contact_rinstance, const CString & server_address, 
////	const CString & local_address, unsigned short local_port, const CString & username, const CString &call_name,
////	int invite_cseq, const CString &from_tag, const CString &to_tag, const CString &call_id)
////{
////	CString string_pack, build_line, random_string, str_null;
////
////	if (!generate_request_line(build_line, SipAck, contact_user, contact_address,
////		contact_port, contact_rinstance))
////	{
////		return false;
////	}
////	string_pack += build_line;
////	//via:
////	if (!NewGUIDString(random_string))
////	{
////		return false;
////	}
////	random_string.Insert(0, _T("z9hG4bK"));
////	build_line.Empty();
////	build_line = generate_via(local_address, local_port, random_string, str_null, str_null);
////	string_pack += build_line;
////
////
////
////	build_line.Empty();
////	build_line = generate_max_forwards(70);
////	string_pack += build_line;
////
////	//to
////	random_string.Empty();
////	build_line.Empty();
////	if (to_tag.IsEmpty())
////	{
////		if (!NewGUIDString(random_string))
////		{
////			return false;
////		}
////	}
////	else
////	{
////		random_string = to_tag;
////	}
////	build_line = generate_to(call_name, server_address, random_string);
////	string_pack += build_line;
////	//from
////	random_string.Empty();
////	build_line.Empty();
////	if (from_tag.IsEmpty())
////	{
////		if (!NewGUIDString(random_string))
////		{
////			return false;
////		}
////	}
////	else
////	{
////		random_string = from_tag;
////	}
////	build_line = generate_from(username, username, server_address, random_string);
////	string_pack += build_line;
////	//call-id
////	random_string.Empty();
////	build_line.Empty();
////	if (call_id.IsEmpty())
////	{
////		if (!NewGUIDString(random_string))
////		{
////			return false;
////		}
////	}
////	else
////	{
////		random_string = call_id;
////	}
////	build_line = generate_call_id(random_string);
////	string_pack += build_line;
////
////	build_line = generate_cseq(invite_cseq, SipAck);
////	string_pack += build_line;
////
////	string_pack += _T("\r\n");
////
////
////	if (string_pack.GetLength() > 0)
////	{
////		m_data_len = string_pack.GetLength();
////		m_data = new unsigned char[m_data_len];
////		USES_CONVERSION;
////		char *data = T2A(string_pack);
////		memcpy(m_data, data, m_data_len);
////	}
////
////	return TRUE;
////
////
////}
//
////CSipPacket * CSipPacket::Clone()
////{
////	return new CSipPacket(*this);
////}
//
////BOOL CSipPacket::set_cseq(int cseq)
////{
////	int num = 0, num_len = 0, i = 0, j = 0;
////	char temp[128] = { 0 }, data_before[1500] = { 0 };
////
////	//得到cseq
////	char *flag = strstr((char *)m_data, "CSeq");
////	if (flag == NULL)
////	{
////		return FALSE;
////	}
////
////	flag += strlen("CSeq: ");
////	i = flag - (char *)m_data;
////	if (i < 0)
////	{
////		i = abs(i);
////	}
////
////	while (*flag != ' ')
////	{
////		if (*flag >= 48 && *flag <= 57)
////		{
////			num = num * 10 + (*flag - 48);
////		}
////		flag++;
////	}
////	num++;
////
////	j = flag - (char *)m_data;
////	if (j < 0)
////	{
////		j = abs(j);
////	}
////
////
////	memcpy(data_before, m_data, i);
////	num_len = sprintf_s(data_before + i, 1500 - i, "%d", num);
////	memcpy(data_before + i + num_len, flag, m_data_len - j);
////
////	m_data_len = i + num_len + m_data_len - j;
////	memcpy(m_data, data_before, m_data_len);
////
////
////	return TRUE;
////}
//
////BOOL CSipPacket::build_packet(CString * str_line, int num)
////{
////
////	return 0;
////}
//
//
//unsigned char * CSipPacket::get_data()
//{
//	unsigned char *data = new unsigned char[m_data_len];
//
//	if (data != NULL)
//		memcpy(data, m_data, m_data_len);
//
//	return data;
//}
//
//int CSipPacket::get_data_len()
//{
//	return m_data_len;
//}
//
//CString CSipPacketInfo::get_content_type()
//{
//	return m_content_type;
//}
//
//int CSipPacketInfo::get_content_length()
//{
//	return 0;
//}
