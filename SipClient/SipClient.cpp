#include "stdafx.h"
#include "SipClient.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define  SERVER_TIMEOUT    2000//sip消息等待时间
#define	 ANSWER_TIMEOUT    60000//对方客户端接听时间
#define  SIP_BUF_SIZE    4096
#define  TEMP_BUF_SIZE		1024



CSipClient::CSipClient()
{
	m_client_status = uninitialized;

	m_call_info = NULL;
	m_send_rtp_cache = NULL;
	m_local_sdp = NULL;
	m_hRecvSipThread = NULL;
	m_hProcessSipThread = NULL;

	m_nRegisterCSeq = 1;
	m_nInviteCSeq = 1;
	m_usServerPort = 0;
	m_bwork = FALSE;
}

CSipClient::~CSipClient()
{
	m_bwork = FALSE;
	m_client_status = uninitialized;
	WaitForSingleObject(m_hRecvSipThread, INFINITE);
	WaitForSingleObject(m_hProcessSipThread, INFINITE);
	CloseHandle(m_hRecvSipThread);
	CloseHandle(m_hProcessSipThread);


}

//初始化
BOOL CSipClient::init(const CString &strServerAddress, unsigned short usServerPort,
	const CString &strLocalAddress, unsigned short usLocalSipPort)
{
	CString strIP;
	unsigned short usPort = 0;

	m_send_rtp_cache = new CRtpPacketCache();
	if (NULL == m_send_rtp_cache)
		return FALSE;
	m_local_sdp = new CSDP();
	if (NULL == m_local_sdp)
		return FALSE;
	m_call_info = new CALL_INFO();
	if (NULL == m_call_info)
		return FALSE;
	//m_call_info->rtp_cache = new CRtpPacketCache();
	//if (NULL == m_call_info->rtp_cache)
	//	return FALSE;

	m_strSipServerAddr = strServerAddress;
	m_usServerPort = usServerPort;
	m_strLocalSipAddr = strLocalAddress;
	//初始化sock
	if (!m_udpSipSock.Create(usLocalSipPort, SOCK_DGRAM))
		return FALSE;
	if (!m_udpSipSock.GetSockName(strIP, usPort))
		return FALSE;
	if (!m_udpSipSock.EnableNonBlocking(TRUE))
		return FALSE;
	m_usLocalSipPort = usPort;

	//创建接收线程
	m_hRecvSipThread = ::CreateThread(NULL, 0, ReceiveSipThread, this, CREATE_SUSPENDED, NULL);
	ASSERT(NULL != m_hRecvSipThread);
	if (NULL == m_hRecvSipThread)
	{
		return FALSE;
	}
	//创建解析sip消息线程
	m_hProcessSipThread = ::CreateThread(NULL, 0, SipPacketProcessThread, this, CREATE_SUSPENDED, NULL);
	ASSERT(NULL != m_hProcessSipThread);
	if (NULL == m_hProcessSipThread)
	{
		return FALSE;
	}

	m_client_status = init_ok;
	m_bwork = TRUE;
	::ResumeThread(m_hRecvSipThread);
	::ResumeThread(m_hProcessSipThread);

	return true;
}

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
//	m_hRecvSipThread = ::CreateThread(NULL, 0, ReceiveSipThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_hRecvSipThread);
//	if (NULL == m_hRecvSipThread)
//	{
//		return FALSE;
//	}
//	//创建解析sip消息线程
//	m_hProcessSipThread = ::CreateThread(NULL, 0, SipPacketProcessThread, this, CREATE_SUSPENDED, NULL);
//	ASSERT(NULL != m_hProcessSipThread);
//	if (NULL == m_hProcessSipThread)
//	{
//		return FALSE;
//	}
//
//	m_client_status = init_ok;
//	m_bwork = TRUE;
//	::ResumeThread(m_hRecvSipThread);
//	::ResumeThread(m_hProcessSipThread);
//
//	return true;
//}



//CSDP CSipClient::get_sdp()
//{
//	return m_sdp;
//}

BOOL CSipClient::register_account(const CString &strUserName, const CString &strPassword)
{
	if (init_ok > m_client_status || m_bwork == FALSE)
		return FALSE;
	
	CSipPacket packet;
	CSipPacketInfo *packet_info = NULL;
	CString strLineData, strGuid;
	CStringArray arrLineData;

	//构建注册消息
	//request-line
	REQUEST_PARAMETER stuRequsetPar;
	stuRequsetPar.method = SipRegister;
	stuRequsetPar.request_uri.host = m_strSipServerAddr;
	stuRequsetPar.request_uri.port = 0;
	stuRequsetPar.request_uri.user = strUserName;
	if (!packet.generate_request_line(strLineData, stuRequsetPar))
		return FALSE;
	arrLineData.Add(strLineData);

	//via
	VIA_PARAMETER stuViaPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuViaPar.branch = _T("z9hG4bK");
	stuViaPar.branch += strGuid;
	stuViaPar.recvived_port = 0;
	stuViaPar.sent_address = m_strLocalSipAddr;
	stuViaPar.sent_port = m_usLocalSipPort;
	strLineData = packet.generate_via_line(stuViaPar);
	arrLineData.Add(strLineData);

	//max forwards
	strLineData = packet.generate_max_forwards_line(70);
	arrLineData.Add(strLineData);

	//contact //联系人 注册时是自己
	CONTACT_PARAMETER stuContactPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuContactPar.contact_uri.host = m_strLocalSipAddr;
	stuContactPar.contact_uri.port = m_usLocalSipPort;
	stuContactPar.contact_uri.user = strUserName;
	stuContactPar.parameter = _T("rinstance");
	stuContactPar.parameter += strGuid;
	strLineData = packet.generate_contact_line(stuContactPar);
	arrLineData.Add(strLineData);

	//to
	TO_PARAMETER stuToPar;
	//if (!packet.NewGUIDString(strGuid))
	//	return FALSE;
	stuToPar.display_info = strUserName;
	stuToPar.to_user = strUserName;
	stuToPar.to_host = m_strSipServerAddr;
	//stuToPar.to_tag = strGuid;
	strLineData = packet.generate_to_line(stuToPar);
	arrLineData.Add(strLineData);

	//from
	FROM_PARAMETER stuFromPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuFromPar.display_info = strUserName;
	stuFromPar.from_user = strUserName;
	stuFromPar.from_host = m_strSipServerAddr;
	stuFromPar.from_tag = strGuid;
	strLineData = packet.generate_from_line(stuFromPar);
	arrLineData.Add(strLineData);

	//call-id
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	strLineData = packet.generate_callid_line(strGuid);
	arrLineData.Add(strLineData);

	//cseq
	CSEQ_PARAMETER stuCSeqPar;
	stuCSeqPar.cseq = m_nRegisterCSeq;
	stuCSeqPar.method = SipRegister;
	if (!packet.generate_cseq_line(strLineData, stuCSeqPar))
		return FALSE;
	arrLineData.Add(strLineData);

	//结束
	arrLineData.Add(_T("\r\n"));

	packet.build_packet(arrLineData);

	//发送
	if (!send_packet(&packet))
		return FALSE;

	//packet info
	packet_info = new CSipPacketInfo();
	if (NULL == packet_info)
		return FALSE;
	if (!packet_info->from_packet(&packet))
		return FALSE;
	//保存信息
	m_strUserName = strUserName;
	m_strPassword = strPassword;

	m_last_send_time = ::GetTickCount();
	packet_info->set_time(m_last_send_time);
	m_request_info_ArrLock.Lock();
	m_arrRequest_PackInfo.Add(packet_info);
	m_request_info_ArrLock.Unlock();

	return TRUE;
}

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

BOOL CSipClient::make_call(const CString &strCallName, BOOL audio_media, WORD audio_port,
	BOOL video_media, WORD video_port)
{
	if (!m_bwork || m_client_status < register_ok)
		return false;

	CSipPacket packet;
	CString addr, str_sdp, strLineData, strGuid;
	CStringArray arrLineData;
	WORD port;
	
	//修改sdp (端口，地址)
	m_local_sdp->set_address(m_strLocalSipAddr);
	m_local_sdp->set_audio_media(audio_media);
	m_local_sdp->set_video_media(video_media);
	if (audio_media)
	{
		m_call_info->udp_audio = new CNetSocket();
		if (NULL == m_call_info->udp_audio)
			return FALSE;
		if (!m_call_info->udp_audio->Create(audio_port, SOCK_DGRAM))
			return FALSE;
		if (!m_call_info->udp_audio->GetSockName(addr, port))
			return FALSE;
		m_local_sdp->set_audio_media(TRUE);
		m_local_sdp->set_audio_port(port);
		m_local_sdp->set_audio_address(m_strLocalSipAddr);
	}
	if (video_media)
	{
		m_call_info->udp_video = new CNetSocket();
		if (NULL == m_call_info->udp_video)
			return FALSE;
		if (!m_call_info->udp_video->Create(video_port, SOCK_DGRAM))
			return FALSE;
		if (!m_call_info->udp_video->GetSockName(addr, port))
			return FALSE;
		m_local_sdp->set_video_media(TRUE);
		m_local_sdp->set_video_port(port);
		m_local_sdp->set_video_address(m_strLocalSipAddr);
	}

	//构建invite消息
	//request-line
	REQUEST_PARAMETER stuRequsetPar;
	stuRequsetPar.method = SipInvite;
	stuRequsetPar.request_uri.host = m_strSipServerAddr;
	stuRequsetPar.request_uri.port = 0;
	stuRequsetPar.request_uri.user = strCallName;
	if (!packet.generate_request_line(strLineData, stuRequsetPar))
		return FALSE;
	arrLineData.Add(strLineData);

	//via
	VIA_PARAMETER stuViaPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuViaPar.branch = _T("z9hG4bK");
	stuViaPar.branch += strGuid;
	stuViaPar.recvived_port = 0;
	stuViaPar.sent_address = m_strLocalSipAddr;
	stuViaPar.sent_port = m_usLocalSipPort;
	strLineData = packet.generate_via_line(stuViaPar);
	arrLineData.Add(strLineData);

	//max forwards
	strLineData = packet.generate_max_forwards_line(70);
	arrLineData.Add(strLineData);

	//contact 
	CONTACT_PARAMETER stuContactPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuContactPar.contact_uri.host = m_strLocalSipAddr;
	stuContactPar.contact_uri.port = m_usLocalSipPort;
	stuContactPar.contact_uri.user = strUserName;
	stuContactPar.parameter = _T("rinstance");
	stuContactPar.parameter += strGuid;
	strLineData = packet.generate_contact_line(stuContactPar);
	arrLineData.Add(strLineData);

	//to
	TO_PARAMETER stuToPar;
	//if (!packet.NewGUIDString(strGuid))
	//	return FALSE;
	stuToPar.display_info = strUserName;
	stuToPar.to_user = strUserName;
	stuToPar.to_host = m_strSipServerAddr;
	//stuToPar.to_tag = strGuid;
	strLineData = packet.generate_to_line(stuToPar);
	arrLineData.Add(strLineData);

	//from
	FROM_PARAMETER stuFromPar;
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	stuFromPar.display_info = strUserName;
	stuFromPar.from_user = strUserName;
	stuFromPar.from_host = m_strSipServerAddr;
	stuFromPar.from_tag = strGuid;
	strLineData = packet.generate_from_line(stuFromPar);
	arrLineData.Add(strLineData);

	//call-id
	if (!packet.NewGUIDString(strGuid))
		return FALSE;
	strLineData = packet.generate_callid_line(strGuid);
	arrLineData.Add(strLineData);

	//cseq
	CSEQ_PARAMETER stuCSeqPar;
	stuCSeqPar.cseq = m_nRegisterCSeq;
	stuCSeqPar.method = SipRegister;
	if (!packet.generate_cseq_line(strLineData, stuCSeqPar))
		return FALSE;
	arrLineData.Add(strLineData);

	//结束
	arrLineData.Add(_T("\r\n"));

	str_sdp = m_local_sdp->to_buffer();
	if (!packet.builf_invite_request(strCallName,m_strUserName, m_strContactUser,  m_strServerIP, m_usServerPort,
		m_strLocalIP, m_usLocalSipPort, m_nInviteCSeq++, str_sdp))
		return FALSE;

	//发送sip消息
	if (!send_sip_packet(&packet))
		return FALSE;

	//需要回应
	CSipPacketInfo *pack_info = new CSipPacketInfo();
	if (!pack_info->from_packet(&packet))
	{
		delete pack_info;
		return FALSE;
	}
	pack_info->set_time(::GetTickCount());
	m_request_info_ArrLock.Lock();
	m_arrRequest_PackInfo.Add(pack_info);
	m_request_info_ArrLock.Unlock();

	//call_info
	m_call_info->call_id = pack_info->get_call_id();
	m_call_info->call_name = strCallName;
	m_call_info->call_status = INVITE_SEND;
	m_client_status = inviteing;
	return TRUE;
}

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

BOOL CSipClient::hangup(const CString &strCallName)
{

	//
	//1,发送bye到服务器
	//build_bye_request()
	//build_ack_request
	//2，拆除 发送和接收 rtp线程
	//3，移除 callinfo

	//m_client_status = register_ok;

	return 0;
}


//sdp协商， 回复ok消息
BOOL CSipClient::call_answer(CSipPacketInfo *packet_info)
{
	if (m_call_info->call_status != INVITE_RECV || NULL == packet_info)
		return FALSE;

	CSipPacket invite_ok_packet;
	CSDP *sdp;
	CString peer_addr;
	WORD peer_port = 0;

	//协商 sdp
	//修改sdp (端口，地址)
	//保存call_info
	sdp = new CSDP();
	*sdp = packet_info->get_sdp_info();
	m_call_info->sdp = sdp;
	m_call_info->call_status = INVITE_SDP_OK;
	m_call_info->call_id = packet_info->get_call_id();
	m_call_info->call_name = packet_info->get_to().to_user;
	

	if (m_call_info->sdp->m_bAudioMedia)
	{
		m_call_info->udp_audio = new CNetSocket();
		if (NULL == m_call_info->udp_audio) return FALSE;
		if (!m_call_info->udp_audio->Create(0, SOCK_DGRAM))
			return FALSE;
		if (!m_call_info->udp_audio->GetSockName(peer_addr, peer_port))
			return FALSE;
		m_local_sdp->m_usAudioPort = peer_port;
		m_local_sdp->m_strAudioIP = m_strLocalIP;

	}

	if (m_call_info->sdp->m_bVideoMedia)
	{
		m_call_info->udp_video = new CNetSocket();
		if (NULL == m_call_info->udp_video) return FALSE;
		if (!m_call_info->udp_video->Create(0, SOCK_DGRAM))
			return FALSE;
		if (!m_call_info->udp_video->GetSockName(peer_addr, peer_port))
			return FALSE;
		m_local_sdp->m_usVideoPort = peer_port;
		m_local_sdp->m_strVideoIP = m_strLocalIP;

	}

	m_local_sdp->m_strAddress = m_strLocalIP;
	m_local_sdp->m_bAudioMedia = FALSE;
	m_local_sdp->m_bVideoMedia = TRUE;
	m_local_sdp->m_strVideoIP = m_strLocalIP;
	m_local_sdp->m_nVideoLoadType = 96;
	m_local_sdp->m_strVideoRtpMap = _T("96 H264/90000");
	m_local_sdp->m_strVideoFmtp = _T("96 packetization-mode=1;profile-level-id=4D002A;sprop-parameter-sets=Z00AKp2oHgCJ+WbgICAgQA==,aO48gA==");



	//m_local_sdp->set_address(m_strLocalIP);
	//m_local_sdp->set_audio_media(sdp->get_audio_media());
	//m_local_sdp->set_video_media(sdp->get_video_media());
	/*if (sdp->get_audio_media())
	{
		m_call_info->udp_audio = new CNetSocket();
		if (NULL == m_call_info->udp_audio)
			return FALSE;
		if (!m_call_info->udp_audio->Create(0, SOCK_DGRAM))
			return FALSE;
		if (!m_call_info->udp_audio->GetSockName(peer_addr, peer_port))
			return FALSE;
		m_local_sdp->set_audio_media(TRUE);
		m_local_sdp->set_audio_port(peer_port);
		m_local_sdp->set_audio_address(m_strLocalIP);
	}*/
	//if (sdp->get_video_media())
	//{
	//	m_call_info->udp_video = new CNetSocket();
	//	if (NULL == m_call_info->udp_video)
	//		return FALSE;
	//	if (!m_call_info->udp_video->Create(0, SOCK_DGRAM))
	//		return FALSE;
	//	if (!m_call_info->udp_video->GetSockName(peer_addr, peer_port))
	//		return FALSE;
	//	//m_local_sdp->set_video_media(TRUE);
	//	m_local_sdp->set_video_port(peer_port);
	//	//m_local_sdp->set_video_address(m_strLocalIP);
	//}

	//if (!m_call_info->udp_audio.Create(0, SOCK_DGRAM))
	//	return FALSE;
	//if (!m_call_info->udp_audio.GetSockName(peer_addr, peer_port))
	//	return FALSE;
	//m_local_sdp
	//if (!m_call_info->udp_audio.Create(0, SOCK_DGRAM))
	//	return FALSE;
	////m_local_sdp->set_audio_media(sdp.get_audio_media());
	//m_local_sdp->set_audio_media(FALSE);
	//m_local_sdp->set_video_media(sdp.get_video_media());

	//回复ok消息
	if (!invite_ok_packet.build_ok_status(packet_info, m_strLocalIP, m_usLocalSipPort,
		m_strContactUser, *m_local_sdp, ok))
		return FALSE;
	if (!send_sip_packet(&invite_ok_packet))
		return FALSE;


	return TRUE;
}

BOOL CSipClient::start_rtp_transport(CSipPacketInfo * packet_info)
{
	//启动发送接收线程
	if (NULL == m_call_info->send_handle)
	{
		m_call_info->send_handle = ::CreateThread(NULL, 0, send_rtp_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_call_info->send_handle)
			return FALSE;
	}
	if (NULL == m_call_info->recv_handle)
	{
		m_call_info->recv_handle = ::CreateThread(NULL, 0, recv_rtp_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_call_info->recv_handle)
			return FALSE;

	}
	::ResumeThread(m_call_info->send_handle);
	::ResumeThread(m_call_info->recv_handle);


	return TRUE;
}

void CSipClient::set_coming_call_function(incoming_call_back function)
{
	m_incoming_call = function;
}

void CSipClient::set_send_cache(CRtpPacketCache * cache)
{
	m_send_rtp_cache = cache;
}

void CSipClient::set_recv_cache(CRtpPacketCache * cache)
{
	m_call_info->rtp_cache = cache;
}

void CSipClient::set_local_sdp(const CSDP & sdp)
{
	if (NULL != m_local_sdp)
	{
		*m_local_sdp = sdp;
		m_local_sdp->set_address(m_strLocalIP);
		m_local_sdp->set_audio_address(m_strLocalIP);
		m_local_sdp->set_video_address(m_strLocalIP);

	}
}

void CSipClient::coming_call_back(CSipPacketInfo *packet)
{
	//保存
	call_answer(packet);
}


CLIENT_STATUS CSipClient::get_client_status()
{
	return m_client_status;
}

CSDP CSipClient::get_local_sdp()
{
	return *m_local_sdp;
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
	char * pBuffer = new char [SIP_BUF_SIZE];
	int nCheckResult = 0, ret = 0;
	CString strPeerIP;
	WORD uPeerPort = 0;

	while (m_bwork)
	{
		nCheckResult = m_udpSipSock.CheckReceive();
		if (nCheckResult > 0)
		{
			ret = m_udpSipSock.ReceiveFrom(pBuffer, SIP_BUF_SIZE, strPeerIP, uPeerPort);
			if (ret > 0 && uPeerPort == m_usServerPort
				&& strPeerIP.CompareNoCase(m_strServerIP) == 0)
			{
				CSipPacket *pack = new CSipPacket;
				if (pack)
				{
					if (pack->from_buffer(pBuffer, ret))
					{
						m_respond_ArrLock.Lock();
						m_arrRespondPack.Add(pack);
						m_respond_ArrLock.Unlock();
					}

				}

			}
		}
	}

	delete [] pBuffer;


	return 0;
}

DWORD CSipClient::DoSipPacketProcess()
{
	CSipPacket *packet = NULL;
	CSipPacketInfo *packet_info = NULL;
	DWORD proc_time = 0;

	while (m_bwork)
	{
		m_respond_ArrLock.Lock();
		if (m_arrRespondPack.GetSize() > 0)
		{
			packet = m_arrRespondPack[0];
			m_arrRespondPack.RemoveAt(0);
		}
		m_respond_ArrLock.Unlock();


		if (packet != NULL)
		{
			proc_sip_mess(packet);
			delete packet;
			packet = NULL;
		}
		else
		{
			//处理request info 队列
			//m_request_info_ArrLock.Lock();
			//if (m_arrRequest_PackInfo.GetSize() > 0)
			//{
			//	packet_info = m_arrRequest_PackInfo[0];
			//	if (NULL != packet_info)
			//	{
			//		proc_time = ::GetTickCount();
			//		if (proc_time - packet_info->get_time() > SERVER_TIMEOUT)
			//		{
			//			delete packet_info;
			//			m_arrRequest_PackInfo.RemoveAt(0);
			//		}

			//	}
			//}
			//m_request_info_ArrLock.Unlock();
			//
			//Sleep(10);
		}
	}

	return 0;

}

//发送ack ， 收发rtp
BOOL CSipClient::invite_ok_process(CSipPacketInfo *pack_info)
{
	if (pack_info == NULL)
		return FALSE;


	//sdp
	if (NULL == m_call_info->sdp)
		m_call_info->sdp = new CSDP();
	if (NULL == m_call_info->sdp)
		return FALSE;
	*(m_call_info->sdp) = pack_info->get_sdp_info();

	//send ack
	CSipPacket ack_pack;
	if (!ack_pack.builf_ack_request(pack_info, m_strLocalIP, m_usLocalSipPort))
		return FALSE;
	if (!send_sip_packet(&ack_pack))
		return FALSE;
	//发送rtp线程
	if (NULL == m_call_info->send_handle)
	{
		m_call_info->send_handle = ::CreateThread(NULL, 0, send_rtp_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_call_info->send_handle)
		{
			return FALSE;
		}
		::ResumeThread(m_call_info->send_handle);

	}

	if (NULL == m_call_info->recv_handle)
	{
		m_call_info->recv_handle = ::CreateThread(NULL, 0, recv_rtp_thread, this, CREATE_SUSPENDED, NULL);
		if (NULL == m_call_info->recv_handle)
		{
			return FALSE;
		}
		::ResumeThread(m_call_info->recv_handle);

	}


	return TRUE;
}

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


BOOL get_md5_hash(const BYTE * pbData, int nDataLen, CString &strMd5Hash)
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


BOOL get_nonce(CSipPacket *pPacket, CString &strNonce)
{
	if (NULL == pPacket)
		return FALSE;

	int nDataLen = 0, i = 0;
	unsigned char * pPacketData = pPacket->get_data(nDataLen);
	char szBuf[128] = { 0 };

	if (NULL == pPacketData)
		return FALSE;

	char * pFlag = strstr((char *)pPacketData, "nonce");
	if (NULL == pFlag)
		return FALSE;
	pFlag += strlen("nonce=\"");

	while (i<128)
	{
		if (pFlag[i] == '\"')
			break;
		szBuf[i] = pFlag[i];
		i++;
	}
	strNonce = szBuf;

	return TRUE;
}

BOOL register_authenticate(CSipPacket *pRecvPacket)
{
	CString strNonce;
	CSipPacket Packet;


	if (!get_nonce(pRecvPacket, strNonce))
		return FALSE;

	Packet.build_register_request()


	return FALSE;
}


//#define FROM_NAME_SIZE 128
void CSipClient::proc_sip_mess(CSipPacket *pack)
{
	if (pack == NULL)
		return;

	CSipPacketInfo recv_packet_info, *send_packet_info;
	BOOL find_request = FALSE, remove_request = FALSE;
	MESSAGE_TYPE type;
	//CString recv_branch;


	if (!recv_packet_info.from_packet(pack))
		return;

	type = recv_packet_info.get_type();
	if (type == sip_request)
	{
		REQUEST_PARAMETER request = recv_packet_info.get_request_para();
		if (SipInvite == request.method)//收到来电
		{
			//保存sdp 发送ok
			if (register_ok == m_client_status)
			{
				m_call_info->call_status = INVITE_RECV;

				if (NULL != m_incoming_call)
					m_incoming_call(&recv_packet_info);
			}
		}
		else if (SipAck == request.method)
		{
			//发送rtp
			if (m_call_info->call_id == recv_packet_info.get_call_id() &&
				m_call_info->call_status == INVITE_SDP_OK)
			{
				m_call_info->call_status = INVITE_ACK_OK;
				start_rtp_transport(&recv_packet_info);
			}
		}
	}
	else
	{
		VIA_PARAMETER via_par, send_via_par;
		if (!recv_packet_info.get_via(via_par, 0))
			return;
		int i = 0;
		m_request_info_ArrLock.Lock();
		for (i = 0; i < m_arrRequest_PackInfo.GetSize(); i++)
		{
			send_packet_info = m_arrRequest_PackInfo.GetAt(i);
			if (send_packet_info )
			{
				if (send_packet_info->get_via(send_via_par, 0))
				{
					if (send_via_par.branch == via_par.branch)
					{
						find_request = TRUE;
						break;
					}
				}

			}
		}
		if (find_request)
		{
			STATUS_CODE status_code = recv_packet_info.get_status_code();
			REQUEST_METHOD method = send_packet_info->get_request_para().method;
			if (method  == SipRegister)
			{
				if (status_code == 200)
				{
					if (m_client_status == init_ok)
					{
						CONTACT_PARAMETER contact_par;
						if (send_packet_info->get_contact(contact_par, 0))
							m_strContactUser = contact_par.contact_uri.user;
						m_client_status = register_ok;
						remove_request = TRUE;
					}
				}
				else if (status_code == 401)
				{
					register_authenticate();
				}
			}
			else if (method == SipInvite)
			{
				if (status_code == 200)
				{
					if (m_client_status == inviteing &&
						recv_packet_info.get_call_id() == m_call_info->call_id)
					{
						if (invite_ok_process(&recv_packet_info))
						{
							m_client_status = calling;
							remove_request = TRUE;
						}
						else
							m_client_status = register_ok;
						
					}
				}
			}

			if (remove_request)
			{
				if (send_packet_info != NULL)
				{
					delete send_packet_info;
					send_packet_info = NULL;
				}

				m_arrRequest_PackInfo.RemoveAt(i);
			}

		}
		m_request_info_ArrLock.Unlock();
	}

	return;
}

DWORD CSipClient::send_rtp_thread(LPVOID lpParam)
{
	CSipClient *pObject = (CSipClient*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->do_send_rtp();
}

DWORD CSipClient::recv_rtp_thread(LPVOID lpParam)
{
	CSipClient *pObject = (CSipClient*)lpParam;
	ASSERT(NULL != pObject);
	return pObject->do_recv_rtp();
}

DWORD CSipClient::do_send_rtp()
{
	int ret = 0;
	CRtpPacketPtr rtp_pack = NULL;
	CString audio_address, video_address, sdp_address;
	unsigned short audio_port = 0, video_port = 0;
	BOOL bAudio, bVideo;

	if (NULL == m_call_info->sdp )
		return 1;

	bAudio = m_call_info->sdp->get_audio_media();
	bVideo = m_call_info->sdp->get_video_media();
	audio_address = m_call_info->sdp->get_audio_address();
	video_address = m_call_info->sdp->get_video_address();
	audio_port = m_call_info->sdp->get_audio_port();
	video_port = m_call_info->sdp->get_video_port();
	sdp_address = m_call_info->sdp->get_address();
	if (audio_address.IsEmpty())
		audio_address = sdp_address;
	if (video_address.IsEmpty())
		video_address = sdp_address;
	


	while (m_bwork)
	{
		if (NULL != m_send_rtp_cache)
			rtp_pack = m_send_rtp_cache->GetNextPacket();
		if (rtp_pack)
		{
			if (rtp_pack->enType == audio && bAudio )
			{
				ret = m_call_info->udp_audio->SendTo(rtp_pack->szData, rtp_pack->usPackLen,
					audio_port, audio_address);
				if (ret < 0)
					int err = WSAGetLastError();

			}
			else if (rtp_pack->enType == video && bVideo )
			{
				ret = m_call_info->udp_video->SendTo(rtp_pack->szData, rtp_pack->usPackLen,
					video_port, video_address);
				if (ret < 0)
					int err = WSAGetLastError();
			}
		}
		else
		{
			Sleep(10);
		}
	}




	return 0;
}

#define RTP_BUFFER	4096
DWORD CSipClient::do_recv_rtp()
{
	int ret = 0;
	CString recv_addr;
	WORD recv_port;
	unsigned char *buf= new unsigned char [RTP_BUFFER];
	CRtpPacketPtr rtp_pack = NULL;
	CString audio_address, video_address, sdp_address;
	unsigned short audio_port = 0, video_port = 0;
	BOOL bAudio, bVideo;

	if (NULL == m_call_info->sdp)
		return 1;
	bAudio = m_local_sdp->get_audio_media();
	bVideo = m_local_sdp->get_video_media();
	audio_address = m_call_info->sdp->get_audio_address();
	video_address = m_call_info->sdp->get_video_address();
	audio_port = m_call_info->sdp->get_audio_port();
	video_port = m_call_info->sdp->get_video_port();
	sdp_address = m_call_info->sdp->get_address();
	if (audio_address.IsEmpty())
		audio_address = sdp_address;
	if (video_address.IsEmpty())
		video_address = sdp_address;

	while (m_bwork)
	{
		if (bAudio)
		{
			ret = m_call_info->udp_audio->ReceiveFrom(buf, RTP_BUFFER, recv_addr, recv_port);
			if (ret > 0 && recv_port == audio_port &&
				recv_addr.Compare(audio_address) == 0)
			{
				rtp_pack = new RTP_PACKET;
				memcpy(rtp_pack->szData, buf, ret);
				rtp_pack->usPackLen = ret;
				rtp_pack->enType = audio;
				if (m_call_info->rtp_cache)
					m_call_info->rtp_cache->AddPacket(rtp_pack);
			}

		}

		if (bVideo)
		{
			ret = m_call_info->udp_video->ReceiveFrom(buf, RTP_BUFFER, recv_addr, recv_port);
			if (ret > 0 && recv_port == video_port
				&& recv_addr.Compare(video_address) == 0)
			{
				rtp_pack = new RTP_PACKET;
				memcpy(rtp_pack->szData, buf, ret);
				rtp_pack->usPackLen = ret;
				rtp_pack->enType = video;
				if (m_call_info->rtp_cache)
					m_call_info->rtp_cache->AddPacket(rtp_pack);
			}
		}
	}


	delete [] buf;
	buf = NULL;

	//FILE *sdp_file = fopen("sip.sdp","w+");
	//if (NULL == sdp_file)
	//	return 0;
	//CString str_sdp = m_sdp.to_buffer();
	//USES_CONVERSION;
	//char * sdp_buf = T2A(str_sdp);
	//if (NULL == sdp_buf)
	//	return 0;
	//int sdp_buf_len = str_sdp.GetLength();
	//int write_len = fwrite(sdp_buf, sdp_buf_len, 1, sdp_file);
	//fflush(sdp_file);

	return 0;
}

//向服务器发送sip消息
BOOL CSipClient::send_packet(CSipPacket *pack)
{
	if (pack == NULL)
		return FALSE;
	CString strData = pack->get_packet_data();
	if (strData.IsEmpty())
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
	}


	return TRUE;

}



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
//CString CSipPacket::generate_request_line(REQUEST_PARAMETER request)
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
