#pragma once
#include "RtspClient.h"
#include "SipPacket.h"



typedef enum call_status
{
	INVITE_START,//发送或接收invite消息之前
	INVITE_SEND,//发送invite消息后
	INVITE_RECV,//收到invite消息后（来电）
	INVITE_SDP_OK,//收到或者发送200ok 消息之后
	INVITE_ACK_OK,//收到或者发送ack消息之后
	INVITE_CALLING,//通话中
	INVITE_DISCONNECTED	//通话结束
}CALL_STATUS;

typedef enum client_status
{
	uninitialized,
	init_ok,
	//register_ok,
	wait,
	inviteing,
	calling,
}CLIENT_STATUS;

typedef int(*incoming_call_back)( CSipPacketInfo *packet_info);


//typedef struct call_info
//{
//	CALL_STATUS sta;
//	CString id;
//	CString name;
//	CSDP *sdp;
//	CSDP *local_sdp;
//	CNetSocket udp_a;
//	CNetSocket udp_v;
//	HANDLE send_handle;
//	HANDLE recv_handle;
//	CRtpPacketCache *rtp_cache;
//}CALL_INFO;



class AFX_EXT_CLASS CSipClient
{
public:
	CSipClient();
	~CSipClient();


	BOOL init(const CString &username, const CString &passwd, const CString &sev_addr, WORD sev_port,
		WORD l_sip_port = 0, WORD l_a_port = 0, WORD l_v_port = 0);
	BOOL register_account();
	BOOL make_call(const CString &strCallName);

	BOOL hangup(CSipPacketInfo *packet_info);
	BOOL call_answer(CSipPacketInfo *packet_info);

	
	void set_send_cache(CRtpPacketCache *cache);
	CRtpPacketCache * get_recv_cache();

	void set_coming_call_function(incoming_call_back function);
	CLIENT_STATUS get_client_status();

	BOOL set_local_sdp(const CSDP &sdp);
	CSDP get_sdp();


protected:

	BOOL send_packet(CSipPacket *packet);
	CSipPacket* recv_packet();
private:
	static DWORD WINAPI ReceiveSipThread(LPVOID lpParam);
	static DWORD WINAPI SipPacketProcessThread(LPVOID lpParam);
	DWORD DoReceiveSip();
	DWORD DoSipPacketProcess();
	void proc_sip_mess(CSipPacket *sipMess);//解析收到的sip消息
	BOOL invite_ok_process(CSipPacketInfo *sipMess);//解析 invite ok

	static DWORD WINAPI send_media_thread(LPVOID lpParam);
	static DWORD WINAPI recv_media_thread(LPVOID lpParam);
	DWORD do_send_media();
	DWORD do_recv_media();

	int find_send_pack_index(CSipPacket *pack);
	BOOL packet_add_auth(CSipPacket *packet, const CString &realm, const CString &nonce, CSEQ_PARAMETER cseq);
	//BOOL remove_binding(CSipPacket *pack);
	//BOOL add_authenticate();


private:
	CMutex		m_recv_lock;
	CTypedPtrArray<CPtrArray, CSipPacket*> m_recv_arr;
	CMutex		m_send_lock;
	CTypedPtrArray<CPtrArray, CSipPacket*> m_send_arr;

	//user
	CString m_user;
	CString m_password;
	CString m_call_name;
	//server
	CString m_sev_addr;
	unsigned short m_sev_port;
	CString m_local_addr;
	WORD m_l_sip_port;
	WORD m_l_a_port;
	WORD m_l_v_port;

	//socket
	CMutex		m_sock_lock;
	CNetSocket m_sock;
	CNetSocket m_sock_a;
	CNetSocket m_sock_v;
	//cache
	CRtpPacketCache *m_send_cache;
	CRtpPacketCache *m_recv_cache;
	//handle
	HANDLE m_recv_h;//接收sip
	HANDLE m_proc_h;//解析sip
	HANDLE m_send_rtp_h;
	HANDLE m_recv_rtp_h;

	//sip
	int m_reg_cseq;
	int m_inv_cseq;
	int m_ack_cseq;
	int m_auth_count; //认证次数
	BOOL m_remove_binding; //取消绑定
	//clinet
	CLIENT_STATUS m_client_status;
	BOOL m_bwork;
	incoming_call_back m_incoming_call;
	//call
	CALL_STATUS m_call_stu;
	CString m_call_id;
	CSDP *m_sdp;
	CSDP *m_local_sdp;
};


/*

//被邀请，发送try
BOOL BuildTryingMess(SIP_MESSAGE &sipMess);

//sdp成功 发送ok
BOOL BuildOKMess(SIP_MESSAGE &sipMess);

BOOL BuildRegisterMess(SIP_MESSAGE *pSipMess, CString strUserName, CString strPassword,
CString strServerIP, CString strLocalIP, unsigned short usLocalSipPort, int nRegisterCSeq,
CString pViaBranch, CString pContactInstance, CString pFromTag, CString pCallId);

BOOL BuildInviteMess(SIP_MESSAGE  *sipMess, CString strCallName, CString strServerIP,
CString strLocalIP, unsigned short usLocalSipPort, CString strUserName, CString strViaBranch,
CString strFromTag, CString strCallId, int nInvCSeq, SDP_INFO *pSdpInfo);

BOOL BuildAckMess(SIP_MESSAGE *pSipMess, CString strUserName, CString strCallName,
CString strServerIP, CString strLocalIP, unsigned short usLocalSipPort, int nInviteCSeq,
CString strViaBranch, CString strFromTag, CString strCallId);

BOOL BuildByeMess(SIP_MESSAGE *pSipMess, CString strUserName, CString strCallName,
CString strServerIP, CString strLocalIP, unsigned short usLocalSipPort, int nInviteCSeq,
CString strViaBranch, CString strFromTag, CString strCallId);*/


//CMutex		m_CallInfoArrLock;
//CTypedPtrArray<CPtrArray, CALL_INFO*> m_arrCallInfo;//call info 队列
//CMutex m_StatusLock;
//bool m_bWork;
//REGISTER_STATUS m_workStatus;//客户端注册状态

//typedef enum sip_respond_status
//{
//	unknown_status = -1,
//	trying = 100,
//	ringing = 180,
//	sip_ok = 200,
//	bad_request = 400,
//	request_timeout = 408,
//}SIP_RESPOND_STATUS;

//typedef enum invite_status
//{
//
//}INVITE_STATUS;

//typedef struct sip_sdp_info
//{
//	CString strIP;
//	//音频
//	BOOL bAudioMedia;
//	unsigned short usAudioPort;
//	CString strAudioIP;
//	int nAudioLoadType;
//	CString strAudioRtpMap;
//	CString strAudioFmtp;
//	//视频
//	BOOL bVideoMedia;
//	unsigned short usVideoPort;
//	CString strVideoIP;
//	int nVideoLoadType;
//	CString strVideoRtpMap;
//	CString strVideoFmtp;
//}SIP_SDP_INFO;

//typedef struct request_info
//{
//	SIP_METHOD emMethod;
//	CString strViaBranch;
//	CString strCallId;
//	CString strCallName;
//
//
//	//CString strFromTag;
//	//SDP_INFO *sdp;//对方
//	//HANDLE hSendMediaThread;
//	//HANDLE hRecvMediaThread;
//	//CString strIP;
//	//unsigned short usSendAudioPort;
//	//unsigned short usSendVideoPort;
//	//unsigned short usRecvAudioPort;
//	//unsigned short usRecvVideoPort;
//	//CNetSocket *udpSockRecvAudio;//接收音频
//	//CNetSocket *udpSockRecvVideo;//接收视频
//	//CNetSocket *udpSockSendAudio;//发送音频
//	//CNetSocket *udpSockSendVideo;//发送视频
//	//CString strViaBranch;
//	//CString strContactInfo;
//	//CString strToTag;
//	//CString strRoute;
//	//CString strContactInstance;
//	//CRtpPacketCache *rtpCache;
//}REQUEST_INFO;

//typedef struct CallInfo
//{
//	//
//	BOOL bCalling;
//	CString strCallName;
//	CString strCallId;
//	SDP_INFO *pLocalSdp;
//	SDP_INFO *pSdp;
//	CNetSocket *udpRecvAudio;//接收音频
//	CNetSocket *udpRecvVideo;//接收视频
//	HANDLE hSendMediaThread;
//	HANDLE hRecvMediaThread;
//	CRtpPacketCache *rtpRecvCache;
//
//
//
//	//CRtpPacketCache *rtpSendCache;
//	//CString strViaBranch;
//	//CString strFromTag;
//	//CString strContactInstance;
//	//CString strContactInfo;
//	//CString strToTag;
//	//CString strRoute;
//	//unsigned short usRecvAudioPort;
//	//unsigned short usRecvVideoPort;
//	//
//	//CString strCallIP;
//	//unsigned short usSendAudioPort;
//	//unsigned short usSendVideoPort;
//	//unsigned short usRecvAudioPort;
//	//unsigned short usRecvVideoPort;
//	//CNetSocket *udpSendAudio;//发送音频
//	//CNetSocket *udpSendVideo;//发送视频
//
//
//}CALL_INFO;

/*
typedef enum message_type
{
sip_request,
sip_status
}MESSAGE_TYPE;

typedef enum request_method
{
other_method = -1,
SipRegister,
SipInvite,
SipAck,
SipBye,
}REQUEST_METHOD;

typedef enum status_code
{
other_status = -1,
trying = 100,
ringing = 180,
ok = 200
}STATUS_CODE;

typedef enum client_status
{
uninitialized,
init_ok,
register_ok,
inviteing,
calling,
}CLIENT_STATUS;

//typedef enum sip_head_key
//{
//	via,
//	max_forward,
//	to,
//	from,
//	contact,
//	cseq,
//	call_id
//}SIP_HEAD_KEY;

//typedef enum call_status
//{
//	INVITE_START,//发送或接收invite消息之前
//	INVITE_SEND,//发送invite消息后
//	INVITE_RECV,//收到invite消息后（来电）
//	INVITE_SDP_OK,//收到或者发送200ok 消息之后
//	INVITE_ACK_OK,//收到或者发送ack消息之后
//	INVITE_CALLING,//通话中
//	INVITE_DISCONNECTED	//通话结束
//}CALL_STATUS;

//typedef struct call_info
//{
//	CALL_STATUS call_status;
//	CString call_name;
//	CString call_id;
//	unsigned short local_audio_port;
//	unsigned short local_video_port;
//	SDP_INFO *sdp_info;
//	CNetSocket audio_socket;
//	CNetSocket video_socket;
//	HANDLE RecvRtpThread;//接收rtp
//	HANDLE SendRtpThread;//发送rtp
//	CRtpPacketCache *rtp_cache;
//
//}CALL_INFO;

typedef struct sip_uri
{
CString user;
CString host;
unsigned short port;
}SIP_URI;

typedef struct request_parameter
{
REQUEST_METHOD method;
SIP_URI request_uri;
}REQUEST_PARAMETER;

//typedef struct status_line
//{
//	RESPOND_STATUS status_code;
//}STATUS_LINE;

typedef struct sip_via
{
CString sent_address;
unsigned short sent_port;
CString received_address;
unsigned short recvived_port;
CString branch;

}SIP_VIA;

//typedef struct sip_max_forwards
//{
//	int forwards;
//}SIP_MAX_FORWARDS;

typedef struct sip_from
{
CString display_info;
CString from_user;
CString from_host;
CString from_tag;
}SIP_FROM;

typedef struct sip_to
{
CString display_info;
CString to_user;
CString to_host;
CString to_tag;
}SIP_TO;

typedef struct sip_contact
{
SIP_URI contact_uri;
CString parameter;
}SIP_CONTACT;

typedef struct sip_cseq
{
int cseq;
REQUEST_METHOD method;
}SIP_CSEQ;

class AFX_EXT_CLASS CSipPacket
{
public:
CSipPacket();
CSipPacket(unsigned int packet_length);
~CSipPacket();

BOOL FromBuffer(unsigned char *data, int data_len);

void build_register_pack(CString request_line, CString via, CString max_forwards, CString from,
CString to, CString contact, CString call_id, CString CSeq);

void build_invite_pack(CString request_line, CString via, CString max_forwards, CString from,
CString to, CString contact, CString call_id, CString CSeq, CString sdp);

void build_ack_pack(CString request_line, CString via, CString max_forwards, CString from,
CString to, CString call_id, CString CSeq);

void build_ok_pack(CString status_line, CString via, CString max_forwards, CString from,
CString to, CString call_id, CString CSeq, CString sdp_buf);


unsigned char* get_data();
int get_data_len();

//BOOL set_cseq(int cseq);
//BOOL build_register_pack(CString str_username, CString str_password,
//	CString server_addr, unsigned short server_port,
//	CString sent_addr, unsigned short sent_port);
//BOOL build_register_pack(REQUEST_LINE request_line, SIP_VIA *via, int via_num,
//	int max_forwards, SIP_FROM from, SIP_TO to, SIP_CONTACT *contact, int contact_num,
//	CString call_id, SIP_CSEQ CSeq);


public:
//BOOL build_packet(CString *str_line, int num);

CString generate_request_line(REQUEST_PARAMETER request);

//message line
//BOOL generate_request_line(CString & request_line, REQUEST_METHOD method, const CString &user,
//const CString &address,unsigned short port, const CString &parameter);
BOOL generate_respond_status_line(CString &status_line, RESPOND_STATUS status);
//message header
CString generate_via(const CString &sent_address, unsigned short port,
const CString &branch, const CString &rport, const CString &received);
CString generate_max_forwards(int max_f);
CString generate_from(const CString &display_name, const CString &sip_user,
const CString &sip_address, const CString &tag);
CString generate_to(const CString & display_name, const CString &to_name,
const CString &to_address, const CString &tag);
CString generate_call_id(const CString &call_id);
CString generate_cseq(int cseq, REQUEST_METHOD method);
CString generate_contact(const CString &name, const CString &address, unsigned short port,
const CString &parameter);

private:
unsigned char *m_data;
unsigned int m_data_len;
};

class AFX_EXT_CLASS CSipPacketInfo
{
public:
CSipPacketInfo();
~CSipPacketInfo();
BOOL from_packet(CSipPacket * packet);

MESSAGE_TYPE get_type();
REQUEST_PARAMETER get_request_line();
STATUS_CODE get_status_line();

CString get_call_id();
SIP_FROM get_from();
SIP_TO get_to();
SIP_CSEQ get_cseq();
int get_max_forwards();
int get_via_array_length();
SIP_VIA get_via(int index);
int get_contact_array_length();
SIP_CONTACT get_contact(int index);
CString get_content_type();
int get_content_length();

CSDP get_sdp_info();


//BOOL from_packet(CSipPacket *packet);
//REQUEST_METHOD get_method();
//RESPOND_STATUS get_status();
//CString get_via_branch();
//CString get_from_tag();
//CString get_to_tag();
//CString get_call_id();
//CString get_contact_rinstance();
//CString get_contact_user();
//CString get_contact_address();
//int get_contact_port();
//int get_cseq();

private:
MESSAGE_TYPE m_type;
REQUEST_PARAMETER m_request_parameter;
STATUS_CODE m_status_code;

SIP_FROM m_from;
SIP_TO m_to;
SIP_CSEQ m_cseq;
int m_max_forwards;
CString m_call_id;
CArray<SIP_VIA, SIP_VIA&> m_array_via;
CArray<SIP_CONTACT, SIP_CONTACT&> m_array_contact;
CString  m_content_type;
int    m_content_length;

CSDP m_sdp;



/*
MESSAGE_TYPE m_type;

CString m_status_line;
RESPOND_STATUS m_status;

CString m_request_line;
REQUEST_METHOD m_method;

CString m_via;
CString m_via_branch;

CString m_max_forwards;

CString m_from;
CString m_from_name;
CString m_from_tag;

CString m_to;
CString m_to_tag;

CString m_call_id;
CString m_call_id_value;

CString m_contact;
CString m_contact_user;
CString m_contact_address;
unsigned short  m_contact_port;
CString m_contact_rinstance;

CString m_cseq;
int m_cseq_value;

CSDP m_sdp_info;
}

//typedef enum sip_head_key
//{
//	via,
//	max_forward,
//	to,
//	from,
//	contact,
//	cseq,
//	call_id
//}SIP_HEAD_KEY;

//typedef enum call_status
//{
//	INVITE_START,//发送或接收invite消息之前
//	INVITE_SEND,//发送invite消息后
//	INVITE_RECV,//收到invite消息后（来电）
//	INVITE_SDP_OK,//收到或者发送200ok 消息之后
//	INVITE_ACK_OK,//收到或者发送ack消息之后
//	INVITE_CALLING,//通话中
//	INVITE_DISCONNECTED	//通话结束
//}CALL_STATUS;

//typedef struct call_info
//{
//	CALL_STATUS call_status;
//	CString call_name;
//	CString call_id;
//	unsigned short local_audio_port;
//	unsigned short local_video_port;
//	SDP_INFO *sdp_info;
//	CNetSocket audio_socket;
//	CNetSocket video_socket;
//	HANDLE RecvRtpThread;//接收rtp
//	HANDLE SendRtpThread;//发送rtp
//	CRtpPacketCache *rtp_cache;
//
//}CALL_INFO;

//typedef struct status_line
//{
//	RESPOND_STATUS status_code;
//}STATUS_LINE;
//typedef struct sip_max_forwards
//{
//	int forwards;
//}SIP_MAX_FORWARDS;

*/




