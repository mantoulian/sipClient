#pragma once

#include "SDP.h"

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

typedef struct via_parameter
{
	CString sent_address;
	unsigned short sent_port;
	CString received_address;
	unsigned short recvived_port;
	CString branch;

}VIA_PARAMETER;

typedef struct from_parameter
{
	CString display_info;
	CString from_user;
	CString from_host;
	CString from_tag;
}FROM_PARAMETER;

typedef struct to_parameter
{
	CString display_info;
	CString to_user;
	CString to_host;
	CString to_tag;
}TO_PARAMETER;

typedef struct contact_parameter
{
	SIP_URI contact_uri;
	CString parameter;
}CONTACT_PARAMETER;

typedef struct cseq_parameter
{
	int cseq;
	REQUEST_METHOD method;
}CSEQ_PARAMETER;

class CSipPacketInfo;


class AFX_EXT_CLASS CSipPacket
{
public:
	CSipPacket();
	~CSipPacket();

	BOOL from_buffer(char * buffer, int buffer_len);

	BOOL build_register_request(CString user_name, CString password, CString server_addr, WORD server_port,
		CString local_addr, WORD local_port, int cseq);
	BOOL builf_invite_request(CString call_name, CString username, CString contact_user,
		CString server_addr, WORD server_port, CString local_addr, WORD local_port, int cseq,
		const CString &str_sdp);
	BOOL builf_ack_request(CSipPacketInfo *inv_status_packet_info, CString local_addr,
		WORD local_port);

	//status
	BOOL build_ok_status(CSipPacketInfo *request_packet, CString local_addr,
		WORD local_portint, CString contact_user, CSDP sdp, STATUS_CODE status_code);

	unsigned char *get_data(int &data_len);

protected:
	 CString generate_status(STATUS_CODE status_parameter);
	 CString generate_request(REQUEST_PARAMETER request_parameter);
	 CString generate_via(VIA_PARAMETER via_parameter);
	 CString generate_from(FROM_PARAMETER from_parameter);
	 CString generate_to(TO_PARAMETER to_parameter);
	 CString generate_contact(CONTACT_PARAMETER contact_parameter);
	 CString generate_max_forwards(int max_forwards);
	 CString generate_call_id(const CString &call_id);
	 CString generate_cseq(CSEQ_PARAMETER cseq_parameter);
	 CString generate_route(CString route);
	 CString generate_record_route(CString route);

	 CString generate_content_type(const CString &content_type);
	 CString generate_content_type_length(int content_length);

	static BOOL NewGUIDString(CString &strGUID);

//void packet_add_line(CString str_line);
	//void build_packet();
	////BOOL FromBuffer(unsigned char *data, unsigned int data_len);
	//BOOL build_register_request(CString str_server_addr, WORD server_port, CString str_local_addr,
	//	WORD local_port, CString username, CString password);
	//BOOL build_invite_request(CString str_server_addr, WORD server_port, CString str_local_addr,
	//	WORD local_port, CString username, CString call_name, unsigned char * sdp, int sdp_len);
	//void build_invite_request(CString request_line, CString via, CString max_forwards, CString from,
	//	CString to, CString contact, CString call_id, CString CSeq, CString sdp);
	//void build_ack_request(CString request_line, CString via, CString max_forwards, CString from,
	//	CString to, CString call_id, CString CSeq);
	//void build_ok_status(CString status_line, CString via, CString max_forwards, CString from,
	//	CString to, CString call_id, CString CSeq, CString sdp_buf);
	////BOOL build_register_request();
	//BOOL build_status_pack(CSipPacket *packet, STATUS_CODE status_code,
	//	unsigned char *content, int content_len);
	//unsigned char* get_data();
	//int get_data_len();
//public:
//	//BOOL build_packet(CString *str_line, int num);
//
//	CString generate_request_line(REQUEST_PARAMETER request);
//
//	//message line
//	BOOL generate_request_line(CString & request_line, REQUEST_METHOD method, const CString &user,
//		const CString &address, unsigned short port, const CString &parameter);
//	// BOOL generate_respond_status_line(CString &status_line, STATUS_CODE status);
//	//message header
//	CString generate_via(const CString &sent_address, unsigned short port,
//		const CString &branch, const CString &rport, const CString &received);
//	CString generate_max_forwards(int max_f);
//	CString generate_from(const CString &display_name, const CString &sip_user,
//		const CString &sip_address, const CString &tag);
//	CString generate_to(const CString & display_name, const CString &to_name,
//		const CString &to_address, const CString &tag);
//	CString generate_call_id(const CString &call_id);
//	CString generate_cseq(int cseq, REQUEST_METHOD method);
//	CString generate_contact(const CString &name, const CString &address, unsigned short port,
//		const CString &parameter);

private:
	unsigned char *m_data;
	unsigned int  m_data_len;
};

class AFX_EXT_CLASS CSipPacketInfo
{
public:
	CSipPacketInfo();
	~CSipPacketInfo();
	BOOL from_packet(CSipPacket *packet);

	MESSAGE_TYPE get_type();
	REQUEST_PARAMETER get_request_para();
	STATUS_CODE get_status_code();
	CString get_call_id();
	FROM_PARAMETER get_from();
	TO_PARAMETER get_to();
	CSEQ_PARAMETER get_cseq();
	int get_max_forwards();

	int get_via_array_length();
	BOOL get_via(VIA_PARAMETER & via_par, int index);
	int get_contact_array_length();
	BOOL get_contact(CONTACT_PARAMETER &contact_par, int index);
	CString get_route();

	CString get_content_type();
	int get_content_length();
	
	CSDP get_sdp_info();
	DWORD get_time();
	void set_time(DWORD time);


public:
	static BOOL viastr_to_viapar(VIA_PARAMETER &via, const CString &string);
	static BOOL request_status_to_parameter(MESSAGE_TYPE & type, STATUS_CODE &status_code,
	 	REQUEST_PARAMETER &request, const CString &string);
	static BOOL fromstr_to_frompar(FROM_PARAMETER & from_par, const CString &string);
	static BOOL tostr_to_topar(TO_PARAMETER &to_par, const CString &string);
	static BOOL contactstr_to_contactpar(CONTACT_PARAMETER &contact_par, const CString &string);
	static BOOL callidstr_to_callid(CString &call_id, const CString &callid_string);
	static BOOL cseqstr_to_cseqpar(CSEQ_PARAMETER &cseq_par, const CString &string);
	static BOOL content_type_string_to_type(CString &content_type, const CString &string);
	static BOOL content_type_length_string_to_length(int &length, const CString &string);
private:
	MESSAGE_TYPE m_type;
	STATUS_CODE m_status_code;
	REQUEST_PARAMETER m_request_parameter;

	CArray<VIA_PARAMETER*, VIA_PARAMETER*> m_array_via;
	CArray<CONTACT_PARAMETER*, CONTACT_PARAMETER*> m_array_contact;

	int m_max_forwards;
	FROM_PARAMETER m_from;
	TO_PARAMETER m_to;
	CString m_call_id;
	CString m_content_type;
	int m_content_length;
	CString m_route;
	CSEQ_PARAMETER m_cseq;
	CSDP m_sdp_info;

	DWORD m_create_time;
	
};
