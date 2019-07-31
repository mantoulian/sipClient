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

	//BOOL from_buffer(char * buffer, int buffer_len);
	//BOOL build_register_request(CString user_name, CString password, CString server_addr, WORD server_port,
	//	CString local_addr, WORD local_port, int cseq);
	//BOOL builf_invite_request(CString call_name, CString username, CString contact_user,
	//	CString server_addr, WORD server_port, CString local_addr, WORD local_port, int cseq,
	//	const CString &str_sdp);
	//BOOL builf_ack_request(CSipPacketInfo *inv_status_packet_info, CString local_addr,
	//	WORD local_port);
	////status
	//BOOL build_ok_status(CSipPacketInfo *request_packet, CString local_addr,
	//	WORD local_portint, CString contact_user, CSDP sdp, STATUS_CODE status_code);
	//unsigned char *get_data(int &data_len);

	 BOOL generate_status_line(CString &strStatusLine, STATUS_CODE status_parameter);
	 BOOL generate_request_line(CString &strRequestLine, REQUEST_PARAMETER request_parameter);
	 CString generate_via_line(VIA_PARAMETER via_parameter);
	 CString generate_from_line(FROM_PARAMETER from_parameter);
	 CString generate_to_line(TO_PARAMETER to_parameter);
	 CString generate_contact_line(CONTACT_PARAMETER contact_parameter);
	 CString generate_max_forwards_line(int max_forwards);
	 CString generate_callid_line(const CString &call_id);
	 BOOL generate_cseq_line(CString &strCSeqLine, CSEQ_PARAMETER cseq_parameter);
	 CString generate_route_line(CString route);
	 CString generate_record_route_line(CString route);
	 CString generate_content_type_line(const CString &content_type);
	 CString generate_content_type_length_line(int content_length);


	 void build_packet(const CStringArray & arrLineData);
	 CString get_packet_data();

	BOOL NewGUIDString(CString &strGUID);
	int new_random_user();

private:
	CString m_strData;
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
