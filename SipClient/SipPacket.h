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
	ok = 200,
	unauth = 401
}STATUS_CODE;

typedef struct request_uri
{
	CString user;
	CString host;
	unsigned short port;
}REQUEST_URI;

//typedef struct sip_uri
//{
//	CString user;
//	CString host;
//	unsigned short port;
//}SIP_URI;

//typedef struct request_parameter
//{
//	REQUEST_METHOD method;
//	SIP_URI request_uri;
//}REQUEST_PARAMETER;

//typedef struct via_par_list
//{
//	CString sent_address;
//	unsigned short sent_port;
//	CString received_address;
//	unsigned short recvived_port;
//	CString branch;
//	VIA_PAR_LIST *next;
//
//}VIA_PAR_LIST;

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

typedef struct contact_uri
{
	CString user;
	CString host;
	unsigned short port;
}CONTACT_URI;

typedef struct contact_parameter
{
	CONTACT_URI contact_uri;
	CString parameter;
}CONTACT_PARAMETER;

//typedef struct contact_parameter
//{
//	CONTACT_URI contact_uri;
//	CString parameter;
//	CONTACT_PARAMETER *next;
//}CONTACT_PARAMETER;

typedef struct cseq_parameter
{
	int cseq;
	REQUEST_METHOD method;
}CSEQ_PARAMETER;

typedef struct content_par
{
	BOOL enable;
	int content_length;
	CString content_type;
}CONTENT_PAR;

typedef struct digest_auth_par
{
	CString name;
	CString realm;
	CString nonce;
	CString uri;
	CString response;
}DIGEST_AUTH_PAR;

class CSipPacketInfo;




class AFX_EXT_CLASS CSipPacket
{
public:
	CSipPacket();
	~CSipPacket();

	CSipPacket * clone_packet();
	BOOL from_buffer(char * buffer, int buffer_len);
	void empty();


	BOOL build_request_line(REQUEST_METHOD method, REQUEST_URI uri);
	BOOL build_status_line(STATUS_CODE code);
	BOOL build_mess_head(VIA_PARAMETER via_par, int max_forwards, FROM_PARAMETER from_par,
		TO_PARAMETER to_par, const CString &call_id, CSEQ_PARAMETER cseq_par, CONTACT_PARAMETER *contact_par,
		CONTENT_PAR *content, DIGEST_AUTH_PAR *auth_par);
	void build_mess_body(const CString & body);


	BOOL set_via_branch(const CString &branch);
	BOOL set_from_tag(const CString &tag);
	BOOL set_to_tag(const CString &tag);
	BOOL set_contact(int index, CONTACT_PARAMETER contact_par);
	BOOL set_cseq(CSEQ_PARAMETER cseq);
	void set_send_time(DWORD time) { m_send_time = time; }

	BOOL get_nonce_realm(CString &realm, CString &nonce);
	CString get_data() { return m_data; }
	DWORD get_send_time() { return m_send_time; }


	BOOL add_via(VIA_PARAMETER via);
	BOOL mess_head_add_entry(const CString &string_line);


	static BOOL NewGUIDString(CString &strGUID);
	static BOOL build_via_branch(CString &via_branch);
	//static CString new_contact_user();


	//BOOL build_REG_packet(REQUEST_PARAMETER req, VIA_PARAMETER via, int max_forwards, FROM_PARAMETER from,
	//	TO_PARAMETER to, CONTACT_PARAMETER contact, const CString call_id, int cseq, DIGEST_AUTH_PAR auth);
	//BOOL build_INV_packet(REQUEST_PARAMETER req, VIA_PARAMETER via, int max_forwards, FROM_PARAMETER from,
	//	TO_PARAMETER to, CONTACT_PARAMETER contact, const CString call_id, int cseq, const CString &sdp);
	//BOOL build_ACK_packet(REQUEST_PARAMETER req, VIA_PARAMETER via, int max_forwards, FROM_PARAMETER from,
	//	TO_PARAMETER to, const CString call_id, int cseq);
	//BOOL build_OK_packet(REQUEST_PARAMETER req);


	

public :

	static BOOL generate_status_line(CString &strStatusLine, STATUS_CODE status_parameter);
	static BOOL generate_request_line(CString &strRequestLine, REQUEST_METHOD method, REQUEST_URI uri);
	static CString generate_via_line(VIA_PARAMETER via_parameter);
	static CString generate_from_line(FROM_PARAMETER from_parameter);
	static CString generate_to_line(TO_PARAMETER to_parameter);
	static CString generate_contact_line(CONTACT_PARAMETER contact_parameter);
	static CString generate_max_forwards_line(int max_forwards);
	static CString generate_callid_line(const CString &call_id);
	static BOOL generate_cseq_line(CString &strCSeqLine, CSEQ_PARAMETER cseq_parameter);
	static CString generate_route_line(CString route);
	static CString generate_record_route_line(CString route);
	static CString generate_content_type_line(const CString &content_type);
	static CString generate_content_type_length_line(int content_length);
	static CString generate_digest_auth_line(DIGEST_AUTH_PAR digest_auth_par);

	

private:
	CString m_data;
	DWORD m_send_time;

};

class AFX_EXT_CLASS CSipPacketInfo
{
public:
	CSipPacketInfo();
	~CSipPacketInfo();

	BOOL from_packet(CSipPacket *packet);

	//MESSAGE_TYPE get_type();
	//REQUEST_PARAMETER get_request_para();
	//STATUS_CODE get_status_code();
	//CString get_call_id();
	//FROM_PARAMETER get_from();
	//TO_PARAMETER get_to();
	//CSEQ_PARAMETER get_cseq();
	//int get_max_forwards();

	//int get_via_array_length();
	//BOOL get_via(VIA_PARAMETER & via_par, int index);
	//int get_contact_array_length();
	//BOOL get_contact(CONTACT_PARAMETER &contact_par, int index);
	//CString get_route();

	//CString get_content_type();
	//int get_content_length();
	//
	//CSDP get_sdp_info();
	//DWORD get_time();
	//void set_time(DWORD time);


public:
	static BOOL str_to_mess_type(MESSAGE_TYPE &type, const CString string);
	static BOOL str_to_request_par(REQUEST_METHOD &method, REQUEST_URI &uri, const CString string);
	static BOOL str_to_status_code(STATUS_CODE &code, const CString &string);
	static BOOL str_to_viapar(VIA_PARAMETER &via, const CString &string);
	static BOOL str_to_frompar(FROM_PARAMETER & from_par, const CString &string);
	static BOOL str_to_topar(TO_PARAMETER &to_par, const CString &string);
	static BOOL str_to_contactpar(CONTACT_PARAMETER &contact_par, const CString &string);
	static BOOL str_to_callid(CString &call_id, const CString &callid_string);
	static BOOL str_to_cseqpar(CSEQ_PARAMETER &cseq_par, const CString &string);
	static BOOL str_to_content_type(CString &content_type, const CString &string);
	static BOOL str_to_content_type_length(int &length, const CString &string);

public:

	//必选
	MESSAGE_TYPE m_type;
	STATUS_CODE m_status_code;
	REQUEST_METHOD m_method;
	REQUEST_URI m_request_uri;

	CArray<VIA_PARAMETER*, VIA_PARAMETER*> m_array_via;
	int m_max_forwards;
	FROM_PARAMETER m_from;
	TO_PARAMETER m_to;
	CString m_call_id;
	CSEQ_PARAMETER m_cseq;

	//可选
	CArray<CONTACT_PARAMETER*, CONTACT_PARAMETER*> m_array_contact;
	CString m_content_type;
	int m_content_length;
	CString m_route;
	DIGEST_AUTH_PAR m_authorization;
	CSDP *m_sdp_info;
	
};
