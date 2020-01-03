#pragma once

#include "SDP.h"

#define PACK_SIZE 4096


typedef enum message_type
{
	Type_None = 0,
	sip_request,
	sip_status
}MESSAGE_TYPE;

typedef enum request_method
{
	Method_None = 0,
	Register,
	Invite,
	Ack,
	Bye
}REQUEST_METHOD;

typedef enum status_code
{
	Code_None = 0,
	Trying = 100,
	Ringing = 180,
	OK = 200,
	Unauthorized = 401,
	Proxy_Authentication = 407
}STATUS_CODE;

typedef struct sip_uri
{
	CString user;
	CString host;
	unsigned short port;

	sip_uri()
	{
		port = 0;
	}

	CString to_string() const;
	BOOL from_string(const CString &string);

}SIP_URI;

typedef struct request_parameter
{
	REQUEST_METHOD method;
	SIP_URI request_uri;
	CString rinstance;

	request_parameter()
	{
		method = Method_None;
	}

	 CString to_string() const;
	 BOOL from_string(const CString &string);

}REQUEST_PARAMETER;

typedef struct via_parameter
{
	CString sent_address;
	unsigned short sent_port;
	CString received_address;
	unsigned short recvived_port;
	CString branch;
	//struct via_parameter *next;

	via_parameter()
	{
		sent_port = 0;
		recvived_port = 0;
		//next = NULL;
	}

	CString to_string() const;
	BOOL from_string(const CString &string);

}VIA_PARAMETER;

typedef struct from_parameter
{
	CString display_user;
	CString user;
	CString host;
	CString tag;

	CString to_string() const;
	BOOL from_string(const CString &string);

}FROM_PARAMETER;

typedef struct to_parameter
{
	CString display_info;
	CString to_user;
	CString to_host;
	CString to_tag;

	CString to_string() const;
	BOOL from_string(const CString &string);

}TO_PARAMETER;

typedef struct contact_parameter
{
	SIP_URI contact_uri;
	CString rinstance;
	//struct contact_parameter *next;

	CString to_string() const;
	BOOL from_string(const CString &string);

}CONTACT_PARAMETER;

typedef struct cseq_parameter
{
	int cseq;
	REQUEST_METHOD method;


	cseq_parameter()
	{
		cseq = 0;
		method = Method_None;
	}

	CString to_string() const;
	BOOL from_string(const CString &string);


}CSEQ_PARAMETER;

typedef struct route_parameter
{
	CString host;
	CString parameter;

	CString to_string()const;
	BOOL from_string(const CString &string);
}ROUTE_PARAMETER;




//typedef struct digest_auth_par
//{
//	//CString name;
//	CString realm;
//	CString nonce;
//	//CString uri;
//	//CString response;
//}DIGEST_AUTH_PAR;

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

//typedef struct content_par
//{
//	int content_length;
//	CString content_type;
//
//	content_par()
//	{
//		content_length = 0;
//	}
//
//	CString to_string() const;
//
//}CONTENT_PAR;

//typedef struct contact_parameter
//{
//	CONTACT_URI contact_uri;
//	CString parameter;
//	CONTACT_PARAMETER *next;
//}CONTACT_PARAMETER;

//typedef struct contact_uri
//{
//	CString user;
//	CString host;
//	unsigned short port;
//}CONTACT_URI;

class CSipPacketInfo;


class AFX_EXT_CLASS CSipPacket
{
public:
	CSipPacket();
	~CSipPacket();

	CSipPacket(const CSipPacket &p);
	int from_buffer(char * buffer, int buffer_len);
	int get_data(BYTE *buf, int buf_size);



	BOOL build_register_request(const REQUEST_PARAMETER &request_par, const VIA_PARAMETER &via_par,
		int max_forward, CONTACT_PARAMETER  &contact_par, const TO_PARAMETER &to_par,
		const FROM_PARAMETER &from_par, const CString &call_id, const CSEQ_PARAMETER &cseq,
		const CString &auth_string, const CString &optional_att);

	BOOL build_inviter_request(const REQUEST_PARAMETER &request_par, const VIA_PARAMETER &via_par,
		int max_forward, CONTACT_PARAMETER  &contact_par, const TO_PARAMETER &to_par,
		const FROM_PARAMETER &from_par, const CString &call_id, const CSEQ_PARAMETER &cseq,
		const CSDP &sdp, const CString &auth_string, const CString &optional_att);

	BOOL build_ack_request(const CSipPacketInfo &status_info, const REQUEST_PARAMETER &request_par,
		const VIA_PARAMETER &via_par, int max_forward, ROUTE_PARAMETER * route,
		CONTACT_PARAMETER  *contact_par, const TO_PARAMETER &to_par,
		const FROM_PARAMETER &from_par, const CString &call_id, const CSEQ_PARAMETER &cseq,
		const CString &auth_string, const CString &optional_att);

	BOOL build_bye_request(const REQUEST_PARAMETER &request_par, const VIA_PARAMETER &via_par,
		int max_forward, ROUTE_PARAMETER * route, CONTACT_PARAMETER  &contact_par, const TO_PARAMETER &to_par,
		const FROM_PARAMETER &from_par, const CString &call_id, const CSEQ_PARAMETER &cseq,
	 const CString &optional_att);


	//BOOL build_request_packet(const REQUEST_PARAMETER &request_par,
	//	const VIA_PARAMETER &via_par, const FROM_PARAMETER &from_par, const TO_PARAMETER &to_par,
	//	const CString &call_id, const CSEQ_PARAMETER &cseq,
	//	/*可选属性*/CONTACT_PARAMETER  *contact_par, ROUTE_PARAMETER *route, const CString &auth_string,
	//	CSDP *sdp, int max_forward = 70);

	static CString NewGUIDString();
	static CString build_via_branch();
	CString max_forward_to_string(int max_forward);
	CString call_id_to_string(const CString call_id);
	
private:	
	BYTE *m_data;
	int m_len;


	//public:
	//BOOL build_register_packet(SIP_URI *request_uri, VIA_PARAMETER *via_par, int max_forward,
	//	CONTACT_PARAMETER *contact_par, FROM_PARAMETER *from_par, TO_PARAMETER *to_par,
	//	const CString &call_id, CSEQ_PARAMETER *cseq, const CString &auth_string);
	//BOOL build_invite_packet(SIP_URI *request_uri, VIA_PARAMETER *via_par, int max_forward, 
	//	CONTACT_PARAMETER  *contact_par, FROM_PARAMETER *from_par, TO_PARAMETER *to_par,
	//	const CString &call_id, CSEQ_PARAMETER *cseq,const CString &auth_string, const CString &sdp);
	//BOOL build_ack_packet(SIP_URI * request_uri, VIA_PARAMETER * via_par, int max_forward,
	//	CONTACT_PARAMETER *con_par, FROM_PARAMETER * from_par, TO_PARAMETER * to_par,
	//	const CString & call_id, CSEQ_PARAMETER * cseq, const CString & auth_str);
	//BOOL modify_tag_value(TAG_KEY key, CString value);
	//BOOL modify_via_branch(const CString &branch);
	//BOOL modify_from_tag(const CString &tag);
	//BOOL modify_cseq(int cseq);
	//BOOL add_via(VIA_PARAMETER via);
	//BOOL add_entry(const CString &value);
	//unsigned char * get_data() { return m_data; }
	//int get_data_len() { return m_len; }
	//void set_send_time(DWORD time) { m_send_time = time; }
	//DWORD get_send_time() { return m_send_time; }
	//static CString generate_status_line(STATUS_CODE status_parameter);
	//static CString generate_request_line(REQUEST_METHOD method, SIP_URI *request_uri);
	//static CString generate_via_line(VIA_PARAMETER *via_parameter);
	//static CString generate_from_line(FROM_PARAMETER *from_parameter);
	//static CString generate_to_line(TO_PARAMETER *to_parameter);
	//static CString generate_contact_line(CONTACT_PARAMETER *contact_parameter);
	//static CString generate_max_forwards_line(int max_forwards);
	//static CString generate_callid_line(const CString &call_id);
	//static CString generate_cseq_line( CSEQ_PARAMETER *cseq_parameter);
	//static CString generate_expires_line(int expires);
	//static CString generate_record_route_line(CString route);
	//static CString generate_content_type_line(const CString &content_type);
	//static CString generate_content_type_length_line(int content_length);

};

class AFX_EXT_CLASS CSipPacketInfo
{
public:
	CSipPacketInfo();
	~CSipPacketInfo();
	CSipPacketInfo& operator=(const CSipPacketInfo &packet_info);

	BOOL from_packet(CSipPacket *packet);


	//必选
	MESSAGE_TYPE get_type();
	REQUEST_PARAMETER get_request();
	STATUS_CODE get_status_code();
	VIA_PARAMETER get_via();
	CString get_call_id();
	FROM_PARAMETER get_from();
	TO_PARAMETER get_to();
	CSEQ_PARAMETER get_cseq();
	int get_max_forwards();

	//可选属性
	CONTACT_PARAMETER get_contact();
	ROUTE_PARAMETER get_route();

	CString get_realm();
	CString get_nonce();
	CString get_auth();
	CSDP get_sdp_info();
	DWORD get_build_time();



protected:
	BOOL str_to_mess_type(MESSAGE_TYPE &type, const CString string);
	BOOL str_to_status_code(STATUS_CODE &code, const CString &string);
	BOOL str_to_callid(CString &call_id, const CString &callid_string);

private:

	//必选
	MESSAGE_TYPE m_type;
	REQUEST_PARAMETER m_request_par;
	STATUS_CODE m_status_code;

	VIA_PARAMETER m_via;
	int m_max_forwards;
	FROM_PARAMETER m_from;
	TO_PARAMETER m_to;
	CString m_call_id;
	CSEQ_PARAMETER m_cseq;

	//可选
	CONTACT_PARAMETER m_contact;
	ROUTE_PARAMETER m_route;
	CString m_realm;
	CString m_nonce;
	CString m_auth;
	CSDP *m_sdp_info;
	//CString m_route;

	DWORD m_build_time;
	
};
