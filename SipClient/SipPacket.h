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

typedef struct stuRequestLine
{
	REQUEST_METHOD method;
	SIP_URI request_uri;
	CString rinstance;

	stuRequestLine()
	{
		method = Method_None;
	}

	 CString to_string() const;
	 BOOL from_string(const CString &string);

}REQUEST_LINE;

typedef struct stuHeaderVia
{
	CString sent_address;
	unsigned short sent_port;
	CString received_address;
	unsigned short recvived_port;
	CString branch;
	//struct HEADER_VIA *next;

	stuHeaderVia()
	{
		sent_port = 0;
		recvived_port = 0;
		//next = NULL;
	}

	//void add_via(const CString &sent_address, WORD sent_port, const CString &recv_address,
	//	WORD recv_port, const CString &branch)
	//{
	//	next = new struct HEADER_VIA();
	//	if (next != NULL)
	//	{
	//		next->sent_address = sent_address;
	//		next->sent_port = sent_port;
	//		next->received_address = recv_address;
	//		next->recvived_port = recv_port;
	//		next->branch = branch;
	//	}
	//}
	//BOOL compared_branch(struct HEADER_VIA *via)
	//{
	//	if (NULL == via)
	//		return FALSE;
	//	struct HEADER_VIA *p1, *p2;
	//	do
	//	{
	//		p1 = next;
	//		p2 = via->next;
	//		if (branch != via->branch)
	//		{
	//			break;
	//		}
	//	} while (true)
	//}

	CString to_string() const;
	BOOL from_string(const CString &string);
	struct stuHeaderVia& operator=(const struct stuHeaderVia &via);


}HEADER_VIA;


typedef struct stuHeaderFrom
{
	CString display_user;
	CString user;
	CString host;
	CString tag;

	CString to_string() const;
	BOOL from_string(const CString &string);

}HEADER_FROM;

typedef struct stuHeaderTo
{
	CString display_info;
	CString to_user;
	CString to_host;
	CString to_tag;

	CString to_string() const;
	BOOL from_string(const CString &string);

}HEADER_TO;

typedef struct stuHeaderContact
{
	SIP_URI contact_uri;
	CString rinstance;
	//struct HEADER_CONTACT *next;

	CString to_string() const;
	BOOL from_string(const CString &string);

}HEADER_CONTACT;

typedef struct stuHeaderCseq
{
	int cseq;
	REQUEST_METHOD method;


	stuHeaderCseq()
	{
		cseq = 0;
		method = Method_None;
	}

	CString to_string() const;
	BOOL from_string(const CString &string);



}HEADER_CSEQ;

typedef struct stuHeaderRoute
{
	CString host;
	CString parameter;

	CString to_string()const;
	BOOL from_string(const CString &string);
}HEADER_ROUTE;


typedef CTypedPtrArray<CPtrArray, HEADER_VIA*> CPtrViaArray;




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

//typedef struct HEADER_CONTACT
//{
//	CONTACT_URI contact_uri;
//	CString parameter;
//	HEADER_CONTACT *next;
//}HEADER_CONTACT;

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
	CString get_data();


	BOOL build_register_request(const REQUEST_LINE &request_par, const CPtrViaArray &via_par,
		int max_forward, HEADER_CONTACT  &contact_par, const HEADER_TO &to_par,
		const HEADER_FROM &from_par, const CString &call_id, const HEADER_CSEQ &cseq,
		const CString &auth_string, const CString &optional_att);

	BOOL build_inviter_request(const REQUEST_LINE &request_par, const CPtrViaArray &via_par,
		int max_forward, HEADER_CONTACT  &contact_par, const HEADER_TO &to_par,
		const HEADER_FROM &from_par, const CString &call_id, const HEADER_CSEQ &cseq,
		const CSDP &sdp, const CString &auth_string, const CString &optional_att);

	BOOL build_ack_request(const REQUEST_LINE &request_par,
		const CPtrViaArray &via_par, int max_forward, HEADER_ROUTE * route,
		HEADER_CONTACT  *contact_par, const HEADER_TO &to_par,
		const HEADER_FROM &from_par, const CString &call_id, const HEADER_CSEQ &cseq,
		const CString &auth_string, const CString &optional_att);

	BOOL build_bye_request(const REQUEST_LINE &request_par, const CPtrViaArray &via_par,
		int max_forward, HEADER_ROUTE * route, HEADER_CONTACT  &contact_par, const HEADER_TO &to_par,
		const HEADER_FROM &from_par, const CString &call_id, const HEADER_CSEQ &cseq,
	 const CString &auth_string, const CString &optional_att);


	BOOL build_status(STATUS_CODE code, const CPtrViaArray &via_par, int max_forward,
		HEADER_ROUTE * route, HEADER_CONTACT  &contact_par, const HEADER_TO &to_par,
		const HEADER_FROM &from_par, const CString &call_id, const HEADER_CSEQ &cseq,
		const CString &optional_att);


	//BOOL build_request_packet(const REQUEST_LINE &request_par,
	//	const HEADER_VIA &via_par, const HEADER_FROM &from_par, const HEADER_TO &to_par,
	//	const CString &call_id, const HEADER_CSEQ &cseq,
	//	/*可选属性*/HEADER_CONTACT  *contact_par, HEADER_ROUTE *route, const CString &auth_string,
	//	CSDP *sdp, int max_forward = 70);

	static CString NewGUIDString();
	static CString build_via_branch();
	CString max_forward_to_string(int max_forward);
	CString call_id_to_string(const CString call_id);
	CString status_code_to_string(STATUS_CODE code);

	BOOL add_auth(const CString &auth);
	
private:	
	BYTE *m_data;
	int m_len;


	//public:
	//BOOL build_register_packet(SIP_URI *request_uri, HEADER_VIA *via_par, int max_forward,
	//	HEADER_CONTACT *contact_par, HEADER_FROM *from_par, HEADER_TO *to_par,
	//	const CString &call_id, HEADER_CSEQ *cseq, const CString &auth_string);
	//BOOL build_invite_packet(SIP_URI *request_uri, HEADER_VIA *via_par, int max_forward, 
	//	HEADER_CONTACT  *contact_par, HEADER_FROM *from_par, HEADER_TO *to_par,
	//	const CString &call_id, HEADER_CSEQ *cseq,const CString &auth_string, const CString &sdp);
	//BOOL build_ack_packet(SIP_URI * request_uri, HEADER_VIA * via_par, int max_forward,
	//	HEADER_CONTACT *con_par, HEADER_FROM * from_par, HEADER_TO * to_par,
	//	const CString & call_id, HEADER_CSEQ * cseq, const CString & auth_str);
	//BOOL modify_tag_value(TAG_KEY key, CString value);
	//BOOL modify_via_branch(const CString &branch);
	//BOOL modify_from_tag(const CString &tag);
	//BOOL modify_cseq(int cseq);
	//BOOL add_via(HEADER_VIA via);
	//BOOL add_entry(const CString &value);
	//unsigned char * get_data() { return m_data; }
	//int get_data_len() { return m_len; }
	//void set_send_time(DWORD time) { m_send_time = time; }
	//DWORD get_send_time() { return m_send_time; }
	//static CString generate_status_line(STATUS_CODE status_parameter);
	//static CString generate_request_line(REQUEST_METHOD method, SIP_URI *request_uri);
	//static CString generate_via_line(HEADER_VIA *HEADER_VIA);
	//static CString generate_from_line(HEADER_FROM *HEADER_FROM);
	//static CString generate_to_line(HEADER_TO *HEADER_TO);
	//static CString generate_contact_line(HEADER_CONTACT *HEADER_CONTACT);
	//static CString generate_max_forwards_line(int max_forwards);
	//static CString generate_callid_line(const CString &call_id);
	//static CString generate_cseq_line( HEADER_CSEQ *HEADER_CSEQ);
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
	//CSipPacket to_packet();


	//必选
	MESSAGE_TYPE get_type()const;
	REQUEST_LINE get_request()const;
	STATUS_CODE get_status_code()const;
	//HEADER_VIA get_via();
	void get_via(CPtrViaArray &viaArr) const;
	CString get_call_id()const;
	HEADER_FROM get_from()const;
	HEADER_TO get_to()const;
	HEADER_CSEQ get_cseq()const;
	int get_max_forwards()const;

	//可选属性
	BOOL get_contact(HEADER_CONTACT &contact)const;
	BOOL get_route(HEADER_ROUTE &route)const;
	BOOL get_sdp_info(CSDP &sdp)const;

	CString get_realm()const;
	CString get_nonce()const;
	CString get_auth()const;
	DWORD get_build_time()const;



protected:
	BOOL str_to_mess_type(MESSAGE_TYPE &type, const CString string);
	BOOL str_to_status_code(STATUS_CODE &code, const CString &string);
	BOOL str_to_callid(CString &call_id, const CString &callid_string);
private:
	void free_via();
	//void copy_via(const CPtrViaArray &via);

private:

	//必选
	MESSAGE_TYPE m_type;
	REQUEST_LINE m_request_par;
	STATUS_CODE m_status_code;

	//HEADER_VIA m_via;
	CPtrViaArray m_via_arr;
	HEADER_FROM m_from;
	HEADER_TO m_to;
	CString m_call_id;
	HEADER_CSEQ m_cseq;

	//可选
	int m_max_forwards;
	HEADER_CONTACT *m_contact;
	HEADER_ROUTE *m_route;
	CString m_realm;
	CString m_nonce;
	CString m_auth;
	CSDP *m_sdp_info;
	//CString m_route;

	DWORD m_build_time;
	
};
