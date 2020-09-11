#pragma once
#include "stdafx.h"
#include "SipPacket.h"





CSipPacket::CSipPacket(int nPacketLen)
{
	m_unLine.pData = NULL;
	m_pBody = NULL;


	//m_data = new BYTE[PACK_SIZE]();
	//m_data = NULL; 
	//m_len = nPacketLen;

	//if (nPacketLen > 0)
	//	m_data = new  BYTE[nPacketLen];
}

CSipPacket::~CSipPacket()
{
	if (m_unLine.pData != NULL)
	{
		delete m_unLine.pData;
		m_unLine.pData = NULL;
	}

	if (m_pBody != NULL)
	{
		delete m_pBody;
		m_pBody = NULL;
	}

}

CSipPacket * CSipPacket::Clone()
{
	CSipPacket* packet = NULL;

	packet->m_len = m_len;
	packet->m_data = new BYTE[m_len];
	if (packet != NULL)
		memcpy(packet->m_data, m_data, m_len);


	return packet;
}

BYTE * CSipPacket::get_meaasge(unsigned & len)
{
	return nullptr;
}

BOOL CSipPacket::get_line(MESSAGE_TYPE & emType, SIP_LINE & unLine)
{
	return 0;
}

BOOL CSipPacket::get_line(SIP_LINE & unLine)
{
	return 0;
}

BOOL CSipPacket::build_line(MESSAGE_TYPE emType, SIP_LINE unLine)
{
	return 0;
}

BOOL CSipPacket::build_line(SIP_LINE unLine)
{
	return 0;
}

SIP_LINE * CSipPacket::get_line()
{
	return nullptr;
}

BOOL CSipPacket::set_line(MESSAGE_TYPE emType, SIP_LINE unLine)
{
	return 0;
}

BOOL CSipPacket::msg_insert_first_hdr(MESSAGE_HDR stHdr)
{
	return 0;
}

BOOL CSipPacket::msg_add_hdr(MESSAGE_HDR stHdr)
{
	return 0;
}

BOOL CSipPacket::msg_add_hdr(HDR_TYPES type, void * data)
{
	if (data == NULL)
		return FALSE;

	MESSAGE_HDR hdr;


	hdr.type = type;
	switch (type)
	{
	case 	H_VIA:
		hdr.pData = new HEADER_VIA();
		memcpy(hdr.pData, data, sizeof(HEADER_VIA));
		break;
	case 	H_MAX_FORWARDS:
		break;	
	case 	H_TO:
		break;	
	case 	H_FROM:
		break;	
	case 	H_CONTACT:
		break;	
	case 	H_CALL_ID:
		break;	
	case 	H_RECORD_ROUTE:
		break;	
	case 	H_CSEQ:
		break;	
	case 	H_CONTENT_TYPE:
		break;	
	case 	H_CONTENT_LENGTH:
		break;
	case 	H_PROXY_AUTHENTICATE:
		break;
	case 	H_PROXY_AUTHORIZATION:
		break;
	case 	H_OTHER:
		break;


	}

	m_arrHdr.Add(hdr);


	return TRUE;
}

BOOL CSipPacket::find_remove_hdr(CString strHarName)
{
	return 0;
}

void * CSipPacket::find_hdr_by_name(HDR_TYPES emHdrType)
{
	return nullptr;
}

MESSAGE_HDR * CSipPacket::find_hdr_by_name(CString strHarName)
{
	return nullptr;
}

BOOL CSipPacket::clone_hdr_list(CHdrArray & arrHar)
{
	return 0;
}

BOOL CSipPacket::set_hdr(const CHdrArray & arrHdr)
{
	return 0;
}

BOOL CSipPacket::set_hdr(const CString & strTypeList, void * pData)
{
	return 0;
}

BOOL CSipPacket::set_message_body(MESS_BODY stuBody)
{
	return 0;
}

BOOL CSipPacket::build_message_body(MESS_BODY stuBody)
{
	return 0;
}

MESS_BODY * CSipPacket::get_message_body()
{
	return nullptr;
}

BOOL CSipPacket::from_string(CString strString)
{
	return 0;
}

BOOL CSipPacket::create_mess(BYTE * pBuf, unsigned uLen)
{
	return 0;
}

BYTE * CSipPacket::get_meaasge_to_buf(unsigned & len)
{
	return nullptr;
}

//CSipPacket::CSipPacket(const CSipPacket & p)
//{
//	m_data = new BYTE[PACK_SIZE]();
//	memcpy(m_data, p.m_data, p.m_len);
//	m_len = p.m_len;
//
//}

//BOOL CSipPacket::build_request_packet(const REQUEST_PARAMETER & request_par,
//	const HEADER_VIA & via_par, const HEADER_FROM & from_par,
//	const HEADER_TO & to_par, const CString & call_id, 
//	const HEADER_CSEQ & cseq, HEADER_CONTACT * contact_par, HEADER_ROUTE *route,
//	const CString & auth_string, CSDP * sdp,int max_forward)
//{
//
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = request_par.to_string();
//	packet += str_temp;
//
//	//packet header
//	//via
//	str_temp = via_par.to_string();
//	packet += str_temp;
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//route
//	if (NULL != route)
//	{
//		str_temp = route->to_string();
//		packet += str_temp;
//
//	}
//
//
//	//contact
//	if (contact_par != NULL)
//	{
//		str_temp = contact_par->to_string();
//		packet += str_temp;
//	}
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//	//auth
//	if (!auth_string.IsEmpty())
//		packet += auth_string;
//
//	//content
//	if (request_par.method == Invite && sdp != NULL)
//	{
//		str_sdp = sdp->to_string();
//		if (str_sdp.IsEmpty())
//			return FALSE;
//		str_temp.Format(_T("Content-Type: application/sdp\r\nContent-Length: %d\r\n"),
//			str_sdp.GetLength());
//		packet += str_temp;
//	}
//
//	packet += _T("\r\n"); //message header结束符
//
//	if (sdp != NULL)
//	{
//		str_sdp = sdp->to_string();
//		packet += str_sdp;
//	}
//
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//
//
//
//}

CString CSipPacket::build_via_branch()
{
	CString branch;

	branch = NewGUIDString();
	if (branch.IsEmpty())
		return branch;

	branch.Insert(0, _T("z9hG4bK-"));
	

	return branch;
}

//CString CSipPacket::max_forward_to_string(int max_forward)
//{
//	CString string;
//
//	string.Format(_T("Max-Forwards: %d\r\n"), max_forward);
//
//	return string;
//}
//
//CString CSipPacket::call_id_to_string(const CString call_id)
//{
//	CString string;
//
//	string.Format(_T("Call-ID: %s\r\n"), call_id);
//
//	return string;
//}
//
//CString CSipPacket::status_code_to_string(STATUS_CODE code)
//{
//	CString str_line;
//	
//	switch (code)
//	{
//	case Trying:
//		str_line.Format(_T("SIP/2.0 100 Trying\r\n"));
//		break;
//	case Ringing:
//		str_line.Format(_T("SIP/2.0 180 Ringing\r\n"));
//		break;
//	case OK:
//		str_line.Format(_T("SIP/2.0 200 OK\r\n"));
//		break;
//	case Unauthorized:
//		str_line.Format(_T("SIP/2.0 401 OK\r\n"));
//		break;
//	case Proxy_Authentication:
//		str_line.Format(_T("SIP/2.0 407 OK\r\n"));
//		break;
//	default:
//		break;
//	}
//	
//	return str_line;
//}
//
//BOOL CSipPacket::add_auth(const CString & auth)
//{
//	if (NULL == m_data || auth.IsEmpty())
//		return FALSE;
//
//	//修改via branch
//	CString str_packet, packet_L, packet_R, branch;
//	int i = 0, j = 0;
//
//	branch = CSipPacket::build_via_branch();
//	if (branch.IsEmpty())
//		return FALSE;
//
//	str_packet = m_data;
//	i = str_packet.Find(_T("branch"));
//	if (i < 0)
//		return FALSE;
//	i += strlen("branch=");
//	j = i;
//	while (j < str_packet.GetLength())
//	{
//		if (';' == str_packet.GetAt(j) || '\r' == str_packet.GetAt(j))
//			break;
//		j++;
//	}
//	packet_L = str_packet.Left(i);
//	packet_R = str_packet.Right(str_packet.GetLength() - j);
//
//	str_packet = packet_L + branch + packet_R;
//
//	//添加auth
//	i = str_packet.Find(_T("\r\n\r\n"));
//	if (i < 0)
//		return FALSE;
//	i += 2;
//	str_packet.Insert(i, auth);
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(str_packet);
//	if (NULL == p)
//		return FALSE;
//
//	str_packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = str_packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//
//
//	return TRUE;
//}
//
//int CSipPacket::from_buffer(char * buffer, int buffer_len)
//{
//	if (NULL == buffer || buffer_len <= 0)
//		return -1;
//
//	buffer_len > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = buffer_len;
//
//	memcpy(m_data, buffer, m_len);
//		
//	return m_len;
//}
//
//int CSipPacket::get_data(BYTE * buf, int buf_size)
//{
//	if (NULL == buf || buf_size < m_len + 1)
//		return -1;
//
//	memset(buf, 0, buf_size);
//	memcpy(buf, m_data, m_len);
//
//
//	return m_len;
//}
//
//CString CSipPacket::get_data()
//{
//	CString data;
//
//
//	if (m_data != NULL)
//		data = m_data;
//
//	return data;
//}
//
//BOOL CSipPacket::build_register_request(const REQUEST_LINE & request_par,
//	const CPtrViaArray & via_par, int max_forward, HEADER_CONTACT & contact_par,
//	const HEADER_TO & to_par, const HEADER_FROM & from_par, const CString & call_id,
//	const HEADER_CSEQ & cseq, const CString & auth_string, const CString & optional_att)
//{
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = request_par.to_string();
//	packet += str_temp;
//
//	//packet header
//	//via
//	for (int i = 0; i < via_par.GetSize(); i++)
//	{
//		if (via_par.GetAt(i) != NULL)
//		{
//			str_temp = via_par.GetAt(i)->to_string();
//			packet += str_temp;
//		}
//
//	}
//
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//route
//	//if (NULL != route)
//	//{
//	//	str_temp = route->to_string();
//	//	packet += str_temp;
//	//}
//
//
//	//contact
//	str_temp = contact_par.to_string();
//	packet += str_temp;
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//	//auth
//	if (!auth_string.IsEmpty())
//		packet += auth_string;
//
//	if(!optional_att.IsEmpty())
//		packet += optional_att;
//
//
//	packet += _T("\r\n"); //message header结束符
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//}
//
//BOOL CSipPacket::build_inviter_request(const REQUEST_LINE & request_par,
//	const CPtrViaArray & via_par, int max_forward, HEADER_CONTACT & contact_par,
//	const HEADER_TO & to_par, const HEADER_FROM & from_par, const CString & call_id,
//	const HEADER_CSEQ & cseq, const CSDP & sdp, const CString & auth_string,
//	const CString & optional_att)
//{
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = request_par.to_string();
//	packet += str_temp;
//
//	//packet header
//	//via
//	for (int i = 0; i < via_par.GetSize(); i++)
//	{
//		if (via_par.GetAt(i) != NULL)
//		{
//			str_temp = via_par.GetAt(i)->to_string();
//			packet += str_temp;
//		}
//
//	}
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//contact
//	str_temp = contact_par.to_string();
//	packet += str_temp;
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//	//auth
//	if (!auth_string.IsEmpty())
//		packet += auth_string;
//	//content
//	str_sdp = sdp.to_string();
//	str_temp.Format(_T("Content-Type: application/sdp\r\nContent-Length: %d\r\n"),
//		str_sdp.GetLength());
//	packet += str_temp;
//
//	if (!optional_att.IsEmpty())
//		packet += optional_att;
//
//	packet += _T("\r\n"); //message header结束符
//
//	//sdp
//	packet += str_sdp;
//
//
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//}
//
//BOOL CSipPacket::build_ack_request(const REQUEST_LINE & request_par,
//	const CPtrViaArray & via_par, int max_forward, HEADER_ROUTE * route,
//	HEADER_CONTACT * contact_par, const HEADER_TO & to_par, const HEADER_FROM & from_par,
//	const CString & call_id, const HEADER_CSEQ & cseq, const CString & auth_string,
//	const CString & optional_att)
//{
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = request_par.to_string();
//	packet += str_temp;
//
//	//packet header
//	//via
//	for (int i = 0; i < via_par.GetSize(); i++)
//	{
//		if (via_par.GetAt(i) != NULL)
//		{
//			str_temp = via_par.GetAt(i)->to_string();
//			packet += str_temp;
//		}
//
//	}
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//route
//	if (NULL != route)
//	{
//		str_temp = route->to_string();
//		packet += str_temp;
//	}
//
//
//	//contact
//	if (contact_par != NULL)
//	{
//		str_temp = contact_par->to_string();
//		packet += str_temp;
//	}
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//	//auth
//	if (!auth_string.IsEmpty())
//		packet += auth_string;
//
//	if (!optional_att.IsEmpty())
//		packet += optional_att;
//
//
//	packet += _T("\r\n"); //message header结束符
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//}
//
//BOOL CSipPacket::build_bye_request(const REQUEST_LINE & request_par, const CPtrViaArray & via_par,
//	int max_forward, HEADER_ROUTE * route, HEADER_CONTACT & contact_par, const HEADER_TO & to_par,
//	const HEADER_FROM & from_par, const CString & call_id, const HEADER_CSEQ & cseq,
//	const CString &auth_string, const CString & optional_att)
//{
//
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = request_par.to_string();
//	packet += str_temp;
//
//	//packet header
//	//via
//	for (int i = 0; i < via_par.GetSize(); i++)
//	{
//		if (via_par.GetAt(i) != NULL)
//		{
//			str_temp = via_par.GetAt(i)->to_string();
//			packet += str_temp;
//		}
//
//	}
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//route
//	if (NULL != route)
//	{
//		str_temp = route->to_string();
//		packet += str_temp;
//	}
//
//
//	//contact
//	str_temp = contact_par.to_string();
//	packet += str_temp;
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//	//auth
//	if (!auth_string.IsEmpty())
//		packet += auth_string;
//
//	if (!optional_att.IsEmpty())
//		packet += optional_att;
//
//
//	packet += _T("\r\n"); //message header结束符
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//
//
//
//}
//
//BOOL CSipPacket::build_status(STATUS_CODE code, const CPtrViaArray & via_par,
//	int max_forward, HEADER_ROUTE * route, HEADER_CONTACT & contact_par,
//	const HEADER_TO & to_par, const HEADER_FROM & from_par, const CString & call_id,
//	const HEADER_CSEQ & cseq, const CString & optional_att)
//{
//
//
//
//	CString packet, str_temp, str_sdp;
//
//	//request line
//	str_temp = status_code_to_string(code);
//	packet += str_temp;
//
//	//packet header
//	//via
//	for (int i = 0; i < via_par.GetSize(); i++)
//	{
//		if (via_par.GetAt(i) != NULL)
//		{
//			str_temp = via_par.GetAt(i)->to_string();
//			packet += str_temp;
//		}
//
//	}
//
//	if (max_forward > 0)
//	{
//		str_temp = max_forward_to_string(max_forward);
//		packet += str_temp;
//	}
//
//	//route
//	if (NULL != route)
//	{
//		str_temp = route->to_string();
//		packet += str_temp;
//	}
//
//
//	//contact
//	str_temp = contact_par.to_string();
//	packet += str_temp;
//	//to
//	str_temp = to_par.to_string();
//	packet += str_temp;
//	//from
//	str_temp = from_par.to_string();
//	packet += str_temp;
//	//call_id
//	str_temp = call_id_to_string(call_id);
//	packet += str_temp;
//	//cseq
//	str_temp = cseq.to_string();
//	packet += str_temp;
//
//	if (!optional_att.IsEmpty())
//		packet += optional_att;
//
//
//	packet += _T("\r\n"); //message header结束符
//
//
//	char *p = NULL;
//	USES_CONVERSION;
//	p = T2A(packet);
//	if (NULL == p)
//		return FALSE;
//
//	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, m_len);
//
//
//	return TRUE;
//
//
//
//	return 0;
//}



CString CSipPacket::NewGUIDString() 
{
	CString string;
	GUID guid;

	char data[1024] = { 0 };
	int len = 0;

	if (S_OK != ::CoCreateGuid(&guid))
		return string;
	len = sprintf_s(data, 1024, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]);

	if (len <= 0)
		return string;
	string = data;

	return string;
}


CSipPacketInfo::CSipPacketInfo()
{
	m_max_forwards = 0;
	m_contact = NULL;
	m_route = NULL;
	m_sdp_info = NULL;
	m_build_time = 0;
}

CSipPacketInfo::~CSipPacketInfo()
{

	if (m_via_arr.GetSize() > 0)
	{
		HEADER_VIA *via = NULL;
		for (int i = 0; i < m_via_arr.GetSize(); i++)
		{
			via = m_via_arr.GetAt(i);
			if (NULL != via)
			{
				delete via;
				via = NULL;
			}
		}

		m_via_arr.RemoveAll();

	}


	if (NULL != m_sdp_info)
	{
		delete m_sdp_info;
		m_sdp_info = NULL;
	}

	if (NULL != m_contact)
	{
		delete m_contact;
		m_contact = NULL;
	}

	if (NULL != m_route)
	{
		delete m_route;
		m_route = NULL;
	}
}

CSipPacketInfo & CSipPacketInfo::operator=(const CSipPacketInfo & packet_info)
{
	this->m_type = packet_info.m_type;
	this->m_request_par = packet_info.m_request_par;
	this->m_status_code = packet_info.m_status_code;

	HEADER_VIA *viaTemp = NULL;
	free_via();
	for (int i = 0; i < packet_info.m_via_arr.GetSize(); i++)
	{
		if (packet_info.m_via_arr.GetAt(i) != NULL)
		{
			viaTemp = new HEADER_VIA();
			*viaTemp = *(packet_info.m_via_arr.GetAt(i));
			m_via_arr.Add(viaTemp);
		}
	}

	this->m_from = packet_info.m_from;
	this->m_to = packet_info.m_to;
	this->m_call_id = packet_info.m_call_id;
	this->m_cseq = packet_info.m_cseq;

	//可选
	if (packet_info.m_max_forwards > 0)
		this->m_max_forwards = packet_info.m_max_forwards;
	this->m_realm = packet_info.m_realm;
	this->m_nonce = packet_info.m_nonce;
	this->m_auth = packet_info.m_auth;
	if (packet_info.m_sdp_info != NULL)
	{
		if (this->m_sdp_info == NULL)
			this->m_sdp_info = new CSDP();

		*(this->m_sdp_info) = *(packet_info.m_sdp_info);
	}

	if (packet_info.m_contact != NULL)
	{
		if (this->m_contact == NULL)
			this->m_contact = new HEADER_CONTACT();

		*(this->m_contact) = *(packet_info.m_contact);
	}
	if (packet_info.m_route != NULL)
	{
		if (this->m_route == NULL)
			this->m_route = new HEADER_ROUTE();

		*(this->m_route) = *(packet_info.m_route);
	}

	m_build_time = ::GetTickCount();

	return *this;
}


BOOL CSipPacketInfo::from_packet(CSipPacket * packet)
{
	if (NULL == packet)
		return FALSE;

	int i = 0, j = 0;
	CString str_data, str_line;
	BYTE buf[4096] = { 0 };



	i = packet->get_data(buf, 4096);
	if (i < 0)
		return FALSE;
	str_data = buf;
	//必选属性
	//request/status
	i= str_data.Find(_T("\r\n"));
	if (i < 0)
		return FALSE;
	str_line = str_data.Left(i);
	if (!CSipPacketInfo::str_to_mess_type(m_type, str_line))
		return FALSE;
	if (m_type == sip_request)
	{
		if(!m_request_par.from_string(str_line))
			return FALSE;
	}
	else
	{
		if (!str_to_status_code(m_status_code, str_line))
			return FALSE;
	}

	//via
	i = 0, j = 0;
	HEADER_VIA *tempVia = NULL;
	free_via();
	while (i < str_data.GetLength() && j < str_data.GetLength())
	{
		i = str_data.Find(_T("Via"), j);
		if (i < 0)
			break;
		j = str_data.Find(_T("\r\n"), i);
		if (j < 0)
			break;
		str_line = str_data.Mid(i, j - i);

		tempVia = new HEADER_VIA();
		if (tempVia != NULL)
		{
			if (!tempVia->from_string(str_line))
				return FALSE;
			m_via_arr.Add(tempVia);
		}
	}


	//from
	i = str_data.Find(_T("From"), 0);
	if (i < 0)
		return FALSE;
	j = str_data.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;
	str_line = str_data.Mid(i, j - i);
	if (!m_from.from_string(str_line))
		return FALSE;
	//to
	i = str_data.Find(_T("To"), 0);
	if (i < 0)
		return FALSE;
	j = str_data.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE; 
	str_line = str_data.Mid(i, j - i);
	if (!m_to.from_string(str_line))
		return FALSE;
	//call_id
	i = str_data.Find(_T("Call-ID"), 0);
	if (i < 0)
		return FALSE;
	j = str_data.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;
	str_line = str_data.Mid(i, j - i);
	if (!str_to_callid(m_call_id, str_line))
		return FALSE;
	//cseq
	i = str_data.Find(_T("CSeq"), 0);
	if (i < 0)
		return FALSE;
	j = str_data.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;
	str_line = str_data.Mid(i, j - i );
	if (!m_cseq.from_string(str_line))
		return FALSE;

	//可选属性
	//contact
	i = 0, j = 0;
	i = str_data.Find(_T("Contact"), j);
	if (i >= 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if ( j >= 0)
		{
			str_line = str_data.Mid(i, j - i );
			if (m_contact == NULL)
				m_contact = new HEADER_CONTACT();
			if (!m_contact->from_string(str_line))
				return FALSE;
		}
	}



	//realm
	i = str_data.Find(_T("realm="));
	if (i >= 0)
	{
		i += strlen("realm=\"");
		j = str_data.Find('\"', i);
		if (j < 0)
			return FALSE;
		m_realm = str_data.Mid(i, j - i);
	}
	//nonce
	i = str_data.Find(_T("nonce="));
	if (i >= 0)
	{
		i += strlen("nonce=\"");
		j = str_data.Find('\"', i);
		if (j < 0)
			return FALSE;
		m_nonce = str_data.Mid(i, j - i);
	}

	//auth
	i = str_data.Find(_T("Proxy-Authorization"));
	if (i < 0)
	{
		i = str_data.Find(_T("Authorization"));
		if (i >= 0)
		{
			j = str_data.Find(_T("\r\n"), i);
			if (j > 0)
			{
				j += 2;
				m_auth = str_data.Mid(i, j - i);
			}
		}
	}
	else
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			j += 2;
			m_auth = str_data.Mid(i, j - i);
		}
	}

	//route
	i = str_data.Find(_T("Route"));
	if (i >= 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j >= 0)
		{
			str_line = str_data.Mid(i, j - i );
			if (m_route == NULL)
				m_route = new HEADER_ROUTE();
			if (!m_route->from_string(str_line))
				return FALSE;
		}
	}

	//sdp
	char *p = NULL;
	i = str_data.Find(_T("\r\n\r\nv="));
	if (i > 0)
	{
		if (m_sdp_info == NULL)
			m_sdp_info = new CSDP();
		i += strlen("\r\n\r\nv=");
		str_line = str_data.Right(str_data.GetLength() - i);
		USES_CONVERSION;
		p = T2A(str_line);
		if (NULL == p)
			return FALSE;
		if (!m_sdp_info->from_buffer(p, str_data.GetLength() - i))
			return FALSE;
	}


	m_build_time = ::GetTickCount();


	//content type
	//i = str_data.Find(_T("Content-Type"), 0);
	//if (i >= 0)
	//{
	//	j = str_data.Find(_T("\r\n"), i);
	//	if (j >= 0)
	//	{
	//		str_line = str_data.Mid(i, j - i);
	//		if (!str_to_content_type(m_content_type, str_line))
	//			return FALSE;
	//	}
	//}
	//content length
	//i = str_data.Find(_T("Content-Length"), 0);
	//if (i > 0)
	//{
	//	j = str_data.Find(_T("\r\n"), i);
	//	if (j > 0)
	//	{
	//		str_line = str_data.Mid(i, j - i);
	//		m_content_length = str_to_content_type_length(str_line);
	//	}
	//}
	//route
	//i = str_data.Find(_T("Route"));
	//if (i > 0)
	//{
	//	i += strlen("Route: ");
	//	j = str_data.Find(_T("\r\n"), i);
	//	if (j > 0)
	//		m_route = str_data.Mid(i, j - i);
	//}

	return TRUE;
}

//CSipPacket CSipPacketInfo::to_packet()
//{
//	CString str_packet;
//	CSipPacket packet;
//
//
//	if (m_type == sip_request)
//		str_packet += m_request_par.to_string();
//	else
//		str_packet += packet.status_code_to_string(m_status_code);
//
//
//	str_packet += m_via.to_string();
//	str_packet += m_.to_string();
//	str_packet += m_via.to_string();
//	str_packet += m_via.to_string();
//
//
//
//}


REQUEST_LINE CSipPacketInfo::get_request()const
{
	return m_request_par;
}


STATUS_CODE CSipPacketInfo::get_status_code()const
{
	return m_status_code;
}


void CSipPacketInfo::get_via(CPtrViaArray & viaArr) const
{
	HEADER_VIA *via = NULL;

	for (int i = 0; i < m_via_arr.GetSize(); i++)
	{
		via = new HEADER_VIA();
		if (via != NULL && m_via_arr.GetAt(i)!=NULL)
		{
			via->branch = m_via_arr.GetAt(i)->branch;
			via->received_address = m_via_arr.GetAt(i)->received_address;
			via->recvived_port = m_via_arr.GetAt(i)->recvived_port;
			via->sent_address = m_via_arr.GetAt(i)->sent_address;
			via->sent_port = m_via_arr.GetAt(i)->sent_port;

			viaArr.Add(via);
		}
	}

}

CString CSipPacketInfo::get_call_id()const
{
	return m_call_id;
}

HEADER_FROM CSipPacketInfo::get_from()const
{
	return m_from;
}

HEADER_TO CSipPacketInfo::get_to()const
{
	return m_to;
}

HEADER_CSEQ CSipPacketInfo::get_cseq()const
{
	
	return m_cseq;
}

int CSipPacketInfo::get_max_forwards()const
{

	return m_max_forwards;
}

DWORD CSipPacketInfo::get_build_time()const
{
	return m_build_time;
}

BOOL CSipPacketInfo::get_contact(HEADER_CONTACT &contact)const
{
	if (m_contact == NULL)
		return FALSE;

	contact = *m_contact;


	return TRUE;
}

CString CSipPacketInfo::get_realm()const
{
	return m_realm;
}

CString CSipPacketInfo::get_nonce()const
{
	return m_nonce;
}

CString CSipPacketInfo::get_auth()const
{
	return m_auth;
}


BOOL CSipPacketInfo::get_route(HEADER_ROUTE &route)const
{
	if (m_route == NULL)
		return FALSE;

	route = *(m_route);


	return TRUE;
}

BOOL CSipPacketInfo::get_sdp_info(CSDP &sdp)const
{
	if (NULL == m_sdp_info)
		return FALSE;

	sdp = *m_sdp_info;

	return TRUE;
}

BOOL CSipPacketInfo::str_to_mess_type(MESSAGE_TYPE &type, const CString string)
{
	CString str_type;


	int i = string.Find(' ');
	if (i < 0)
		return FALSE;

	str_type = string.Left(i);
	if (str_type.Compare(_T("SIP/2.0")) == 0)
	{
		type = sip_status;
	}
	else
	{
		type = sip_request;
	}



	return TRUE;
}

BOOL CSipPacketInfo::str_to_status_code(STATUS_CODE &code, const CString &string)
{
	int i = 0, j = 0, num = 0;
	CString str_temp;

	i = string.Find(' ');
	if (i < 0)
		return FALSE;
	str_temp = string.Left(i);
	if (0 == str_temp.Compare(_T("SIP/2.0")))
	{
		j = string.Find(' ', i + 1);
		num = _ttoi(string.Mid(i + 1, j - i - 1));
		switch (num)
		{
		case 100:
			code = Trying;
			break;
		case 180:
			code = Ringing;
			break;
		case 200:
			code = OK;
			break;
		case 401:
			code = Unauthorized;
			break;
		case 407:
			code = Proxy_Authentication;
			break;
		default:
			return FALSE;
		}
	}

	return TRUE;
}

BOOL CSipPacketInfo::str_to_callid(CString & call_id, const CString & callid_string)
{
	int i = 0, j = 0;

	i = callid_string.Find(' ');
	if (i < 0)return FALSE;
	i++;
	call_id = callid_string.Right(callid_string.GetLength() - i);

	return TRUE;
}

void CSipPacketInfo::free_via()
{
	HEADER_VIA *p = NULL;
	if (m_via_arr.GetSize() > 0)
	{
		for (int i = 0; i < m_via_arr.GetSize(); i++)
		{
			p = m_via_arr.GetAt(i);
			if (p != NULL)
			{
				delete p;
				p = NULL;
			}
		}

		m_via_arr.RemoveAll();
	}

}

//void CSipPacketInfo::copy_via(const CPtrViaArray & via)
//{
//	free_via();
//	HEADER_VIA *p = NULL;
//
//
//	for (int i = 0; i < via.GetSize(); i++)
//	{
//		p = new HEADER_VIA();
//		if (p != NULL &&  via.GetAt(i) != NULL)
//		{
//			p->sent_address = via.GetAt(i)->sent_address;
//			p->sent_port= via.GetAt(i)->sent_port;
//			p->received_address = via.GetAt(i)->received_address;
//			p->recvived_port = via.GetAt(i)->recvived_port;
//			p->branch = via.GetAt(i)->branch;
//
//			m_via_arr.Add(p);
//		}
//	}
//}

 CString stuRequestLine::to_string() const
{
	CString string, str_method, str_sip;

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
	}

	str_sip = request_uri.to_string();

	if (rinstance.IsEmpty())
		string.Format(_T("%s %s SIP/2.0\r\n"), str_method, str_sip);
	else
		string.Format(_T("%s %s;rinstance=%s SIP/2.0\r\n"), str_method, str_sip, rinstance);

	return string;

}

 BOOL stuRequestLine::from_string(const CString & string)
 {

	 int i = 0, j = 0;
	 CString str_temp;

	 i = string.Find(' ');
	 if (i < 0)
		 return FALSE;
	 str_temp = string.Left(i);
	 //method 必须
	 if (0 == str_temp.Compare(_T("REGISTER")))
		 method = Register;
	 else if (0 == str_temp.Compare(_T("INVITE")))
		 method = Invite;
	 else if (0 == str_temp.Compare(_T("ACK")))
		 method = Ack;
	 else if (0 == str_temp.Compare(_T("BYE")))
		 method = Bye;
	 else
		 return FALSE;

	 //uri
	 i = string.Find(_T("sip:"));
	 if (i < 0)
		 return FALSE;
	 j = string.Find(' ', i);
	 if (j < 0)
		 return FALSE;
	 str_temp = string.Mid(i, j - i);
	 if (!request_uri.from_string(str_temp))
		 return FALSE;
	 //rinstance
	 i = string.Find(_T("rinstance"));
	 if (i >= 0)
	 {
		 i += strlen("rinstance=");
		 str_temp.Empty();
		 while (i < string.GetLength())
		 {
			 if (' ' == string.GetAt(i) || ';' == string.GetAt(i))
				 break;
			 str_temp += string.GetAt(i);
			 i++;
		 }
		 rinstance = str_temp;
	 }

	 return TRUE;
 }

CString sip_uri::to_string() const
{
	CString sip_str, temp;

	sip_str.Format(_T("sip:"));
	if (!user.IsEmpty())
	{
		temp.Format(_T("%s@"), user);
		sip_str += temp;
	}
	sip_str += host;
	if (port > 0)
	{
		temp.Format(_T(":%d"), port);
		sip_str += temp;
	}

	return sip_str;

}


//格式必须为 sip:1001@192.168.100.1:5060 (用户名和端口号可以为空)
BOOL sip_uri::from_string(const CString & string)
{
	if (string.IsEmpty())
		return FALSE;

	CString  temp;
	int i = 0, j = 0, n = 0, k=0, num = 0;

	i = string.Find(_T("sip:"));
	if (i < 0)
		return FALSE;
	i += strlen("sip:");

	//user
	j = string.Find('@', i);
	if (j >= 0)
	{
		user = string.Mid(i, j - i);
		if (user.IsEmpty())
			return FALSE;
	}

	//port
	n = string.Find(':', i);
	if (n >= 0)
	{
		k = n + 1;
		while (k < string.GetLength())
		{
			if (string.GetAt(k) < 48 || string.GetAt(k) > 57)
				break;
			num = num * 10 + (string.GetAt(k) - 48);
			k++;
		}
		if (num > 65536)
			return FALSE;
		port = num;
	}

	//host
	temp.Empty();
	if (j >= 0)
		k = j + 1;
	else
		k = i;
	while (k < string.GetLength())
	{
		if (' ' == string.GetAt(k) || ':' == string.GetAt(k) || '\r' == string.GetAt(k))
			break;
		temp += string.GetAt(k);
		k++;
	}
	host = temp;

	return TRUE;
}

CString stuHeaderVia::to_string() const
{
	CString str_via, str_temp;

	str_via.Format(_T("Via: SIP/2.0/UDP %s:%d;"), sent_address, sent_port);
	str_temp.Format(_T("branch=%s;"), branch);
	str_via += str_temp;

	if (!received_address.IsEmpty())
	{
		str_temp.Format(_T("received=%s;"), received_address);
		str_via += str_temp;

		if (recvived_port > 0)
		{
			str_temp.Format(_T("rport=%d\r\n"), recvived_port);
			str_via += str_temp;
		}
	}
	else
	{
		str_temp.Format(_T("rport\r\n"));
		str_via += str_temp;
	}

	return str_via;
}

BOOL stuHeaderVia::from_string(const CString & string)
{
	if (string.IsEmpty())
		return FALSE;
	CString temp;


	int i = 0, j = 0, num = 0;
	//send address
	i = string.Find(' ', 5);
	if (i < 0)
		return FALSE;
	j = string.Find(':', i);
	if (j < 0)
		return FALSE;
	sent_address = string.Mid(i + 1, j - i - 1);
	//send port
	i = string.Find(';', j);
	sent_port = _ttoi(string.Mid(j + 1, i - j - 1));
	//branch
	i = string.Find(_T("branch"));
	if (i < 0)
		return FALSE;
	i += strlen("branch=");
	temp.Empty();
	while (i < string.GetLength())
	{
		if (';' == string.GetAt(i) || ' ' == string.GetAt(i))
			break;
		temp += string.GetAt(i);
		i++;
	}
	branch = temp;


	//receive addres
	i = string.Find(_T("received"));
	if (i > 0)
	{
		i += strlen("received=");
		while (i < string.GetLength())
		{
			if (';' == string.GetAt(i) || ' ' == string.GetAt(i))
				break;
			temp += string.GetAt(i);
			i++;
		}
		received_address = temp;
	}

	//rport
	i = string.Find(_T("rport="));
	if (i >= 0)
	{
		i += strlen("rport=");
		while (i < string.GetLength())
		{
			if (string.GetAt(i) < 48 || string.GetAt(i) > 57)
				break;
			num = num * 10 + (string.GetAt(i) - 48);
			i++;
		}
		if (num > 0 && num <= 65536)
			recvived_port = num;
	}

	return TRUE;
}

stuHeaderVia & stuHeaderVia::operator=(const stuHeaderVia & via)
{
	sent_address = via.sent_address;
	sent_port = via.sent_port;
	received_address = via.received_address;
	recvived_port = via.recvived_port;
	branch = via.branch;

	return *this;
}

//stuHeaderVia& operator=(const struct stuHeaderVia &via)
//{
//	 sent_address = via.sent_address;
//	 sent_port = via.sent_port;
//	 received_address = via.received_address;
//	 recvived_port = via.recvived_port;
//	 branch = via.branch;
//}

CString stuHeaderFrom::to_string() const
{
	CString str_from, str_temp;

	str_from.Format(_T("From: "));
	if (!display_user.IsEmpty())
	{
		str_temp.Format(_T("\"%s\" "), display_user);
		str_from += str_temp;
	}
	str_temp.Format(_T("<sip:%s@%s>"), user, host);
	str_from += str_temp;
	if (!tag.IsEmpty())
	{
		str_temp.Format(_T(";tag=%s"), tag);
		str_from += str_temp;
	}
	str_from += _T("\r\n");

	return str_from;
}

BOOL stuHeaderFrom::from_string(const CString & string)
{
	int i = 0, j = 0;

	i = string.Find('"');
	if (i >= 0)
	{
		i++;
		j = string.Find('"', i);
		if (j >= 0)
			display_user = string.Mid(i, j - i);
	}

	i = string.Find(_T("sip:"));
	if (i < 0)return FALSE;
	i += strlen("sip:");
	j = string.Find('@', i);
	if (j < 0)return FALSE;
	user = string.Mid(i, j - i);

	j++;
	i = string.Find('>', j);
	if (i < 0) return FALSE;
	host = string.Mid(j, i - j);

	j = string.Find(_T("tag"));
	if (j >= 0)
	{
		j += strlen("tag=");
		tag = string.Right(string.GetLength() - j);
	}

	return TRUE;
}

CString stuHeaderCseq::to_string() const
{
	CString str_cseq, str_method;
	
	switch (method)
	{
	case Register:
		str_method = _T("REGISTER");
		break;
	case Invite:
		str_method = _T("INVITE");
		break;
	case Ack:
		str_method = _T("ACK");
		break;
	case Bye:
		str_method = _T("BYE");
		break;
	}
	str_cseq.Format(_T("CSeq: %d %s\r\n"), cseq, str_method);
	
		
	return str_cseq;
	
}

BOOL stuHeaderCseq::from_string(const CString & string)
{
	CString temp;
	int i = 0, j = 0;

	i = string.Find(' ');
	if (i < 0)return FALSE;
	i++;
	j = string.Find(' ', i);
	if (j < 0)return FALSE;
	temp = string.Mid(i, j - i);
	cseq = _ttoi(temp);
	if (cseq <= 0)
		return FALSE;


	i = string.Find(_T("\r\n"));
	if (i < 0)
		temp = string.Right(string.GetLength() - j - 1);
	else
		temp = string.Mid(j + 1, i - j - 1);


	if (temp.Compare(_T("REGISTER")) == 0)
	{
		method = Register;
	}
	else if (temp.Compare(_T("INVITE")) == 0)
	{
		method = Invite;
	}
	else if (temp.Compare(_T("ACK")) == 0)
	{
		method = Ack;
	}
	else if (temp.Compare(_T("BYE")) == 0)
	{
		method = Bye;
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

CString stuHeaderContact::to_string() const
{
	CString string, str_temp;

	string.Format(_T("Contact: <sip:%s@%s:%d"), contact_uri.user,
		contact_uri.host, contact_uri.port);
	if (!rinstance.IsEmpty())
	{
		str_temp.Format(_T(";rinstance=%s"), rinstance);
		string += str_temp;
	}
	string += _T(">\r\n");

	return string;
}

BOOL stuHeaderContact::from_string(const CString & string)
{
	int i = 0, j = 0;
	CString str_temp;


	i = string.Find(_T("<sip:"));
	if (i < 0)return FALSE;
	//i += strlen("<sip:");
	j = string.Find('>', i);
	if (j < 0)return FALSE;
	str_temp = string.Mid(i, j - i);

	if (!contact_uri.from_string(str_temp))
		return FALSE;


	i = string.Find(_T("rinstance"));
	if (i >= 0)
	{
		i += strlen("rinstance=");
		str_temp.Empty();

		while (i < string.GetLength())
		{
			if (';' == string.GetAt(i) || ' ' == string.GetAt(i))
				break;
			if ('<' == string.GetAt(i) || '>' == string.GetAt(i)
				|| '\"' == string.GetAt(i))
			{
				i++;
				continue;
			}
			str_temp += string.GetAt(i);
			i++;
		}
		rinstance = str_temp;
	}


	return TRUE;
}

CString stuHeaderTo::to_string() const
{
	CString string, str_temp;

	string.Format(_T("To: "));
	if (!display_info.IsEmpty())
	{
		str_temp.Format(_T("\"%s\" "), display_info);
		string += str_temp;
	}
	str_temp.Format(_T("<sip:%s@%s>"), to_user, to_host);
	string += str_temp;
	if (!to_tag.IsEmpty())
	{
		str_temp.Format(_T(";tag=%s"), to_tag);
		string += str_temp;
	}
	string += _T("\r\n");

	return string;
}

BOOL stuHeaderTo::from_string(const CString & string)
{

	int i = 0, j = 0;

	i = string.Find('"');
	if (i >= 0)
	{
		i++;
		j = string.Find('"', i);
		if (j >= 0)
			display_info = string.Mid(i, j - i);
	}

	i = string.Find(_T("sip:"));
	if (i < 0)return FALSE;
	i += strlen("sip:");
	j = string.Find('@', i);
	if (j < 0)return FALSE;
	to_user = string.Mid(i, j - i);

	j++;
	i = string.Find('>', j);
	if (i < 0) return FALSE;
	to_host = string.Mid(j, i - j);

	j = string.Find(_T("tag"));
	if (j >= 0)
	{
		j += strlen("tag=");
		to_tag = string.Right(string.GetLength() - j);
	}

	return TRUE;


	return 0;
}

MESSAGE_TYPE CSipPacketInfo::get_type()const
{
	return m_type;
}
























//CString CSipPacketInfo::get_route()
// {
//	 return m_route;
// }

//BOOL CSipPacketInfo::str_to_viapar(HEADER_VIA &via, const CString & string)
//{
//	if (string.IsEmpty())
//		return FALSE;
//
//
//	int i = 0, j = 0;
//
//	i = string.Find(' ', 5);
//	if (i < 0)
//		return FALSE;
//	j = string.Find(':', i);
//	via.sent_address = string.Mid(i + 1, j - i - 1);
//	i = string.Find(';', j);
//	via.sent_port = _ttoi(string.Mid(j + 1, i - j - 1));
//	i = string.Find(_T("branch"));
//	if (i < 0)
//		return FALSE;
//	i += strlen("branch=");
//	j = string.Find(';', i);
//	if (j > 0)
//	{
//		via.branch = string.Mid(i, j - i);
//	}
//	else
//	{
//		via.branch = string.Right(string.GetLength() - i);
//	}
//
//
//	i = string.Find(_T("received"));
//	if (i > 0)
//	{
//		j = string.Find(';', i);
//		if (j > 0)
//		{
//			via.received_address = string.Mid(i + strlen("recvived="), j - (i + strlen("recvived=")));
//		}
//	}
//	
//
//	return TRUE;
//}

//BOOL str_to_sipuri(SIP_URI &uri, const CString string)
//{
//	if (string.IsEmpty())
//		return FALSE;
//
//	int i = 0, j = 0;
//	i = string.Find('@');
//	if (i >= 0)
//		uri.user = string.Left(i);
//	j = string.Find(':');
//	if (j >= 0)
//		uri.port = _ttoi(string.Right(string.GetLength() - i));
//
//	if (i >= 0)
//	{
//		if (j >= 0)
//			uri.host = string.Mid(i + 1, j - i - 1);
//		else
//			uri.host = string.Right(string.GetLength() - i - 1);
//	}
//	else
//	{
//		if (j >= 0)
//			uri.host = string.Left(j);
//		else
//			uri.host = string;
//	}
//
//	return TRUE;
//}

//BOOL CSipPacketInfo::str_to_request_par(REQUEST_PARAMETER &req_par, const CString string)
//{
//	int i = 0, j = 0;
//	CString str_temp;
//	
//	i = string.Find(' ');
//	if (i < 0)
//		return FALSE;
//	str_temp = string.Left(i);
//	//method 必须
//	if (0 == str_temp.Compare(_T("REGISTER")))
//		req_par.method = Register;
//	else if (0 == str_temp.Compare(_T("INVITE")))
//		req_par.method = Invite;
//	else if (0 == str_temp.Compare(_T("ACK")))
//		req_par.method = Ack;
//	else if (0 == str_temp.Compare(_T("BYE")))
//		req_par.method = Bye;
//	else
//		return FALSE;
//
//	//uri
//	i = string.Find(_T("sip:"));
//	if (i < 0)
//		return FALSE;
//	i += strlen("sip:");
//
//	j = string.Find(' ', i);
//	if (j < 0)
//		return FALSE;
//	str_temp = string.Mid(i, j - i);
//	req_par.uri = str_to_sipuri(str_temp);
//
//
//	return TRUE;
//
//}

//BOOL CSipPacketInfo::str_to_frompar(HEADER_FROM &from_par, const CString & string)
//{
//	int i = 0, j = 0;
//	CString display_user, user, host, tag;
//
//	i = string.Find('"');
//	if (i > 0)
//	{
//		i++;
//		j = string.Find('"', i);
//		if (j > 0)
//			display_user = string.Mid(i, j - i);
//	}
//
//	i = string.Find(_T("sip:"));
//	if (i < 0)return FALSE;
//	i += strlen("sip:");
//	j = string.Find('@', i);
//	if (j < 0)return FALSE;
//	user = string.Mid(i, j - i);
//
//	j++;
//	i = string.Find('>', j);
//	if (i < 0) return FALSE;
//	host = string.Mid(j, i - j);
//
//	j = string.Find(_T("tag"));
//	if (j > 0)
//	{
//		j += strlen("tag=");
//		tag = string.Right(string.GetLength() - j);
//	}
//
//	from_par.display_user = display_user;
//	from_par.user = user;
//	from_par.host = host;
//	from_par.tag = tag;
//
//
//
//	return TRUE;
//}
//
//BOOL CSipPacketInfo::str_to_topar(HEADER_TO &to_par, const CString & string)
//{
//	int i = 0, j = 0;
//
//	i = string.Find('"');
//	if (i > 0)
//	{
//		i++;
//		j = string.Find('"', i);
//		if (j > 0)
//			to_par.display_info = string.Mid(i, j - i);
//	}
//
//	i = string.Find(_T("sip:"));
//	if (i < 0)return FALSE;
//	i += strlen("sip:");
//	j = string.Find('@', i);
//	if (j < 0)return FALSE;
//	to_par.to_user = string.Mid(i, j - i);
//
//	j++;
//	i = string.Find('>', j);
//	if (i < 0) return FALSE;
//	to_par.to_host = string.Mid(j, i - j);
//
//	j = string.Find(_T("tag"));
//	if (j > 0)
//	{
//		j += strlen("tag=");
//		to_par.to_tag = string.Right(string.GetLength() - j);
//	}
//
//	return TRUE;
//}
//
//BOOL CSipPacketInfo::str_to_contactpar(HEADER_CONTACT &contact_par, const CString & string)
//{
//	int i = 0, j = 0;
//	CString str_temp;
//
//
//	i = string.Find(_T("<sip:"));
//	if (i < 0)return FALSE;
//	i += strlen("<sip:");
//	j = string.Find('>', i);
//	if (j < 0)return FALSE;
//	str_temp = string.Mid(i, j - i);
//	i = str_temp.Find('@');
//	j = str_temp.Find(':');
//	if (i < 0 || j < 0) return FALSE;
//	contact_par.contact_uri.user = str_temp.Left(i);
//	contact_par.contact_uri.host = str_temp.Mid(i + 1, j - i - 1);
//	contact_par.contact_uri.port = _ttoi(str_temp.Right(str_temp.GetLength() - j-1));
//
//	i = string.Find(_T("rinstance"));
//	if (i >= 0)
//	{
//		j = string.Find('>', i);
//		if (j < 0)
//		{
//			j = string.Find(_T("\r\n"), i);
//			if (j < 0)
//				return FALSE;
//		}
//
//		i += strlen("rinstance=");
//		contact_par.rinstance = string.Mid(i, j - i);
//	}
//
//
//
//
//	//i = string.Find(_T("sip:"));
//	//if (i > 0)
//	//{
//	//	i += strlen("sip:");
//	//	j = string.Find('@', i);
//	//	if (j > 0)
//	//	{
//	//		contact_par.contact_uri.user = string.Mid(i, j - i);
//	//		i = string.Find(':', j);
//	//		if (i > 0)
//	//		{
//	//			j++;
//	//			contact_par.contact_uri.host = string.Mid(j, i - j);
//	//			j = string.Find(' ', i);
//	//			if (j > 0)
//	//				contact_par.contact_uri.port = _ttoi(string.Mid(i, j - i - 1));
//	//		}
//	//	}
//	//}
//
//
//	return TRUE;
//}

//BOOL CSipPacketInfo::str_to_cseqpar(HEADER_CSEQ &cseq_par, const CString & string)
//{
//	CString temp;
//	int i = 0, j = 0;
//
//	i = string.Find(' ');
//	if (i < 0)return FALSE;
//	i++;
//	j = string.Find(' ', i);
//	if (j < 0)return FALSE;
//	temp = string.Mid(i, j - i);
//	cseq_par.cseq = _ttoi(temp);
//	
//
//
//	temp = string.Right(string.GetLength() - j - 1);
//
//
//	if (temp.Compare(_T("REGISTER")) == 0)
//	{
//		cseq_par.method = Register;
//	}
//	else if (temp.Compare(_T("INVITE")) == 0)
//	{
//		cseq_par.method = Invite;
//	}
//	else if (temp.Compare(_T("ACK")) == 0)
//	{
//		cseq_par.method = Ack;
//	}
//	else if (temp.Compare(_T("BYE")) == 0)
//	{
//		cseq_par.method = Bye;
//	}
//	else
//	{
//		return FALSE;
//	}
//
//	return TRUE;
//}
//
//BOOL CSipPacketInfo::str_to_content_type(CString & content_type, const CString & string)
//{
//
//	return TRUE;
//}

//int random_contact_user()
//{
//	int random = 0, num = 0;
//	LARGE_INTEGER seed;
//
//	for (int i = 0; i < 8; i++)
//	{
//		QueryPerformanceFrequency(&seed);
//		QueryPerformanceCounter(&seed);
//		srand(seed.QuadPart);//初始化一个以微秒为单位的时间种子
//		random = rand() % 10;//产生一个随机数
//		num = num * 10 + random;
//	}
//
//	return num;
//}

//CSipPacket * CSipPacket::clone_packet()
//{
//
//	CSipPacket *p = new CSipPacket();
//
//	int i = 0;
//	m_len > PACK_SIZE ? i = PACK_SIZE : i = m_len;
//
//	memcpy(p->m_data, m_data, i);
//	p->m_len = i;
//	p->m_send_time = m_send_time;
//
//
//	return p;
//
//}

//BOOL CSipPacket::add_entry(const CString &value)
//{
//	if (value.IsEmpty() || NULL == m_data)
//		return FALSE;
//
//
//	int i = 0;
//	CString src_data, des_data;
//	char buf[4096] = { 0 };
//
//	src_data = m_data;
//	i = src_data.Find(_T("\r\n\r\n"));
//	if (i < 0)
//		return FALSE;
//	i += 2;
//	des_data = string_modify(src_data, value, i, i);
//	USES_CONVERSION;
//	char *p = T2A(des_data);
//	if (NULL == p)
//		return FALSE;
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, p, des_data.GetLength());
//
//
//
//	if (!cstring_to_char(buf, 4096, des_data))
//		return FALSE;
//	memset(m_data, 0, PACK_SIZE);
//	memcpy(m_data, buf, des_data.GetLength());
//	m_len = des_data.GetLength();
//
//	return TRUE;
//}
//
//BOOL CSipPacket::add_via(HEADER_VIA via)
//{
//
//
//
//
//	return 0;
//}

//CString CSipPacket::generate_status_line(STATUS_CODE status_code)
//{
//	CString str_line;
//
//	switch (status_code)
//	{
//	case Trying:
//		str_line.Format(_T("SIP/2.0 100 Trying\r\n"));
//		break;
//	case Ringing:
//		str_line.Format(_T("SIP/2.0 180 Ringing\r\n"));
//		break;
//	case OK:
//		str_line.Format(_T("SIP/2.0 200 OK\r\n"));
//		break;
//	case Unauthorized:
//		str_line.Format(_T("SIP/2.0 401 OK\r\n"));
//		break;
//	case Proxy_Authentication:
//		str_line.Format(_T("SIP/2.0 407 OK\r\n"));
//		break;
//	}
//
//	return str_line;
//}
//
//CString CSipPacket::generate_request_line(REQUEST_METHOD method, SIP_URI *request_uri)
//{
//	CString str_value, str_temp;
//
//	switch (method)
//	{
//	case Register:
//		str_value.Format(_T("REGISTER sip:"));
//		break;
//	case Invite:
//		str_value.Format(_T("INVITE sip:"));
//		break;
//	case Ack:
//		str_value.Format(_T("ACK sip:"));
//		break;
//	case Bye:
//		str_value.Format(_T("BYE sip:"));
//		break;
//	}
//	if (!request_uri->user.IsEmpty())
//	{
//		str_value += request_uri->user;
//		str_value += '@';
//	}
//	str_value += request_uri->host;
//	if (request_uri->port > 0)
//	{
//		str_temp.Format(_T(":%d"), request_uri->port);
//		str_value += str_temp;
//	}
//	if (!request_uri->rinstance.IsEmpty())
//	{
//		str_temp.Format(_T(";rinstance=%s"), request_uri->rinstance);
//		str_value += str_temp;
//
//	}
//
//	str_value += " SIP/2.0\r\n";
//
//	return str_value;
//}
//
//BOOL CSipPacket::generate_request_line(CString &strRequestLine,  REQUEST_PARAMETER *request_parameter)
//{
//	CString str_value, str_temp;
//
//	switch (request_parameter.method)
//	{
//	case SipRegister:
//		str_value.Format(_T("REGISTER sip:"));
//		break;
//	case SipInvite:
//		str_value.Format(_T("INVITE sip:"));
//		break;
//	case SipAck:
//		str_value.Format(_T("ACK sip:"));
//		break;
//	case SipBye:
//		str_value.Format(_T("BYE sip:"));
//		break;
//	default:
//		return FALSE;
//		break;
//	}
//	if (!request_parameter.request_uri.user.IsEmpty())
//	{
//		str_value += request_parameter.request_uri.user;
//		str_value += '@';
//	}
//	str_value += request_parameter.request_uri.host;
//	if (request_parameter.request_uri.port > 0)
//	{
//		str_temp.Format(_T(":%d"), request_parameter.request_uri.port);
//		str_value += str_temp;
//	}
//
//	str_value += " SIP/2.0\r\n";
//	strRequestLine = str_value;
//
//	return TRUE;
//}
//
//CString CSipPacket::generate_via_line(HEADER_VIA *HEADER_VIA)
//{
//	CString str_via, str_temp;
//
//	str_via.Format(_T("Via: SIP/2.0/UDP %s:%d;"), HEADER_VIA->sent_address, HEADER_VIA->sent_port);
//	str_temp.Format(_T("branch=%s;"), HEADER_VIA->branch);
//	str_via += str_temp;
//	
//	if (!HEADER_VIA->received_address.IsEmpty())
//	{
//		str_temp.Format(_T("received=%s;"), HEADER_VIA->received_address);
//		str_via += str_temp;
//
//		if (HEADER_VIA->recvived_port > 0)
//		{
//			str_temp.Format(_T("rport=%d\r\n"), HEADER_VIA->recvived_port);
//			str_via += str_temp;
//		}
//	}
//	else
//	{
//		str_temp.Format(_T("rport\r\n"));
//		str_via += str_temp;
//	}
//
//	return str_via;
//}
//
//CString CSipPacket::generate_from_line(HEADER_FROM *HEADER_FROM)
//{
//	CString str_from, str_temp;
//
//	str_from.Format(_T("From: "));
//	if (!HEADER_FROM->display_user.IsEmpty())
//	{
//		str_temp.Format(_T("\"%s\" "), HEADER_FROM->display_user);
//		str_from += str_temp;
//	}
//	str_temp.Format(_T("<sip:%s@%s>"), HEADER_FROM->user, HEADER_FROM->host);
//	str_from += str_temp;
//	if (!HEADER_FROM->tag.IsEmpty())
//	{
//		str_temp.Format(_T(";tag=%s"), HEADER_FROM->tag);
//		str_from += str_temp;
//	}
//	str_from += _T("\r\n");
//
//	return str_from;
//}
//
//CString CSipPacket::generate_to_line(HEADER_TO *HEADER_TO)
//{
//	CString str_to, str_temp;
//
//	str_to.Format(_T("To: "));
//	if (!HEADER_TO->display_info.IsEmpty())
//	{
//		str_temp.Format(_T("\"%s\" "), HEADER_TO->display_info);
//		str_to += str_temp;
//	}
//	str_temp.Format(_T("<sip:%s@%s>"), HEADER_TO->to_user, HEADER_TO->to_host);
//	str_to += str_temp;
//	if (!HEADER_TO->to_tag.IsEmpty())
//	{
//		str_temp.Format(_T(";tag=%s"), HEADER_TO->to_tag);
//		str_to += str_temp;
//	}
//	str_to += _T("\r\n");
//
//	return str_to;
//
//}
//
//CString CSipPacket::generate_contact_line(HEADER_CONTACT *HEADER_CONTACT)
//{
//	CString contact_line, str_temp;
//
//	contact_line.Format(_T("Contact: <sip:%s@%s:%d>"), HEADER_CONTACT->contact_uri.user,
//		HEADER_CONTACT->contact_uri.host, HEADER_CONTACT->contact_uri.port);
//	if (!HEADER_CONTACT->contact_uri.rinstance.IsEmpty())
//	{
//		str_temp.Format(_T(";+sip.instance=%s"), HEADER_CONTACT->contact_uri.rinstance);
//		contact_line += str_temp;
//	}
//	contact_line += _T("\r\n");
//
//	return contact_line;
//}
//
//CString CSipPacket::generate_max_forwards_line(int max_forwards)
//{
//	CString str_max_forwards;
//	if (max_forwards > 0)
//		str_max_forwards.Format(_T("Max-Forwards: %d\r\n"), max_forwards);
//
//	return str_max_forwards;
//}
//
//CString CSipPacket::generate_callid_line(const CString & call_id)
//{
//	CString str_call_id;
//
//	str_call_id.Format(_T("Call-ID: %s\r\n"), call_id);
//
//	return str_call_id;
//}
//
//CString  CSipPacket::generate_cseq_line(HEADER_CSEQ *HEADER_CSEQ)
//{
//	CString str_cseq, str_method;
//
//	switch (HEADER_CSEQ->method)
//	{
//	case Register:
//		str_method = _T("REGISTER");
//		break;
//	case Invite:
//		str_method = _T("INVITE");
//		break;
//	case Ack:
//		str_method = _T("ACK");
//		break;
//	case Bye:
//		str_method = _T("BYE");
//		break;
//	}
//	str_cseq.Format(_T("CSeq: %d %s\r\n"), HEADER_CSEQ->cseq, str_method);
//
//	
//	return str_cseq;
//}
//
//CString CSipPacket::generate_expires_line(int expires)
//{
//	CString value;
//	if (expires >= 0)
//		value.Format(_T("Expires: %d\r\n"), expires);
//	return value;
//}
//
//CString CSipPacket::generate_route_line(CString route)
//{
//	CString str_route;
//
//	str_route.Format(_T("Route: %s\r\n"), route);
//
//	return str_route;
//}
//
//CString CSipPacket::generate_record_route_line(CString route)
//{
//	CString str_route;
//
//	str_route.Format(_T("Record-Route: %s\r\n"), route);
//
//	return str_route;
//}
//
//CString CSipPacket::generate_content_type_line(const CString & content_type)
//{
//	CString str_content_type;
//
//	str_content_type.Format(_T("Content-Type: %s\r\n"), content_type);
//
//	return str_content_type;
//}
//
//CString CSipPacket::generate_content_type_length_line(int content_length)
//{
//	CString str_content_type_length;
//
//	str_content_type_length.Format(_T("Content-Length: %d\r\n"), content_length);
//
//	return str_content_type_length;
//}
//
//CString CSipPacket::generate_digest_auth_line(DIGEST_AUTH_PAR *digest_auth_par)
//{
//	CString auth;
//
//
//	if (NULL != digest_auth_par)
//	{
//		auth.Format(_T("Authorization: Digest username=\"%s\",realm=\"%s\",nonce=\"%s\",uri=\"%s\",response=\"%s\",algorithm=MD5\r\n"),
//			digest_auth_par->name, digest_auth_par->realm, digest_auth_par->nonce, digest_auth_par->uri, digest_auth_par->response);
//	}
//
//	return auth;
//}

// BOOL CSipPacketInfo::get_via(HEADER_VIA &via_par, int index)
//{
//	if (index<0 || index>m_array_via.GetCount() - 1)
//		return FALSE;
//	via_par.branch = m_array_via.GetAt(index)->branch;
//	via_par.sent_address = m_array_via.GetAt(index)->sent_address;
//	via_par.sent_port = m_array_via.GetAt(index)->sent_port;
//	via_par.received_address = m_array_via.GetAt(index)->received_address;
//	via_par.recvived_port = m_array_via.GetAt(index)->recvived_port;
//
//	return TRUE;
//}

CString HEADER_ROUTE::to_string() const
{
	CString string;
	string.Format(_T("Route: <sip:%s;%s>\r\n"), host, parameter);
	return string;
}

BOOL HEADER_ROUTE::from_string(const CString & string)
{

	if (string.IsEmpty())
		return FALSE;

	int i = 0, j = 0;
	i = string.Find(_T("<sip"));
	if (i < 0)
		return FALSE;
	i += strlen("<sip:");
	j = string.Find(';', i);
	if (j < 0)
		return FALSE;
	host = string.Mid(i, j - i);

	i = string.Find('>');
	if (i >= 0)
		parameter = string.Mid(j + 1, i - j - 1);
	else
		return FALSE;


	return TRUE;
}

void delete_mess_body(MESS_BODY * pBody)
{
	if (pBody == NULL)
		return;

	if (pBody->type == _T("SDP"))
	{
		if (pBody->data != NULL)
		{
			delete ((CSDP*)pBody->data);
			pBody->data = NULL;
		}
	}

	pBody->len = 0;

	delete pBody;

}
