#pragma once
#include "stdafx.h"
#include "SipPacket.h"

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

CSipPacket::CSipPacket()
{
}


CSipPacket::~CSipPacket()
{
}

//BOOL CSipPacket::from_buffer(char * buffer, int buffer_len)
//{
//	if (NULL == buffer || buffer < 0)
//		return FALSE;
//	
//	m_data = new unsigned char[buffer_len];
//	memcpy(m_data, buffer, buffer_len);
//	m_data_len = buffer_len;
//	return TRUE;
//}
//
//BOOL CSipPacket::build_register_request(CString username, CString password, CString server_addr,
//	WORD server_port, CString local_addr, WORD local_port, int cseq)
//{
//	REQUEST_PARAMETER request_par;
//	VIA_PARAMETER via_par;
//	FROM_PARAMETER from_par;
//	TO_PARAMETER to_par;
//	CONTACT_PARAMETER contact_par;
//	CSEQ_PARAMETER cseq_par;
//	int max_forward = 70;
//	CString call_id, random_string, sta_packet;
//	char *packet = NULL;
//
//	
//	request_par.method = SipRegister;
//	request_par.request_uri.host = server_addr;
//	request_par.request_uri.port = 0;
//
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	random_string.Insert(0, _T("z9hG4bK"));
//	via_par.sent_address = local_addr;
//	via_par.sent_port = local_port;
//	via_par.branch = random_string;
//
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	from_par.display_info = username;
//	from_par.from_user = username;
//	from_par.from_host = server_addr;
//	from_par.from_tag = random_string;
//
//	to_par.display_info = username;
//	to_par.to_user = username;
//	to_par.to_host = server_addr;
//
//	random_string.Format(_T("%d"), random_contact_user());
//	contact_par.contact_uri.user = random_string;
//	contact_par.contact_uri.host = local_addr;
//	contact_par.contact_uri.port = local_port;
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	contact_par.parameter = random_string;
//
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	call_id = random_string;
//
//	cseq_par.cseq = cseq;
//	cseq_par.method = SipRegister;
//
//
//	random_string = generate_request(request_par);
//	sta_packet += random_string;
//
//	random_string = generate_via(via_par);
//	sta_packet += random_string;
//
//	random_string = generate_max_forwards(max_forward);
//	sta_packet += random_string;
//
//	random_string = generate_from(from_par);
//	sta_packet += random_string;
//
//	random_string = generate_to(to_par);
//	sta_packet += random_string;
//
//	random_string = generate_contact(contact_par);
//	sta_packet += random_string;
//
//	random_string = generate_call_id(call_id);
//	sta_packet += random_string;
//
//	random_string = generate_cseq(cseq_par);
//	sta_packet += random_string;
//
//	sta_packet += _T("\r\n");
//
//	USES_CONVERSION;
//	packet = T2A(sta_packet);
//	if (NULL == packet)
//		return FALSE;
//	m_data_len = sta_packet.GetLength();
//	m_data = new unsigned char[m_data_len];
//	if (NULL == m_data)
//		return FALSE;
//	memcpy(m_data, packet, m_data_len);
//
//
//	return TRUE;
//}
//
//BOOL CSipPacket::builf_invite_request(CString call_name, CString username, CString contact_user,
//	CString server_addr, WORD server_port, CString local_addr, WORD local_port, int cseq,
//	const CString &str_sdp)
//{
//
//	REQUEST_PARAMETER request_par;
//	VIA_PARAMETER via_par;
//	FROM_PARAMETER from_par;
//	TO_PARAMETER to_par;
//	CONTACT_PARAMETER contact_par;
//	CSEQ_PARAMETER cseq_par;
//	int max_forward = 70, content_length;
//	CString call_id, random_string, str_packet, content_type, content_type_length;
//	char *packet = NULL;
//
//
//	request_par.method = SipInvite;
//	request_par.request_uri.user = call_name;
//	request_par.request_uri.host = server_addr;
//	request_par.request_uri.port = 0;
//
//	via_par.sent_address = local_addr;
//	via_par.sent_port = local_port;
//	via_par.recvived_port = 0;
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	random_string.Insert(0, _T("z9hG4bK"));
//	via_par.branch = random_string;
//
//	from_par.display_info = username;
//	from_par.from_user = username;
//	from_par.from_host = server_addr;
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	from_par.from_tag = random_string;
//
//	//to_par.display_info = call_name;
//	to_par.to_user = call_name;
//	to_par.to_host = server_addr;
//
//	contact_par.contact_uri.user = contact_user;
//	contact_par.contact_uri.host = local_addr;
//	contact_par.contact_uri.port = local_port;
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	contact_par.parameter = random_string;
//
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	call_id = random_string;
//
//	cseq_par.cseq = cseq;
//	cseq_par.method = SipInvite;
//
//	content_type = _T("Content-Type: application/sdp\r\n");
//	content_length = str_sdp.GetLength();
//	content_type_length.Format(_T("Content-Length: %d\r\n"), content_length);
//
//	random_string = generate_request(request_par);
//	str_packet += random_string;
//
//	random_string = generate_via(via_par);
//	str_packet += random_string;
//
//	random_string = generate_max_forwards(max_forward);
//	str_packet += random_string;
//
//	random_string = generate_from(from_par);
//	str_packet += random_string;
//
//	random_string = generate_to(to_par);
//	str_packet += random_string;
//
//	random_string = generate_contact(contact_par);
//	str_packet += random_string;
//
//	random_string = generate_call_id(call_id);
//	str_packet += random_string;
//
//	random_string = generate_cseq(cseq_par);
//	str_packet += random_string;
//
//	str_packet += content_type;
//	str_packet += content_type_length;
//	str_packet += _T("\r\n");
//	//sdp
//	str_packet += str_sdp;
//
//	USES_CONVERSION;
//	packet = T2A(str_packet);
//	if (NULL == packet)
//		return FALSE;
//	m_data_len = str_packet.GetLength();
//	m_data = new unsigned char[m_data_len];
//	if (NULL == m_data)
//		return FALSE;
//	memcpy(m_data, packet, m_data_len);
//
//	return TRUE;
//}
//
//BOOL CSipPacket::builf_ack_request(CSipPacketInfo *inv_status_packet_info, CString local_addr,
//	WORD local_port)
//{
//	if (NULL == inv_status_packet_info)
//		return FALSE;
//
//	REQUEST_PARAMETER request_par;
//	VIA_PARAMETER via_par;
//	FROM_PARAMETER from_par;
//	TO_PARAMETER to_par;
//	CONTACT_PARAMETER recv_contact;
//	CSEQ_PARAMETER cseq_par;
//	int max_forward = 70;
//	CString call_id, random_string, str_packet, route;
//	char *packet = NULL;
//
//
//
//	request_par.method = SipAck;
//	if (!inv_status_packet_info->get_contact(recv_contact, 0))
//		return FALSE;
//	request_par.request_uri.user = recv_contact.contact_uri.user;
//	request_par.request_uri.host = recv_contact.contact_uri.host;//
//	request_par.request_uri.port = recv_contact.contact_uri.port;
//
//	via_par.sent_address = local_addr;
//	via_par.sent_port = local_port;
//	via_par.recvived_port = 0;
//	if (!NewGUIDString(random_string))
//		return FALSE;
//	random_string.Insert(0, _T("z9hG4bK"));
//	via_par.branch = random_string;
//
//	from_par = inv_status_packet_info->get_from();
//	to_par = inv_status_packet_info->get_to();
//	call_id = inv_status_packet_info->get_call_id();
//	cseq_par.cseq = inv_status_packet_info->get_cseq().cseq;
//	cseq_par.method = SipAck;
//	route = inv_status_packet_info->get_route();
//
//	random_string = generate_request(request_par);
//	str_packet += random_string;
//
//	random_string = generate_via(via_par);
//	str_packet += random_string;
//
//	random_string = generate_max_forwards(max_forward);
//	str_packet += random_string;
//
//	random_string = generate_from(from_par);
//	str_packet += random_string;
//
//	random_string = generate_to(to_par);
//	str_packet += random_string;
//
//	random_string = generate_call_id(call_id);
//	str_packet += random_string;
//
//	random_string = generate_cseq(cseq_par);
//	str_packet += random_string;
//
//	random_string = generate_route(route);
//	str_packet += random_string;
//
//	str_packet += _T("\r\n");
//
//	USES_CONVERSION;
//	packet = T2A(str_packet);
//	if (NULL == packet)
//		return FALSE;
//	m_data_len = str_packet.GetLength();
//	m_data = new unsigned char[m_data_len];
//	if (NULL == m_data)
//		return FALSE;
//	memcpy(m_data, packet, m_data_len);
//	return TRUE;
//}
//
//BOOL CSipPacket::build_ok_status(CSipPacketInfo *request_packet, CString local_addr,
//	WORD local_portint, CString contact_user, CSDP sdp,  STATUS_CODE status_code)
//{
//	if (NULL == request_packet)
//		return FALSE;
//
//	VIA_PARAMETER via_par;
//	FROM_PARAMETER from_par;
//	TO_PARAMETER to_par;
//	CONTACT_PARAMETER contact_par;
//	CSEQ_PARAMETER cseq_par;
//	int max_forward = 70, content_length;
//	CString str_packet, str_line, str_temp;
//	char *packet = NULL;
//
//	str_line = generate_status(status_code);
//	str_packet += str_line;
//
//	for (int i = 0; i < request_packet->get_via_array_length(); i++)
//	{
//		if (!request_packet->get_via(via_par, i))
//			return FALSE;
//		str_line = generate_via(via_par);
//		str_packet += str_line;
//	}
//	
//	str_line = generate_record_route(request_packet->get_route());
//	str_packet += str_line;
//
//	str_temp = request_packet->get_call_id();
//	str_line = generate_call_id(str_temp);
//	str_packet += str_line;
//
//	from_par = request_packet->get_from();
//	str_line = generate_from(from_par);
//	str_packet += str_line;
//
//	if (!NewGUIDString(str_temp)) return FALSE;
//	to_par = request_packet->get_to();
//	to_par.to_tag = str_temp;
//	str_line = generate_to(to_par);
//	str_packet += str_line;
//
//	cseq_par = request_packet->get_cseq();
//	str_line = generate_cseq(cseq_par);
//	str_packet += str_line;
//	
//	contact_par.contact_uri.user = contact_user;
//	contact_par.contact_uri.host = local_addr;
//	contact_par.contact_uri.port = local_portint;
//	str_line = generate_contact(contact_par);
//	str_packet += str_line;
//
//	str_line = generate_content_type(_T("application/sdp"));
//	str_packet += str_line;
//
//	str_temp = sdp.to_buffer();
//	str_line = generate_content_type_length(str_temp.GetLength());
//	str_packet += str_line;
//	str_packet += _T("\r\n");
//	//sdp
//	str_packet += str_temp;
//
//	USES_CONVERSION;
//	packet = T2A(str_packet);
//	if (NULL == packet)
//		return FALSE;
//	m_data_len = str_packet.GetLength();
//	m_data = new unsigned char[m_data_len];
//	if (NULL == m_data)
//		return FALSE;
//	memcpy(m_data, packet, m_data_len);
//
//	return TRUE;
//}

//BOOL CSipPacket::build_register_request(CString str_server_addr, WORD server_port,
//	CString str_local_addr, WORD local_port, CString username, CString password)
//{
//	if (str_server_addr.IsEmpty() || str_local_addr.IsEmpty())
//		return FALSE;
//
//	REQUEST_PARAMETER request_parameter;
//	SIP_VIA via;
//	SIP_FROM from;
//	SIP_TO to;
//	SIP_CONTACT contact;
//	SIP_CSEQ cseq;
//	CString random_string, value_line, str_temp;
//
//	request_parameter.method = SipRegister;
//	request_parameter.request_uri.host = str_server_addr;
//	value_line = generate_request_line(request_parameter);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	random_string.Insert(0, _T("z9hG4bK"));
//	via.sent_address = str_local_addr;
//	via.sent_port = local_port;
//	via.branch = random_string;
//	value_line = generate_via_line(via);
//	m_data += value_line;
//
//	value_line = generate_max_forwards(70);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	from.display_info = username;
//	from.from_user = username;
//	from.from_host = str_server_addr;
//	from.from_tag = random_string;
//	value_line = generate_from_line(from);
//	m_data += value_line;
//
//	//自己接收
//	to.display_info = username;
//	to.to_user = username;
//	to.to_host = str_server_addr;
//	value_line = generate_to_line(to);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	str_temp.Format(_T("+sip.instance=<%s>"), random_string);
//	m_contact_user.Format(_T("%s"), random_contact_user());
//	contact.contact_uri.user.Format(_T("%s"), m_contact_user);
//	contact.contact_uri.host = str_local_addr;
//	contact.contact_uri.port = local_port;
//	contact.parameter = str_temp;
//	value_line = generate_contact_line(contact);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	value_line = generate_call_id(random_string);
//	m_data += value_line;
//
//	cseq.method = SipRegister;
//	cseq.cseq = ++m_register_cseq;
//	value_line =generate_cseq(cseq);
//	m_data += value_line;
//
//	m_data += _T("\r\n");
//
//	return TRUE;
//}
//
//BOOL CSipPacket::build_invite_request(CString str_server_addr, WORD server_port,
//	CString str_local_addr, WORD local_port, CString username, CString call_name,
//	unsigned char * sdp, int sdp_len)
//{
//	if (str_server_addr.IsEmpty() || str_local_addr.IsEmpty()||NULL == sdp)
//		return FALSE;
//
//	REQUEST_PARAMETER request_parameter;
//	SIP_VIA via;
//	SIP_FROM from;
//	SIP_TO to;
//	SIP_CONTACT contact;
//	SIP_CSEQ cseq;
//	CString random_string, value_line, str_temp;
//
//	request_parameter.method = SipInvite;
//	request_parameter.request_uri.user = call_name;
//	request_parameter.request_uri.host = str_server_addr;
//	value_line = generate_request_line(request_parameter);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	random_string.Insert(0, _T("z9hG4bK"));
//	via.sent_address = str_local_addr;
//	via.sent_port = local_port;
//	via.branch = random_string;
//	value_line = generate_via_line(via);
//	m_data += value_line;
//
//	value_line = generate_max_forwards(70);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	from.display_info = username;
//	from.from_user = username;
//	from.from_host = str_server_addr;
//	from.from_tag = random_string;
//	value_line = generate_from_line(from);
//	m_data += value_line;
//
//	//to.display_info = username;
//	to.to_user = call_name;
//	to.to_host = str_server_addr;
//	value_line = generate_to_line(to);
//	m_data += value_line;
//
//	//if (!NewGUIDString(random_string))
//	//	return false;
//	//str_temp.Format(_T("+sip.instance=<%s>"), random_string);
//	contact.contact_uri.user.Format(_T("%d"), m_contact_user);
//	contact.contact_uri.host = str_local_addr;
//	contact.contact_uri.port = local_port;
//	//contact.parameter = str_temp;
//	value_line = generate_contact_line(contact);
//	m_data += value_line;
//
//	if (!NewGUIDString(random_string))
//		return false;
//	value_line = generate_call_id(random_string);
//	m_data += value_line;
//
//	cseq.method = SipRegister;
//	cseq.cseq = ++m_register_cseq;
//	value_line = generate_cseq(cseq);
//	m_data += value_line;
//
//	m_data += _T("\r\n");
//
//	return TRUE;
//}

//unsigned char * CSipPacket::get_data(int &data_len)
//{
//	unsigned char * data = NULL;
//
//	if (m_data_len > 0)
//	{
//		data = new unsigned char[m_data_len];
//		if (NULL != data)
//		{
//			memcpy(data, m_data, m_data_len);
//			data_len = m_data_len;
//		}
//	}
//
//	return data;
//}



BOOL CSipPacket::generate_status_line(CString &strStatusLine, STATUS_CODE status_code)
{
	CString str_line;

	switch (status_code)
	{
	case trying:
		str_line.Format(_T("SIP/2.0 100 Trying\r\n"));
		break;
	case ringing:
		str_line.Format(_T("SIP/2.0 180 Ringing\r\n"));
		break;
	case ok:
		str_line.Format(_T("SIP/2.0 200 OK\r\n"));
		break;
	default:
		return FALSE;
		break;
	}
	strStatusLine = str_line;

	return TRUE;
}

BOOL CSipPacket::generate_request_line(CString &strRequestLine,  REQUEST_PARAMETER request_parameter)
{
	CString str_value, str_temp;

	switch (request_parameter.method)
	{
	case SipRegister:
		str_value.Format(_T("REGISTER sip:"));
		break;
	case SipInvite:
		str_value.Format(_T("INVITE sip:"));
		break;
	case SipAck:
		str_value.Format(_T("ACK sip:"));
		break;
	case SipBye:
		str_value.Format(_T("BYE sip:"));
		break;
	default:
		return FALSE;
		break;
	}
	if (!request_parameter.request_uri.user.IsEmpty())
	{
		str_value += request_parameter.request_uri.user;
		str_value += '@';
	}
	str_value += request_parameter.request_uri.host;
	if (request_parameter.request_uri.port > 0)
	{
		str_temp.Format(_T(":%d"), request_parameter.request_uri.port);
		str_value += str_temp;
	}

	str_value += " SIP/2.0\r\n";
	strRequestLine = str_value;

	return TRUE;
}

CString CSipPacket::generate_via_line(VIA_PARAMETER via_parameter)
{
	CString str_via, str_temp;

	str_via.Format(_T("Via: SIP/2.0/UDP %s:%d;"), via_parameter.sent_address, via_parameter.sent_port);
	if (!via_parameter.received_address.IsEmpty())
	{
		str_temp.Format(_T("received=%s;"), via_parameter.received_address);
		str_via += str_temp;
	}
	if (via_parameter.recvived_port > 0)
	{
		str_temp.Format(_T("rport=%d;"), via_parameter.recvived_port);
		str_via += str_temp;
	}
	str_temp.Format(_T("branch=%s\r\n"), via_parameter.branch);
	str_via += str_temp;

	return str_via;
}

CString CSipPacket::generate_from_line(FROM_PARAMETER from_parameter)
{
	CString str_from, str_temp;

	str_from.Format(_T("From: "));
	if (!from_parameter.display_info.IsEmpty())
	{
		str_temp.Format(_T("\"%s\" "), from_parameter.display_info);
		str_from += str_temp;
	}
	str_temp.Format(_T("<sip:%s@%s>"), from_parameter.from_user, from_parameter.from_host);
	str_from += str_temp;
	if (!from_parameter.from_tag.IsEmpty())
	{
		str_temp.Format(_T(";tag=%s"), from_parameter.from_tag);
		str_from += str_temp;
	}
	str_from += _T("\r\n");

	return str_from;
}

CString CSipPacket::generate_to_line(TO_PARAMETER to_parameter)
{
	CString str_to, str_temp;

	str_to.Format(_T("To: "));
	if (!to_parameter.display_info.IsEmpty())
	{
		str_temp.Format(_T("\"%s\" "), to_parameter.display_info);
		str_to += str_temp;
	}
	str_temp.Format(_T("<sip:%s@%s>"), to_parameter.to_user, to_parameter.to_host);
	str_to += str_temp;
	if (!to_parameter.to_tag.IsEmpty())
	{
		str_temp.Format(_T(";tag=%s"), to_parameter.to_tag);
		str_to += str_temp;
	}
	str_to += _T("\r\n");

	return str_to;

}

CString CSipPacket::generate_contact_line(CONTACT_PARAMETER contact_parameter)
{
	CString contact_line, str_temp;

	contact_line.Format(_T("Contact: <sip:%s@%s:%d>"), contact_parameter.contact_uri.user,
		contact_parameter.contact_uri.host, contact_parameter.contact_uri.port);
	if (!contact_parameter.parameter.IsEmpty())
	{
		str_temp.Format(_T(";+sip.instance=%s"), contact_parameter.parameter);
		contact_line += str_temp;
	}
	contact_line += _T("\r\n");

	return contact_line;
}

CString CSipPacket::generate_max_forwards_line(int max_forwards)
{
	CString str_max_forwards;

	str_max_forwards.Format(_T("Max-Forwards: %d\r\n"), max_forwards);

	return str_max_forwards;
}

CString CSipPacket::generate_callid_line(const CString & call_id)
{
	CString str_call_id;

	str_call_id.Format(_T("Call-ID: %s\r\n"), call_id);

	return str_call_id;
}

BOOL CSipPacket::generate_cseq_line(CString &strCSeqLine, CSEQ_PARAMETER cseq_parameter)
{
	CString str_cseq, str_method;

	switch (cseq_parameter.method)
	{
	case SipRegister:
		str_method = _T("REGISTER");
		break;
	case SipInvite:
		str_method = _T("INVITE");
		break;
	case SipAck:
		str_method = _T("ACK");
		break;
	case SipBye:
		str_method = _T("BYE");
		break;
	default:
		return FALSE;
		break;
	}
	str_cseq.Format(_T("CSeq: %d %s\r\n"), cseq_parameter.cseq, str_method);
	strCSeqLine = str_cseq;

	
	return TRUE;
}

CString CSipPacket::generate_route_line(CString route)
{
	CString str_route;

	str_route.Format(_T("Route: %s\r\n"), route);

	return str_route;
}

CString CSipPacket::generate_record_route_line(CString route)
{
	CString str_route;

	str_route.Format(_T("Record-Route: %s\r\n"), route);

	return str_route;
}

CString CSipPacket::generate_content_type_line(const CString & content_type)
{
	CString str_content_type;

	str_content_type.Format(_T("Content-Type: %s\r\n"), content_type);

	return str_content_type;
}

CString CSipPacket::generate_content_type_length_line(int content_length)
{
	CString str_content_type_length;

	str_content_type_length.Format(_T("Content-Length: %d\r\n"), content_length);

	return str_content_type_length;
}

void CSipPacket::build_packet(const CStringArray & arrLineData)
{
	for (int i = 0; i < arrLineData.GetSize(); i++)
	{
		m_strData += arrLineData.GetAt(i);
	}
}

CString CSipPacket::get_packet_data()
{
	return m_strData;
}


BOOL CSipPacket::NewGUIDString(CString & strGUID)
{
	GUID guid;
	char data[1024] = { 0 };
	int len = 0;

	if (S_OK != ::CoCreateGuid(&guid))
		return FALSE;
	len = sprintf_s(data, 1024, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1],
		guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5],
		guid.Data4[6], guid.Data4[7]);

	if (len <= 0)
		return FALSE;
	strGUID = data;

	return TRUE;
}

int CSipPacket::new_random_user()
{
	int random = 0, num = 0;
	LARGE_INTEGER seed;

	for (int i = 0; i < 8; i++)
	{
		QueryPerformanceFrequency(&seed);
		QueryPerformanceCounter(&seed);
		srand(seed.QuadPart);//初始化一个以微秒为单位的时间种子
		random = rand() % 10;//产生一个随机数
		num = num * 10 + random;
	}

	return num;
}

CSipPacketInfo::CSipPacketInfo()
{
}

CSipPacketInfo::~CSipPacketInfo()
{
}

BOOL CSipPacketInfo::from_packet(CSipPacket * packet)
{
	if (NULL == packet)
		return FALSE;
	
	char *data = NULL;
	int i = 0, j = 0, flag = 0;
	CString str_data, str_line;


	str_data = packet->get_packet_data();
	//request/status
	i= str_data.Find(_T("\r\n"));
	if (i < 0)
		return FALSE;
	str_line = str_data.Left(i);
	if (!request_status_to_parameter(m_type, m_status_code, m_request_parameter, str_line))
		return FALSE;
	//via
	i = 0, j = 0;
	while (1)
	{
		i = str_data.Find(_T("Via"), j);
		if (i < 0)
			break;
		j = str_data.Find(_T("\r\n"), i);
		if (j < 0)
			break;
		str_line = str_data.Mid(i, j - i);
		VIA_PARAMETER *via_par = new VIA_PARAMETER;
		if (NULL == via_par)
			return FALSE;
		if (!viastr_to_viapar(*via_par, str_line))
			return FALSE;
		m_array_via.Add(via_par);
	}
	if (m_array_via.GetCount() <= 0)
		return FALSE;
	//contact
	i = 0, j = 0;
	while (1)
	{
		i = str_data.Find(_T("Contact"), j);
		if (i < 0)
			break;
		j = str_data.Find(_T("\r\n"), i);
		if (j < 0)
			break;
		str_line = str_data.Mid(i, j - i);
		CONTACT_PARAMETER *contact_par = new CONTACT_PARAMETER;
		if (NULL == contact_par)
			return FALSE;
		if (!contactstr_to_contactpar(*contact_par, str_line))
			return FALSE;
		m_array_contact.Add(contact_par);
	}
	//from
	i = str_data.Find(_T("From"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!fromstr_to_frompar(m_from, str_line))
				return FALSE;
		}
	}
	//to
	i = str_data.Find(_T("To"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!tostr_to_topar(m_to, str_line))
				return FALSE;
		}
	}
	//call_id
	i = str_data.Find(_T("Call-ID"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!callidstr_to_callid(m_call_id, str_line))
				return FALSE;
		}
	}
	//cseq
	i = str_data.Find(_T("CSeq"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!cseqstr_to_cseqpar(m_cseq, str_line))
				return FALSE;
		}
	}

	//content type
	i = str_data.Find(_T("Content-Type"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!content_type_string_to_type(m_content_type, str_line))
				return FALSE;
		}
	}
	//content length
	i = str_data.Find(_T("Content-Length"), 0);
	if (i > 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
		{
			str_line = str_data.Mid(i, j - i);
			if (!content_type_length_string_to_length(m_content_length, str_line))
				return FALSE;
		}
	}
	//route
	i = str_data.Find(_T("Route"));
	if (i > 0)
	{
		i += strlen("Route: ");
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
			m_route = str_data.Mid(i, j - i);
	}

	//sdp
	i = str_data.Find(_T("\r\n\r\nv="));
	if (i > 0)
	{
		i += strlen("\r\n\r\nv=");
		str_line = str_data.Right(str_data.GetLength() - i);
		USES_CONVERSION;
		data = T2A(str_line);
		if (NULL == data)
			return FALSE;
		if (!m_sdp_info.from_buffer(data, str_data.GetLength() - i))
			return FALSE;
	}


	return TRUE;
}

//BOOL CSipPacketInfo::from_buffer(char * buffer, int buffer_len)
//{
//	return 0;
//}

MESSAGE_TYPE CSipPacketInfo::get_type()
{
	return m_type;
}

REQUEST_PARAMETER CSipPacketInfo::get_request_para()
{
	return m_request_parameter;
}

STATUS_CODE CSipPacketInfo::get_status_code()
{
	
	return m_status_code;
}

CString CSipPacketInfo::get_call_id()
{
	return m_call_id;
}

FROM_PARAMETER CSipPacketInfo::get_from()
{
	return m_from;
}

TO_PARAMETER CSipPacketInfo::get_to()
{
	return m_to;
}

CSEQ_PARAMETER CSipPacketInfo::get_cseq()
{
	
	return m_cseq;
}

int CSipPacketInfo::get_max_forwards()
{
	return 70;
}

int CSipPacketInfo::get_via_array_length()
{
	return m_array_via.GetCount();
}

 BOOL CSipPacketInfo::get_via(VIA_PARAMETER &via_par, int index)
{
	if (index<0 || index>m_array_via.GetCount() - 1)
		return FALSE;
	via_par.branch = m_array_via.GetAt(index)->branch;
	via_par.sent_address = m_array_via.GetAt(index)->sent_address;
	via_par.sent_port = m_array_via.GetAt(index)->sent_port;
	via_par.received_address = m_array_via.GetAt(index)->received_address;
	via_par.recvived_port = m_array_via.GetAt(index)->recvived_port;

	return TRUE;
}

int CSipPacketInfo::get_contact_array_length()
{
	return m_array_contact.GetCount();
}

 BOOL CSipPacketInfo::get_contact(CONTACT_PARAMETER &contact_par, int index)
{
	 if (index<0 || index>m_array_contact.GetCount() - 1)
		 return FALSE;
	 contact_par = *(m_array_contact.GetAt(index));
	 return TRUE;
}

 CString CSipPacketInfo::get_route()
 {
	 return m_route;
 }

CString CSipPacketInfo::get_content_type()
{
	return m_content_type;
}

int CSipPacketInfo::get_content_length()
{
	return m_content_length;
}

CSDP CSipPacketInfo::get_sdp_info()
{
	return m_sdp_info;
}

DWORD CSipPacketInfo::get_time()
{
	return m_create_time;
}

void CSipPacketInfo::set_time(DWORD time)
{
	m_create_time = time;
}

BOOL CSipPacketInfo::viastr_to_viapar(VIA_PARAMETER & via, const CString & string)
{
	int i = 0, j = 0;

	i = string.Find(' ', 5);
	if (i < 0)
		return FALSE;
	j = string.Find(':', i);
	via.sent_address = string.Mid(i + 1, j - i - 1);
	i = string.Find(';', j);
	via.sent_port = _ttoi(string.Mid(j + 1, i - j - 1));
	i = string.Find(_T("branch"));
	if (i < 0)
		return FALSE;
	i += strlen("branch=");
	j = string.Find(';', i);
	if (j > 0)
	{
		via.branch = string.Mid(i, j - i);
	}
	else
	{
		via.branch = string.Right(string.GetLength() - i);
	}


	i = string.Find(_T("received"));
	if (i > 0)
	{
		j = string.Find(';', i);
		if (j > 0)
		{
			via.received_address = string.Mid(i + strlen("recvived="), j - (i + strlen("recvived=")));
		}
	}
	

	return TRUE;
}

BOOL CSipPacketInfo::request_status_to_parameter(MESSAGE_TYPE & type, STATUS_CODE & status_code,
	REQUEST_PARAMETER & request, const CString & string)
{
	CString str_temp;
	int i = 0, j = 0, num = 0;
	
	i = string.Find(' ');
	if (i < 0)
		return FALSE;
	str_temp = string.Left(i);
	if (0 == str_temp.Compare(_T("SIP/2.0")))
	{
		type = sip_status;
		j = string.Find(' ', i + 1);
		num = _ttoi(string.Mid(i + 1, j - i - 1));
		switch (num)
		{
		case 100:
			status_code = trying;
			break;
		case 180:
			status_code = ringing;
			break;
		case 200:
			status_code = ok;
			break;
		default:
			status_code = other_status;
			break;
		}
	}
	else
	{
		type = sip_request;
		//method 必须
		if (0 == str_temp.Compare(_T("REGISTER")))
			request.method = SipRegister;
		else if (0 == str_temp.Compare(_T("INVITE")))
			request.method = SipInvite;
		else if (0 == str_temp.Compare(_T("ACK")))
			request.method = SipAck;
		else if (0 == str_temp.Compare(_T("BYE")))
			request.method = SipBye;
		else
			request.method = other_method;
		//uri
		i = string.Find(_T("sip:"));
		j = string.Find(' ', i);
		if (i < 0 || j < 0)return FALSE;
		i += strlen("sip:");
		str_temp = string.Mid(i , j - i);
		i = str_temp.Find('@');
		if (i > 0)
			request.request_uri.user = str_temp.Left(i);
		else
		{
			j = str_temp.Find(':');
			if (j > 0)
			{
				request.request_uri.port = _ttoi(str_temp.Right(str_temp.GetLength() - j));
				request.request_uri.host = str_temp.Left(j);
			}
			else
			{
				request.request_uri.port = 0;
				request.request_uri.host = str_temp;
			}
		}
	}
	
	return TRUE;
}

BOOL CSipPacketInfo::fromstr_to_frompar(FROM_PARAMETER & from_par, const CString & string)
{
	int i = 0, j = 0;

	i = string.Find('"');
	if (i > 0)
	{
		i++;
		j = string.Find('"', i);
		if (j > 0)
			from_par.display_info = string.Mid(i, j - i);
	}

	i = string.Find(_T("sip:"));
	if (i < 0)return FALSE;
	i += strlen("sip:");
	j = string.Find('@', i);
	if (j < 0)return FALSE;
	from_par.from_user = string.Mid(i, j - i);

	j++;
	i = string.Find('>', j);
	if (i < 0) return FALSE;
	from_par.from_host = string.Mid(j, i - j);

	j = string.Find(_T("tag"));
	if (j > 0)
	{
		j += strlen("tag=");
		from_par.from_tag = string.Right(string.GetLength() - j);
	}


	return TRUE;
}

BOOL CSipPacketInfo::tostr_to_topar(TO_PARAMETER & to_par, const CString & string)
{
	int i = 0, j = 0;

	i = string.Find('"');
	if (i > 0)
	{
		i++;
		j = string.Find('"', i);
		if (j > 0)
			to_par.display_info = string.Mid(i, j - i);
	}

	i = string.Find(_T("sip:"));
	if (i < 0)return FALSE;
	i += strlen("sip:");
	j = string.Find('@', i);
	if (j < 0)return FALSE;
	to_par.to_user = string.Mid(i, j - i);

	j++;
	i = string.Find('>', j);
	if (i < 0) return FALSE;
	to_par.to_host = string.Mid(j, i - j);

	j = string.Find(_T("tag"));
	if (j > 0)
	{
		j += strlen("tag=");
		to_par.to_tag = string.Right(string.GetLength() - j);
	}

	return TRUE;
}

BOOL CSipPacketInfo::contactstr_to_contactpar(CONTACT_PARAMETER & contact_par, const CString & string)
{
	int i = 0, j = 0;
	CString str_temp;


	i = string.Find(_T("<sip:"));
	if (i < 0)return FALSE;
	i += strlen("<sip:");
	j = string.Find('>', i);
	if (j < 0)return FALSE;
	str_temp = string.Mid(i, j - i);
	i = str_temp.Find('@');
	j = str_temp.Find(':');
	if (i < 0 || j < 0) return FALSE;
	contact_par.contact_uri.user = str_temp.Left(i);
	contact_par.contact_uri.host = str_temp.Mid(i + 1, j - i - 1);
	contact_par.contact_uri.port = _ttoi(str_temp.Right(str_temp.GetLength() - j-1));


	//i = string.Find(_T("sip:"));
	//if (i > 0)
	//{
	//	i += strlen("sip:");
	//	j = string.Find('@', i);
	//	if (j > 0)
	//	{
	//		contact_par.contact_uri.user = string.Mid(i, j - i);
	//		i = string.Find(':', j);
	//		if (i > 0)
	//		{
	//			j++;
	//			contact_par.contact_uri.host = string.Mid(j, i - j);
	//			j = string.Find(' ', i);
	//			if (j > 0)
	//				contact_par.contact_uri.port = _ttoi(string.Mid(i, j - i - 1));
	//		}
	//	}
	//}


	return TRUE;
}

BOOL CSipPacketInfo::callidstr_to_callid(CString & call_id, const CString & callid_string)
{
	int i = 0, j = 0;

	i = callid_string.Find(' ');
	if (i < 0)return FALSE;
	i++;
	call_id = callid_string.Right(callid_string.GetLength() - i);

	return TRUE;
}

BOOL CSipPacketInfo::cseqstr_to_cseqpar(CSEQ_PARAMETER &cseq_par, const CString & string)
{
	CString temp;
	int i = 0, j = 0;

	i = string.Find(' ');
	if (i < 0)return FALSE;
	i++;
	j = string.Find(' ', i);
	if (j < 0)return FALSE;
	temp = string.Mid(i, j - i);
	cseq_par.cseq = _ttoi(temp);
	


	temp = string.Right(string.GetLength() - j - 1);


	if (temp.Compare(_T("REGISTER")) == 0)
	{
		cseq_par.method = SipRegister;
	}
	else if (temp.Compare(_T("INVITE")) == 0)
	{
		cseq_par.method = SipInvite;
	}
	else if (temp.Compare(_T("ACK")) == 0)
	{
		cseq_par.method = SipAck;
	}
	else if (temp.Compare(_T("BYE")) == 0)
	{
		cseq_par.method = SipBye;
	}
	else
	{
		cseq_par.method = other_method;
	}

	return TRUE;
}

BOOL CSipPacketInfo::content_type_string_to_type(CString & content_type, const CString & string)
{

	return TRUE;
}

BOOL CSipPacketInfo::content_type_length_string_to_length(int & length, const CString & string)
{
	return TRUE;
}

//BOOL CSipPacketInfo::get_via_parameter(CString string)
//{
//	if (string.IsEmpty())
//		return FALSE;
//
//	BOOL ret = FALSE;
//	SIP_VIA *sip_via = new SIP_VIA;
//	
//	int i = 0, j = 0;
//
//	i = string.Find(' ', strlen("Via: ") + 1);
//	if (i < 0)
//		goto end;
//	j = string.Find(':', i);
//	if (j < 0)
//		goto end;
//	sip_via->sent_address = string.Mid(i + 1, j - i - 1);
//	i = string.Find(' ', j);
//	sip_via->sent_port = _ttoi(string.Mid(j + 1, i - j - 1));
//	i = string.Find(_T("branch"));
//	if (i < 0)
//		goto end;
//	j = string.Find(';', i);
//	if (j > 0)
//		sip_via->branch = string.Mid(i + strlen("branch="), j - (i + strlen("branch=")));
//	else
//	{
//		sip_via->branch = string.Mid(i + strlen("branch="));
//		sip_via->branch.Left(sip_via->branch.GetLength() - 1);
//	}
//
//
//	i = string.Find(_T("received"));
//	if (i > 0)
//	{
//		j = string.Find(';', i);
//		sip_via->received_address = string.Mid(i + strlen("received="), j - (i + strlen("received=")));
//	}
//	i = string.Find(_T("rport"));
//	if (i > 0)
//	{
//		j = string.Find(';', i);
//		sip_via->recvived_port = _ttoi(string.Mid(i + strlen("rport="), j - (i + strlen("rport="))));
//	}
//	m_array_via.Add(*sip_via);
//	ret = TRUE;
//
//end:
//	if (!ret)
//	{
//		if (NULL != sip_via)
//			delete sip_via;
//		sip_via = NULL;
//	}
//
//
//	return ret;
//}
//
//BOOL CSipPacketInfo::get_request_status_parameter(CString string)
//{
//	CString str_temp;
//	int i = 0, j = 0, num = 0;
//
//	i = string.Find(' ');
//	if (i < 0)
//		return FALSE;
//	str_temp = string.Left(i);
//	if (0 == str_temp.Compare(_T("SIP/2.0")))
//	{
//		m_type = sip_status;
//		j = string.Find(' ', i + 1);
//		num = _ttoi(string.Mid(i + 1, j - i - 1));
//		switch (num)
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
//	}
//	else
//	{
//		m_type = sip_request;
//		//
//		//str_temp = string.Mid(i + 1, j - i - 1);
//		if (0 == str_temp.Compare(_T("REGISTER")))
//			m_request_parameter.method = SipRegister;
//		else if (0 == str_temp.Compare(_T("INVITE")))
//			m_request_parameter.method = SipInvite;
//		else if (0 == str_temp.Compare(_T("ACK")))
//			m_request_parameter.method = SipAck;
//		else if (0 == str_temp.Compare(_T("BYE")))
//			m_request_parameter.method = SipBye;
//		else
//			m_request_parameter.method = other_method;
//		i = string.Find(':');
//		j = string.Find('@');
//		if (i < 0 || j < 0)
//			return FALSE;
//		m_request_parameter.request_uri.user = string.Mid(i + 1, j - i - 1);
//		i = string.Find(':', j);
//		if (i < 0)
//		{
//			i = string.Find(' ', j);
//			if (i < 0)
//				return FALSE;
//			m_request_parameter.request_uri.host = string.Mid(j + 1, i - j - 1);
//		}
//		else
//		{
//			m_request_parameter.request_uri.host = string.Mid(j + 1, i - j - 1);
//			j = string.Find(' ', i);
//			if (j > 0)
//				m_request_parameter.request_uri.port = _ttoi(string.Mid(i + 1, j - 1 - i));
//		}
//
//		
//
//	}
//
//	return TRUE;
//
//}
//
//BOOL CSipPacketInfo::get_from_parameter(CString string)
//{
//	return 0;
//}