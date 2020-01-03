#pragma once
#include "stdafx.h"
#include "SipPacket.h"





CSipPacket::CSipPacket()
{
	m_data = new BYTE[PACK_SIZE]();
	m_len = 0;
}

CSipPacket::~CSipPacket()
{
	if (NULL != m_data)
	{
		delete m_data;
		m_data = NULL;
	}

	m_len = 0;
}

CSipPacket::CSipPacket(const CSipPacket & p)
{
	m_data = new BYTE[PACK_SIZE]();
	memcpy(m_data, p.m_data, p.m_len);
	m_len = p.m_len;

}

//BOOL CSipPacket::build_request_packet(const REQUEST_PARAMETER & request_par,
//	const VIA_PARAMETER & via_par, const FROM_PARAMETER & from_par,
//	const TO_PARAMETER & to_par, const CString & call_id, 
//	const CSEQ_PARAMETER & cseq, CONTACT_PARAMETER * contact_par, ROUTE_PARAMETER *route,
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

CString CSipPacket::max_forward_to_string(int max_forward)
{
	CString string;

	string.Format(_T("Max-Forwards: %d\r\n"), max_forward);

	return string;
}

CString CSipPacket::call_id_to_string(const CString call_id)
{
	CString string;

	string.Format(_T("Call-ID: %s\r\n"), call_id);

	return string;
}

int CSipPacket::from_buffer(char * buffer, int buffer_len)
{
	if (NULL == buffer || buffer_len <= 0)
		return -1;

	buffer_len > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = buffer_len;

	memcpy(m_data, buffer, m_len);
		
	return m_len;
}

int CSipPacket::get_data(BYTE * buf, int buf_size)
{
	if (NULL == buf || buf_size < m_len + 1)
		return -1;

	memset(buf, 0, buf_size);
	memcpy(buf, m_data, m_len);


	return m_len;
}

BOOL CSipPacket::build_register_request(const REQUEST_PARAMETER & request_par,
	const VIA_PARAMETER & via_par, int max_forward, CONTACT_PARAMETER & contact_par,
	const TO_PARAMETER & to_par, const FROM_PARAMETER & from_par, const CString & call_id,
	const CSEQ_PARAMETER & cseq, const CString & auth_string, const CString & optional_att)
{
	CString packet, str_temp, str_sdp;

	//request line
	str_temp = request_par.to_string();
	packet += str_temp;

	//packet header
	//via
	str_temp = via_par.to_string();
	packet += str_temp;

	if (max_forward > 0)
	{
		str_temp = max_forward_to_string(max_forward);
		packet += str_temp;
	}

	//route
	//if (NULL != route)
	//{
	//	str_temp = route->to_string();
	//	packet += str_temp;
	//}


	//contact
	str_temp = contact_par.to_string();
	packet += str_temp;
	//to
	str_temp = to_par.to_string();
	packet += str_temp;
	//from
	str_temp = from_par.to_string();
	packet += str_temp;
	//call_id
	str_temp = call_id_to_string(call_id);
	packet += str_temp;
	//cseq
	str_temp = cseq.to_string();
	packet += str_temp;
	//auth
	if (!auth_string.IsEmpty())
		packet += auth_string;

	if(!optional_att.IsEmpty())
		packet += optional_att;


	packet += _T("\r\n"); //message header结束符


	char *p = NULL;
	USES_CONVERSION;
	p = T2A(packet);
	if (NULL == p)
		return FALSE;

	packet.GetLength() > PACK_SIZE - 1 ? m_len = PACK_SIZE - 1 : m_len = packet.GetLength();
	memset(m_data, 0, PACK_SIZE);
	memcpy(m_data, p, m_len);


	return TRUE;
}

BOOL CSipPacket::build_inviter_request(const REQUEST_PARAMETER & request_par, const VIA_PARAMETER & via_par, int max_forward, CONTACT_PARAMETER & contact_par, const TO_PARAMETER & to_par, const FROM_PARAMETER & from_par, const CString & call_id, const CSEQ_PARAMETER & cseq, const CSDP & sdp, const CString & auth_string, const CString & optional_att)
{
	return 0;
}

BOOL CSipPacket::build_ack_request(const CSipPacketInfo & status_info, const REQUEST_PARAMETER & request_par, const VIA_PARAMETER & via_par, int max_forward, ROUTE_PARAMETER * route, CONTACT_PARAMETER * contact_par, const TO_PARAMETER & to_par, const FROM_PARAMETER & from_par, const CString & call_id, const CSEQ_PARAMETER & cseq, const CString & auth_string, const CString & optional_att)
{
	return 0;
}

BOOL CSipPacket::build_bye_request(const REQUEST_PARAMETER & request_par, const VIA_PARAMETER & via_par, int max_forward, ROUTE_PARAMETER * route, CONTACT_PARAMETER & contact_par, const TO_PARAMETER & to_par, const FROM_PARAMETER & from_par, const CString & call_id, const CSEQ_PARAMETER & cseq, const CString & optional_att)
{
	return 0;
}



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
	m_max_forwards = 70;
	m_sdp_info = NULL;
	m_build_time = 0;
}

CSipPacketInfo::~CSipPacketInfo()
{
	if (NULL != m_sdp_info)
	{
		delete m_sdp_info;
		m_sdp_info = NULL;
	}
}

CSipPacketInfo & CSipPacketInfo::operator=(const CSipPacketInfo & packet_info)
{
	this->m_type = packet_info.m_type;
	this->m_request_par = packet_info.m_request_par;
	this->m_status_code = packet_info.m_status_code;

	this->m_via = packet_info.m_via;
	this->m_max_forwards = packet_info.m_max_forwards;
	this->m_from = packet_info.m_from;
	this->m_to = packet_info.m_to;
	this->m_call_id = packet_info.m_call_id;
	this->m_cseq = packet_info.m_cseq;

	//可选
	this->m_contact = packet_info.m_contact;
	this->m_route = packet_info.m_route;
	this->m_realm = packet_info.m_realm;
	this->m_nonce = packet_info.m_nonce;
	this->m_auth = packet_info.m_auth;
	if (packet_info.m_sdp_info != NULL)
	{
		if (this->m_sdp_info == NULL)
			this->m_sdp_info = new CSDP();

		*(this->m_sdp_info) = *(packet_info.m_sdp_info);
	}
	//CString m_route;

	m_build_time = ::GetTickCount();

	return *this;
}


BOOL CSipPacketInfo::from_packet(CSipPacket * packet)
{
	if (NULL == packet)
		return FALSE;
	
	char *p = NULL;
	int i = 0, j = 0, flag = 0, data_len = 0;
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
	i = str_data.Find(_T("Via"), j);
	if (i < 0)
		return FALSE;
	j = str_data.Find(_T("\r\n"), i);
	if (j < 0)
		return FALSE;
	str_line = str_data.Mid(i, j - i);
	if (!m_via.from_string(str_line))
		return FALSE;
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
			if (!m_contact.from_string(str_line))
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
				m_auth = str_data.Mid(i, j - i);
		}
	}
	else
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j > 0)
			m_auth = str_data.Mid(i, j - i);
	}

	//route
	i = str_data.Find(_T("Route"));
	if (i >= 0)
	{
		j = str_data.Find(_T("\r\n"), i);
		if (j >= 0)
		{
			str_line = str_data.Mid(i, j - i );
			if (!m_route.from_string(str_line))
				return FALSE;
		}
	}

	//sdp
	i = str_data.Find(_T("\r\n\r\nv="));
	if (i > 0)
	{
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


REQUEST_PARAMETER CSipPacketInfo::get_request()
{
	return m_request_par;
}


STATUS_CODE CSipPacketInfo::get_status_code()
{
	return m_status_code;
}

VIA_PARAMETER  CSipPacketInfo::get_via()
{
	return m_via;
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

	return m_max_forwards;
}

DWORD CSipPacketInfo::get_build_time()
{
	return m_build_time;
}

CONTACT_PARAMETER  CSipPacketInfo::get_contact()
{
	return m_contact;
}

CString CSipPacketInfo::get_realm()
{
	return m_realm;
}

CString CSipPacketInfo::get_nonce()
{
	return m_nonce;
}

CString CSipPacketInfo::get_auth()
{
	return m_auth;
}


ROUTE_PARAMETER CSipPacketInfo::get_route()
{
	return m_route;
}

CSDP CSipPacketInfo::get_sdp_info()
{
	return *m_sdp_info;
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

 CString request_parameter::to_string() const
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

 BOOL request_parameter::from_string(const CString & string)
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
		 while (i < string.GetLength())
		 {
			 if (' ' == string.GetAt(i) || ';' == string.GetAt(i))
				 break;
			 rinstance += string.GetAt(i);
			 i++;
		 }
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
	if (j >= 0)
		k = j + 1;
	else
		k = i;
	while (k < string.GetLength())
	{
		if (' ' == string.GetAt(k) || ':' == string.GetAt(k) || '\r' == string.GetAt(k))
			break;
		host += string.GetAt(k);
		k++;
	}
	return TRUE;
}

CString via_parameter::to_string() const
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

BOOL via_parameter::from_string(const CString & string)
{
	if (string.IsEmpty())
		return FALSE;


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
	while (i < string.GetLength())
	{
		if (';' == string.GetAt(i) || ' ' == string.GetAt(i))
			break;
		branch += string.GetAt(i);
		i++;
	}


	//receive addres
	i = string.Find(_T("received"));
	if (i > 0)
	{
		i += strlen("received=");
		while (i < string.GetLength())
		{
			if (';' == string.GetAt(i) || ' ' == string.GetAt(i))
				break;
			received_address += string.GetAt(i);
			i++;
		}
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

CString from_parameter::to_string() const
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

BOOL from_parameter::from_string(const CString & string)
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

CString cseq_parameter::to_string() const
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

BOOL cseq_parameter::from_string(const CString & string)
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

CString contact_parameter::to_string() const
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

BOOL contact_parameter::from_string(const CString & string)
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
			rinstance += string.GetAt(i);
			i++;
		}
	}


	return TRUE;
}

CString to_parameter::to_string() const
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

BOOL to_parameter::from_string(const CString & string)
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

MESSAGE_TYPE CSipPacketInfo::get_type()
{
	return m_type;
}
























//CString CSipPacketInfo::get_route()
// {
//	 return m_route;
// }

//BOOL CSipPacketInfo::str_to_viapar(VIA_PARAMETER &via, const CString & string)
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

//BOOL CSipPacketInfo::str_to_frompar(FROM_PARAMETER &from_par, const CString & string)
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
//BOOL CSipPacketInfo::str_to_topar(TO_PARAMETER &to_par, const CString & string)
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
//BOOL CSipPacketInfo::str_to_contactpar(CONTACT_PARAMETER &contact_par, const CString & string)
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

//BOOL CSipPacketInfo::str_to_cseqpar(CSEQ_PARAMETER &cseq_par, const CString & string)
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
//BOOL CSipPacket::add_via(VIA_PARAMETER via)
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
//CString CSipPacket::generate_via_line(VIA_PARAMETER *via_parameter)
//{
//	CString str_via, str_temp;
//
//	str_via.Format(_T("Via: SIP/2.0/UDP %s:%d;"), via_parameter->sent_address, via_parameter->sent_port);
//	str_temp.Format(_T("branch=%s;"), via_parameter->branch);
//	str_via += str_temp;
//	
//	if (!via_parameter->received_address.IsEmpty())
//	{
//		str_temp.Format(_T("received=%s;"), via_parameter->received_address);
//		str_via += str_temp;
//
//		if (via_parameter->recvived_port > 0)
//		{
//			str_temp.Format(_T("rport=%d\r\n"), via_parameter->recvived_port);
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
//CString CSipPacket::generate_from_line(FROM_PARAMETER *from_parameter)
//{
//	CString str_from, str_temp;
//
//	str_from.Format(_T("From: "));
//	if (!from_parameter->display_user.IsEmpty())
//	{
//		str_temp.Format(_T("\"%s\" "), from_parameter->display_user);
//		str_from += str_temp;
//	}
//	str_temp.Format(_T("<sip:%s@%s>"), from_parameter->user, from_parameter->host);
//	str_from += str_temp;
//	if (!from_parameter->tag.IsEmpty())
//	{
//		str_temp.Format(_T(";tag=%s"), from_parameter->tag);
//		str_from += str_temp;
//	}
//	str_from += _T("\r\n");
//
//	return str_from;
//}
//
//CString CSipPacket::generate_to_line(TO_PARAMETER *to_parameter)
//{
//	CString str_to, str_temp;
//
//	str_to.Format(_T("To: "));
//	if (!to_parameter->display_info.IsEmpty())
//	{
//		str_temp.Format(_T("\"%s\" "), to_parameter->display_info);
//		str_to += str_temp;
//	}
//	str_temp.Format(_T("<sip:%s@%s>"), to_parameter->to_user, to_parameter->to_host);
//	str_to += str_temp;
//	if (!to_parameter->to_tag.IsEmpty())
//	{
//		str_temp.Format(_T(";tag=%s"), to_parameter->to_tag);
//		str_to += str_temp;
//	}
//	str_to += _T("\r\n");
//
//	return str_to;
//
//}
//
//CString CSipPacket::generate_contact_line(CONTACT_PARAMETER *contact_parameter)
//{
//	CString contact_line, str_temp;
//
//	contact_line.Format(_T("Contact: <sip:%s@%s:%d>"), contact_parameter->contact_uri.user,
//		contact_parameter->contact_uri.host, contact_parameter->contact_uri.port);
//	if (!contact_parameter->contact_uri.rinstance.IsEmpty())
//	{
//		str_temp.Format(_T(";+sip.instance=%s"), contact_parameter->contact_uri.rinstance);
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
//CString  CSipPacket::generate_cseq_line(CSEQ_PARAMETER *cseq_parameter)
//{
//	CString str_cseq, str_method;
//
//	switch (cseq_parameter->method)
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
//	str_cseq.Format(_T("CSeq: %d %s\r\n"), cseq_parameter->cseq, str_method);
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

// BOOL CSipPacketInfo::get_via(VIA_PARAMETER &via_par, int index)
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

CString route_parameter::to_string() const
{
	CString string;
	string.Format(_T("Route: <sip:%s;%s>\r\n"), host, parameter);
	return string;
}

BOOL route_parameter::from_string(const CString & string)
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
