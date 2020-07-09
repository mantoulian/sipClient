#pragma once
#include "stdafx.h"

//typedef struct sdp_info
//{
//	CString strAddress;
//	//“Ù∆µ
//	BOOL bAudioMedia;
//	unsigned short usAudioPort;
//	CString strAudioIP;
//	int nAudioLoadType;
//	CString strAudioTrackId;
//	CString strAudioRtpMap;
//	CString strAudioFmtp;
//	// ”∆µ
//	BOOL bVideoMedia;
//	unsigned short usVideoPort;
//	CString strVideoIP;
//	int nVideoLoadType;
//	CString  strVideoTrackId;
//	CString strVideoRtpMap;
//	CString strVideoFmtp;
//
//}SDP_INFO;




#define MEDIA_MAX_SDP_FMTP		16
#define MEDIA_MAX_SDP_ATTR		(MEDIA_MAX_SDP_FMTP * 2 + 4)
#define MEDIA_MAX_SDP_FMT		32


typedef struct sdp_conn
{
	CString	net_type;	/**< Network type ("IN").		*/
	CString	addr_type;	/**< Address type ("IP4", "IP6").	*/
	CString	addr;		/**< The address.			*/

	BOOL frome_string(const CString &strConn);
	CString to_string();

}sdp_conn;




typedef struct sdp_attr
{
	CString		name;	    /**< Attribute name.    */
	CString		value;	    /**< Attribute value.   */


	BOOL frome_string(const CString &strAttr);
	CString to_string();

}sdp_attr;

typedef struct media_attributes
{
	/** Media descriptor line ("m=" line) */
	struct
	{
		CString    media;		/**< Media type ("audio", "video")  */
		WORD        port;		/**< Port number.		    */
		//unsigned    port_count;		/**< Port count, used only when >2  */
		CString    transport;		/**< Transport ("RTP/AVP")	    */
		unsigned int   fmt_count;		/**< Number of formats.		    */
		CString    fmt[MEDIA_MAX_SDP_FMT];       /**< Media formats.	    */
	} desc;


	sdp_conn *conn;
	unsigned int attrCount;
	sdp_attr *attr[MEDIA_MAX_SDP_ATTR];

	/*CString type;
	WORD port;

	BYTE fmtpCount;
	CString fmtp[MEDIA_MAX_SDP_FMTP];
	BYTE attrCount;
	CString attr[MEDIA_MAX_SDP_ATTR];*/


	BOOL from_string(const CString &strMedia);
	CString to_string();

}MEDIA_ATTRIBUTES;




#define SDP_MAX_MEDIA	8

class AFX_EXT_CLASS CSDP
{
public:
	CSDP();
	~CSDP();
	//CSDP(const CSDP &sdp);

	//BOOL init();

	BOOL from_buffer(char * buffer, int buf_len);
	CString to_string() const;

	//CSDP* Clone(BOOL bEncodeData);

	//sdp_attr_find();//
	CSDP sdp_compare(const CSDP &sdp);

	//pjmedia_sdp_attr_clone

	

	//void set_address(CString str_address);
	//void set_audio_media(BOOL media);
	//void set_audio_address(CString str_address);
	//void set_audio_port(unsigned short port);
	//void set_audio_load_type(int type);
	//void set_audio_track_id(CString track_id);
	//void set_audio_rtp_map(CString rtp_map);
	//void set_audio_fmtp(CString fmtp);
	//void set_video_media(BOOL media);
	//void set_video_address(CString str_address);
	//void set_video_port(unsigned short port);
	//void set_video_load_type(int type);
	//void set_video_track_id(CString track_id);
	//void set_video_rtp_map(CString rtp_map);
	//void set_video_fmtp(CString fmtp);
	//CString get_address();
	//BOOL get_audio_media();
	//CString get_audio_address();
	//unsigned short get_audio_port();
	//int get_audio_load_type();
	//CString get_audio_track_id();
	//CString get_audio_rtp_map();
	//CString get_audio_fmtp();
	//BOOL get_video_media();
	//CString get_video_address();
	//unsigned short get_video_port();
	//int get_video_load_type();
	//CString get_video_track_id();
	//CString get_video_rtp_map();
	//CString get_video_fmtp();

private:



private:
	//CString m_netType;  /*Network type("IN")*/
	//CString m_addrType; /*address type("IP4", "IP6")*/
	sdp_conn m_conn;  /*address*/

	unsigned char m_mediaCount;
	MEDIA_ATTRIBUTES *m_media[SDP_MAX_MEDIA];


public:
	//CString m_strAddress;
	////“Ù∆µ
	//BOOL m_bAudioMedia;
	//unsigned short m_usAudioPort;
	//CString m_strAudioIP;
	//int m_nAudioLoadType;
	//CString m_strAudioControl;
	//CString m_strAudioRtpMap;
	//CString m_strAudioFmtp;
	//// ”∆µ
	//BOOL m_bVideoMedia;
	//unsigned short m_usVideoPort;
	//CString m_strVideoIP;
	//int m_nVideoLoadType;
	//CString  m_strVideoControl;
	//CString  m_strVideoRtpMap;
	//CString  m_strVideoFmtp;
};

