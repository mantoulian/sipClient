#include "stdafx.h"
#include "Rtp.h"


//FU indicator 
/*
+---------------+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|F|NRI|  Type   |
+---------------+
*/
typedef struct fu_indicator
{
	unsigned char TYPE : 5;
	unsigned char NRI : 2;
	unsigned char F : 1;
} FU_INDICATOR; // 1 BYTE 


//FU header
/*
+---------------+
|0|1|2|3|4|5|6|7|
+-+-+-+-+-+-+-+-+
|S|E|R|  Type   |
+---------------+
*/
typedef struct fu_header
{
	unsigned char TYPE : 5;
	unsigned char R : 1;
	unsigned char E : 1;
	unsigned char S : 1;
} FU_HEADER;   // 1 BYTES 

//����base64
BOOL base64_decode(char *szCode, int nCodeLen, char *szDeCode, int *nDecodeLen)
{
	if (szCode == NULL || szDeCode == NULL)
	{
		return false;
	}



	//����base64�����ַ��ҵ���Ӧ��ʮ��������    
	int table[] = { 0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,62,0,0,0,
		63,52,53,54,55,56,57,58,
		59,60,61,0,0,0,0,0,0,0,0,
		1,2,3,4,5,6,7,8,9,10,11,12,
		13,14,15,16,17,18,19,20,21,
		22,23,24,25,0,0,0,0,0,0,26,
		27,28,29,30,31,32,33,34,35,
		36,37,38,39,40,41,42,43,44,
		45,46,47,48,49,50,51
	};
	long len;
	long str_len;
	//unsigned char *res;
	int i, j;

	//����������ַ�������    
	len = nCodeLen;
	//�жϱ������ַ������Ƿ���=    
	if (strstr(szCode, "=="))
		str_len = len / 4 * 3 - 2;
	else if (strstr(szCode, "="))
		str_len = len / 4 * 3 - 1;
	else
		str_len = len / 4 * 3;

	*nDecodeLen = str_len;
	//res = malloc(sizeof(unsigned char)*str_len + 1);
	//res[str_len] = '\0';

	//��4���ַ�Ϊһλ���н���    
	for (i = 0, j = 0; i < len - 2; j += 3, i += 4)
	{
		//ȡ����һ���ַ���Ӧbase64���ʮ��������ǰ6λ��ڶ����ַ���Ӧbase64���ʮ�������ĺ�2λ�������    
		szDeCode[j] = ((unsigned char)table[szCode[i]]) << 2 | (((unsigned char)table[szCode[i + 1]]) >> 4);
		//ȡ���ڶ����ַ���Ӧbase64���ʮ�������ĺ�4λ��������ַ���Ӧbas464���ʮ�������ĺ�4λ�������    
		szDeCode[j + 1] = (((unsigned char)table[szCode[i + 1]]) << 4) | (((unsigned char)table[szCode[i + 2]]) >> 2);
		//ȡ���������ַ���Ӧbase64���ʮ�������ĺ�2λ���4���ַ��������    
		szDeCode[j + 2] = (((unsigned char)table[szCode[i + 2]]) << 6) | ((unsigned char)table[szCode[i + 3]]);
	}

	return true;

}

//��fmtp�л�ȡsps pps
BOOL Get_sps_pps_From_Fmtp(unsigned char * fmtp, unsigned char *sps_pps, int &sps_pps_len)
{

	if (fmtp == NULL || sps_pps == NULL)
	{
		return false;
	}

	char *szTemp = NULL;
	char szCodeSPS[128] = { 0 }, szCodePPS[128] = { 0 };
	int nCodeSpsLen = 0, nCodePpsLen = 0;
	char szDecodeSPS[128] = { 0 }, szDecodePPS[128] = { 0 };
	int nDecodeSpsLen = 0, nDecodePpsLen = 0;
	char szSpsPps[128] = { 0 };



	szTemp = strstr((char *)fmtp, "sprop-parameter-sets");
	if (szTemp == NULL)
	{
		return false;
	}

	szTemp += strlen("sprop-parameter-sets=");
	while (*szTemp != ',')//����ǰ�������Ϊsps
	{
		szCodeSPS[nCodeSpsLen] = *szTemp;
		szTemp++;
		nCodeSpsLen++;
	}
	szTemp++;//��������
	while (*szTemp != '\0')
	{
		szCodePPS[nCodePpsLen] = *szTemp;
		szTemp++;
		nCodePpsLen++;
	}

	//����base64
	int num = 0;
	if (base64_decode(szCodeSPS, nCodeSpsLen, szDecodeSPS, &nDecodeSpsLen))
	{
		//�����ʼ�� 0x00 00 00 01
		szSpsPps[3] = 1;
		num += 4;
		memcpy(szSpsPps + num, szDecodeSPS, nDecodeSpsLen);
		num += nDecodeSpsLen;
	}
	if (base64_decode(szCodePPS, nCodePpsLen, szDecodePPS, &nDecodePpsLen))
	{
		//�����ʼ�� 0x00 00 00 01
		szSpsPps[num + 3] = 1;
		num += 4;
		memcpy(szSpsPps + num, szDecodePPS, nDecodePpsLen);
		num += nDecodePpsLen;
	}

	memcpy(sps_pps, szSpsPps, num);
	sps_pps_len = num;


	return true;
}

//rtpתh264
BOOL rtpPackToH264(char *rtpPack, int rtpPackLen, unsigned char *h264Buf, int *h264Len)
{

	if (rtpPack == NULL || h264Buf == NULL)
	{
		return false;
	}


	FU_INDICATOR *fuIndi = NULL;
	FU_HEADER *fuHeader = NULL;
	int len = 0, sps_len = 0, pps_len = 0;
	char *pSource = rtpPack + 12, *sps = NULL, *pps = NULL;

	//�Ȳ鿴�������
	fuIndi = (FU_INDICATOR *)&rtpPack[12];

	if (fuIndi->TYPE > 0 && fuIndi->TYPE < 24)//1-23Ϊ����
	{
		//���������ʱֻ��ȥ��ǰ��12���ֽڵ�rtpͷ����Ȼ�����0x00 00 00 01����

		h264Buf[0] = 0;
		h264Buf[1] = 0;
		h264Buf[2] = 0;
		h264Buf[3] = 1;
		len += 4;

		memcpy(h264Buf + len, pSource, rtpPackLen - 12);
		len += rtpPackLen - 12;

		*h264Len = len;

	}
	else if (fuIndi->TYPE == 28)//fu-a�ĸ�ʽ���
	{
		//fu-a ��2��ͷ�������ݵڶ���ͷ���ж��ǿ�ʼ�����м�������ǽ�����
		fuHeader = (FU_HEADER *)&rtpPack[13];

		if (fuHeader->S == 1)//��ʼ�� ��Ҫ������ʼ�� ��ͷ��
		{

			//memcpy(h264Buf, &nStartNum, 4);//��� 0x00 00 00 01
			//len += 4;
			h264Buf[0] = 0;
			h264Buf[1] = 0;
			h264Buf[2] = 0;
			h264Buf[3] = 1;
			len = 4;

			//���ͷ��
			//NALͷ�İ�λ����FU indicator��ǰ��λ��FU header�ĺ���λ��ɣ�����
			//	nal_unit_type = (fu_indicator & 0xe0) | (fu_header & 0x1f)

			char fi = *(char *)fuIndi;
			char fh = *(char *)fuHeader;
			char nal = (fi & 0xe0) | (fh & 0x1f);
			memcpy(h264Buf + len, &nal, 1);
			len += 1;

			//�������
			memcpy(h264Buf + len, pSource + 2, rtpPackLen - 14);
			len += rtpPackLen - 14;
			*h264Len = len;


		}
		else if (fuHeader->E == 1)//������ ȡ��rtp��������ݼ���
		{
			memcpy(h264Buf, pSource + 2, rtpPackLen - 14);
			len += rtpPackLen - 14;
			*h264Len = len;
		}
		else//�м�� ȡ��rtp��������ݼ���
		{
			memcpy(h264Buf, pSource + 2, rtpPackLen - 14);
			len += rtpPackLen - 14;
			*h264Len = len;
		}

	}
	else//�������ͷ����δ����
	{
		return false;
	}

	return true;

}

//���벢����
static BOOL decode(AVCodecContext *dec_ctx, AVFrame *frame, AVPacket *pkt, CWnd* pWnd)
{
	int ret = 0, result = 0;
	struct SwsContext *pSwCon = NULL;
	uint8_t *dst_data[4];//ת���������
	int dst_linesize[4];

	BYTE R, G, B;
	CRect rcDraw;
	pWnd->GetWindowRect(&rcDraw);
	CClientDC dc(pWnd);
	BITMAPINFO m_bmpMapInfo;


	ret = avcodec_send_packet(dec_ctx, pkt);
	if (ret < 0)
	{
		return false;
	}
	while (ret >= 0)
	{
		ret = avcodec_receive_frame(dec_ctx, frame);
		if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
			return true;
		else if (ret < 0)
		{
			return false;
		}

		//��ʾ
		//1 ����ռ�
		DWORD* pImageData = new DWORD[frame->width * frame->height];
		if (pImageData == NULL)
		{
			break;
		}

		//2 ����ת�� //yuvתrgb
		if ((AVPixelFormat)frame->format == AV_PIX_FMT_YUVJ420P ||
			(AVPixelFormat)frame->format == AV_PIX_FMT_YUV420P)
		{
			//����ת�������ݿռ�
			ret = av_image_alloc(dst_data, dst_linesize, frame->width, frame->height, AV_PIX_FMT_RGB24, 1);
			if (ret < 0)
			{
				break;
			}

			pSwCon = sws_getContext(frame->width, frame->height, (AVPixelFormat)frame->format,
				frame->width, frame->height, AV_PIX_FMT_RGB24,
				SWS_FAST_BILINEAR, NULL, NULL, NULL);

			if (pSwCon == NULL)
			{
				break;
			}

			ret = sws_scale(pSwCon, frame->data, frame->linesize, 0,
				frame->height, dst_data, dst_linesize);

			if (ret < 0)
			{
				break;
			}

			//rgb תdword
			for (int i = 0; i < frame->width * frame->height; i++)
			{
				R = dst_data[0][i * 3];
				G = dst_data[0][i * 3 + 1];
				B = dst_data[0][i * 3 + 2];
				//pImageData[i] = (B << 24) | (G << 16) | (R << 8) | 0xff000000;
				pImageData[i] = (R << 24) | (G << 16) | (B << 8) | 0xff000000;
			}

			//�ͷſռ�
			av_freep(dst_data);

		}

		//3 ��ʾ
		memset(&m_bmpMapInfo, 0, sizeof(m_bmpMapInfo));
		m_bmpMapInfo.bmiHeader.biBitCount = 32;
		m_bmpMapInfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		m_bmpMapInfo.bmiHeader.biPlanes = 1;
		m_bmpMapInfo.bmiHeader.biWidth = frame->width;
		m_bmpMapInfo.bmiHeader.biHeight = -frame->height;
		m_bmpMapInfo.bmiHeader.biSizeImage = 0;
		m_bmpMapInfo.bmiHeader.biCompression = BI_RGB;


		//::StretchDIBits(dc.GetSafeHdc(), 0, 0, frame->width, frame->height, 0, 0,
		//	frame->width, frame->height, pImageData, &m_bmpMapInfo, DIB_RGB_COLORS, SRCCOPY);

		result = ::StretchDIBits(dc.GetSafeHdc(), 0, 0, rcDraw.Width(), rcDraw.Height(), 0, 0,
			frame->width, frame->height, pImageData, &m_bmpMapInfo, DIB_RGB_COLORS, SRCCOPY);

		//4����
		delete [] pImageData;

		////����һ֡��ɣ���������
		// f = av_frame_alloc();
		// av_frame_copy();
		////AVFrame *f = av_frame_alloc();
		////���Ƹ�ʽ
		//f->format = frame->format;
		//f->repeat_pict = frame->repeat_pict;
		////��������
		////���ͼƬ�����ֽ���
		//av_image_get_buffer_size();
		//bytes_num = avpicture_get_size((AVPixelFormat)frame->format, frame->width, frame->height);
		////����ռ�
		//buff = (uint8_t*)av_malloc(bytes_num);
		////������ݵ�֡
		//avf = f;
		////av_image_fill_arrays();
		//av_image_fill_arrays();
		//avpicture_fill((AVPicture*)avf, buff, (AVPixelFormat)frame->format, frame->width, frame->height);
		//dataCache->AddPacket(f);
		////����ͼ��Ŀ��
		//if (*width <= 0)
		//{
		//	*width = frame->width;
		//	*height = frame->height;
		//}

	}


	return true;


}

CRtpPlayer::CRtpPlayer()
{
	m_RtpCache = NULL;
	m_codec = NULL;
	m_parser = NULL;
	m_c = NULL;
	m_frame = NULL;
	m_pkt = NULL;
	m_codecPa = NULL;
	m_hDecodeThread = NULL;
	m_width = 0;
	m_height = 0;
	m_pWnd = NULL;
	m_bWork = FALSE;
}

CRtpPlayer::~CRtpPlayer()
{
	m_bWork = FALSE;
	Sleep(500);

	if (NULL != m_c)
	{
		avcodec_free_context(&m_c);
		m_c = NULL;
	}
	if (NULL != m_frame)
	{
		av_frame_free(&m_frame);
		m_frame = NULL;
	}
	if (NULL != m_codecPa)
	{
		avcodec_parameters_free(&m_codecPa);
		m_codecPa = NULL;
	}

	CloseHandle(m_hDecodeThread);
}

#define SPS_PPS_SIZE    512
BOOL CRtpPlayer::init()
{
	char sps_pps[SPS_PPS_SIZE] = { 0 }, *pFmtp;
	int sps_pps_len = 0, ret = 0;

	//ffmpeg ��ʼ��
	m_pkt = av_packet_alloc();
	if (m_pkt == NULL)
		return FALSE;

	m_codec = avcodec_find_decoder(AV_CODEC_ID_H264);
	if (m_codec == NULL)
		return FALSE;

	m_parser = av_parser_init(m_codec->id);
	if (m_parser == NULL)
		return FALSE;

	m_c = avcodec_alloc_context3(m_codec);
	if (m_c == NULL)
		return FALSE;

	m_frame = av_frame_alloc();
	if (m_frame == NULL)
		return FALSE;

	m_codecPa = avcodec_parameters_alloc();
	if (m_codecPa == NULL)
		return FALSE;

	//USES_CONVERSION;
	//pFmtp = T2A(str_fmtp);
	//if (pFmtp == NULL)
	//	return FALSE;

	////��sdp�е�fmtp�л�ȡsps pps
	//if (Get_sps_pps_From_Fmtp((unsigned char *)pFmtp, (unsigned char *)sps_pps, sps_pps_len))
	//{
	//	//���õ�ffmpeg
	//	m_codecPa->extradata_size = sps_pps_len;
	//	m_codecPa->extradata = (uint8_t*)av_malloc(sps_pps_len + AV_INPUT_BUFFER_PADDING_SIZE);
	//	memcpy(m_codecPa->extradata, sps_pps, sps_pps_len);
	//	ret = avcodec_parameters_to_context(m_c, m_codecPa);
	//	if (ret != 0)
	//		return FALSE;
	//	if (avcodec_open2(m_c, m_codec, NULL) < 0)
	//		return FALSE;
	//	m_width = m_c->width;
	//	m_height = m_c->height;
	//	m_sps_pps_ok = TRUE;
	//}


	//�����߳�
	m_hDecodeThread = ::CreateThread(NULL, 0, DecodeVideoThread, this, CREATE_SUSPENDED, NULL);

	return TRUE;

}

//BOOL CRtpPlayer::set_sps_pps(CString str_fmtp)
//{
//	return TRUE;
//}

CRtpPacketCache * CRtpPlayer::GetRtpCache()
{
	return m_RtpCache;
}

void CRtpPlayer::SetRtpCache(CRtpPacketCache * cache)
{
	if (NULL != cache)
		m_RtpCache = cache;
}

BOOL CRtpPlayer::Play(const CString &fmtp, CWnd * pCWnd)
{
	if (NULL == pCWnd)
		return FALSE;

	char *pFmtp = NULL;
	char sps_pps[512] = { 0 };
	int sps_pps_len = 0, ret = 0;

	USES_CONVERSION;
	pFmtp = T2A(fmtp);
	if (pFmtp == NULL)
		return FALSE;

	//��sdp�е�fmtp�л�ȡsps pps
	if (Get_sps_pps_From_Fmtp((unsigned char *)pFmtp, (unsigned char *)sps_pps, sps_pps_len))
	{
		//���õ�ffmpeg
		m_codecPa->extradata_size = sps_pps_len;
		m_codecPa->extradata = (uint8_t*)av_malloc(sps_pps_len + AV_INPUT_BUFFER_PADDING_SIZE);
		memcpy(m_codecPa->extradata, sps_pps, sps_pps_len);
		ret = avcodec_parameters_to_context(m_c, m_codecPa);
		if (ret != 0)
			return FALSE;
		if (avcodec_open2(m_c, m_codec, NULL) < 0)
			return FALSE;
		m_width = m_c->width;
		m_height = m_c->height;
		m_sps_pps_ok = TRUE;
	}

	m_pWnd = pCWnd;
	::ResumeThread(m_hDecodeThread);
	m_bWork = true;

	return TRUE;

}

//void CRtpPlayer::Play(CWnd * pCWnd)
//{
//	if (NULL != pCWnd)
//	{
//		m_pWnd = pCWnd;
//		::ResumeThread(m_hDecodeThread);
//		m_bWork = true;
//	}
//
//}

DWORD CRtpPlayer::DecodeVideoThread(LPVOID lpParam)
{
	CRtpPlayer *pObject = (CRtpPlayer *)lpParam;
	ASSERT(NULL != pObject);

	return pObject->DoDecode();
}

#define VIDEO_BUF_SIZE    4096
#define SPS_PPS_SIZE    512
DWORD CRtpPlayer::DoDecode()
{
	unsigned char *buf = NULL, *data = NULL;
	int buf_len = 0, data_size = 0, ret = 0;
	CRtpPacketPtr pack;
	char *sps_pps = NULL;
	int sps_pps_len = 0;

	buf = (unsigned char *)calloc(VIDEO_BUF_SIZE, 1);
	if (NULL == buf)
		return 1;
	sps_pps = (char *)calloc(SPS_PPS_SIZE, 1);
	if (NULL == sps_pps)
		return 2;

	while (m_bWork)
	{
		if (m_RtpCache != NULL)
			pack = m_RtpCache->GetNextPacket();
		if (pack == NULL)//û����Ҫ���������
		{
			Sleep(10);
		}
		else
		{
			//������Ƶ
			if (pack->enType == video)
			{
				//��ȡrtp�е���Ƶ��
				if (!rtpPackToH264(pack->szData, pack->usPackLen, buf, &buf_len))
					continue;
				if (FALSE == m_sps_pps_ok)//sdp��û��sps pps����Ҫ��h264���л�ȡ
				{
					if ((buf[4]&0x1f) == 7)//sps
					{
						memset(sps_pps, 0, SPS_PPS_SIZE);
						sps_pps_len = 0;
						memcpy(sps_pps, buf, buf_len);
						sps_pps_len += buf_len;
						continue;
					}
					else if ((buf[4]&0x1f) == 8)//pps
					{
						memcpy(sps_pps + sps_pps_len, buf, buf_len);
						sps_pps_len += buf_len;
						//����ffmpeg����
						if (NULL == m_codecPa->extradata)
						{
							m_codecPa->extradata_size = sps_pps_len;
							m_codecPa->extradata = (uint8_t*)av_malloc(sps_pps_len + AV_INPUT_BUFFER_PADDING_SIZE);
							memcpy(m_codecPa->extradata, sps_pps, sps_pps_len);
							ret = avcodec_parameters_to_context(m_c, m_codecPa);
							if (ret != 0)
								continue;
							ret = avcodec_open2(m_c, m_codec, NULL);
							if (ret < 0)
								continue;
							m_width = m_c->width;
							m_height = m_c->height;
						}
						continue;
					}
				}

				data = buf;
				data_size = buf_len;
				while (data_size > 0)
				{
					ret = av_parser_parse2(m_parser, m_c, &m_pkt->data, &m_pkt->size,
						data, data_size, AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
					if (ret < 0)
						break;
					data += ret;
					data_size -= ret;
					if (m_pkt->size)
						decode(m_c, m_frame, m_pkt, m_pWnd);
				}
			}
		}
	}

	if (NULL != buf)
	{
		free(buf);
		buf = NULL;
	}

	return 0;
}

BOOL find_sps_pps_from_rtp(char *buf, int buf_len, char *sps_pps, int sps_pps_len)
{
	if (NULL == buf|| buf_len <= 0)
		return FALSE;

	
	
	return TRUE;
}
