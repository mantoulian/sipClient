// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // �� Windows ͷ���ų�����ʹ�õ�����
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // ĳЩ CString ���캯��������ʽ��

#include <afxwin.h>         // MFC ��������ͱ�׼���
#include <afxext.h>         // MFC ��չ

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxole.h>         // MFC OLE ��
#include <afxodlgs.h>       // MFC OLE �Ի�����
#include <afxdisp.h>        // MFC �Զ�����
#endif // _AFX_NO_OLE_SUPPORT

#ifndef _AFX_NO_DB_SUPPORT
#include <afxdb.h>                      // MFC ODBC ���ݿ���
#endif // _AFX_NO_DB_SUPPORT

#ifndef _AFX_NO_DAO_SUPPORT
#include <afxdao.h>                     // MFC DAO ���ݿ���
#endif // _AFX_NO_DAO_SUPPORT

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC �� Internet Explorer 4 �����ؼ���֧��
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>                     // MFC �� Windows �����ؼ���֧��
#endif // _AFX_NO_AFXCMN_SUPPORT


#include "../../ItSyncLib/include/LogFund/LogFund.h"
#include "../../ItSyncLib/include/CommonFund/CommonFund.h"
#include "../../ItSyncLib/include/NetFund/NetFund.h"
#include "../../ItSyncLib/include/CommonFund/SingleInstanceApp.h"
#include "../../ItSyncLib/include/CommonFund/SmartPtr.h"

extern "C"
{
//ffmpeg
#include "../../ffmpeg/include/libavutil/imgutils.h"
#include "../../ffmpeg/include/libavutil/samplefmt.h"
#include "../../ffmpeg/include/libavutil/timestamp.h"
#include "../../ffmpeg/include/libavformat/avformat.h"
#include "../../ffmpeg/include/libswscale/swscale.h"
}

#ifdef _WIN64
#pragma comment(lib, "../../ItSyncLib/x64/lib/LogFund.lib")
#pragma comment(lib, "../../ItSyncLib/x64/lib/CommonFund.lib")
#pragma comment(lib, "../../ItSyncLib/x64/lib/NetFund.lib")

#pragma comment(lib,"../../ffmpeg/x64/lib/avcodec.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/avdevice.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/avfilter.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/avformat.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/avutil.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/postproc.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/swresample.lib")
#pragma comment(lib,"../../ffmpeg/x64/lib/swscale.lib")

#pragma comment(lib,"../../SDL2/lib/x64/SDL2.lib")
#pragma comment(lib,"../../SDL2/lib/x64/SDL2main.lib")
#pragma comment(lib,"../../SDL2/lib/x64/SDL2test.lib")


#else
#pragma comment(lib, "../../ItSyncLib/Win32/lib/LogFund.lib")
#pragma comment(lib, "../../ItSyncLib/Win32/lib/CommonFund.lib")
#pragma comment(lib, "../../ItSyncLib/Win32/lib/NetFund.lib")
#endif // _WIN64