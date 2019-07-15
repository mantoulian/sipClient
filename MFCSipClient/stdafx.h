
// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // �� Windows ͷ���ų�����ʹ�õ�����
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // ĳЩ CString ���캯��������ʽ��

// �ر� MFC ��ĳЩ�����������ɷ��ĺ��Եľ�����Ϣ������
#define _AFX_ALL_WARNINGS

#include <afxwin.h>         // MFC ��������ͱ�׼���
#include <afxext.h>         // MFC ��չ


#include <afxdisp.h>        // MFC �Զ�����



#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC �� Internet Explorer 4 �����ؼ���֧��
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>             // MFC �� Windows �����ؼ���֧��
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxcontrolbars.h>     // �������Ϳؼ����� MFC ֧��









#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

#include "../../ItSyncLib/include/LogFund/LogFund.h"
#include "../../ItSyncLib/include/CommonFund/CommonFund.h"
#include "../../ItSyncLib/include/NetFund/NetFund.h"
#include "../../ItSyncLib/include/CommonFund/SingleInstanceApp.h"
//ffmpeg
#include "../../ffmpeg/include/libavutil/imgutils.h"
#include "../../ffmpeg/include/libavutil/samplefmt.h"
#include "../../ffmpeg/include/libavutil/timestamp.h"
#include "../../ffmpeg/include/libavformat/avformat.h"
#include "../../ffmpeg/include/libswscale/swscale.h"
//sdl2
#include "../../SDL2/include/SDL.h"

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
#else
#pragma comment(lib, "../../ItSyncLib/Win32/lib/LogFund.lib")
#pragma comment(lib, "../../ItSyncLib/Win32/lib/CommonFund.lib")
#pragma comment(lib, "../../ItSyncLib/Win32/lib/NetFund.lib")
#endif // _WIN64


