
// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // 从 Windows 头中排除极少使用的资料
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // 某些 CString 构造函数将是显式的

// 关闭 MFC 对某些常见但经常可放心忽略的警告消息的隐藏
#define _AFX_ALL_WARNINGS

#include <afxwin.h>         // MFC 核心组件和标准组件
#include <afxext.h>         // MFC 扩展


#include <afxdisp.h>        // MFC 自动化类



#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC 对 Internet Explorer 4 公共控件的支持
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>             // MFC 对 Windows 公共控件的支持
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <afxcontrolbars.h>     // 功能区和控件条的 MFC 支持









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


