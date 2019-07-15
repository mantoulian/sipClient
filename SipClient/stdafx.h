// stdafx.h : 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 特定于项目的包含文件

#pragma once

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // 从 Windows 头中排除极少使用的资料
#endif

#include "targetver.h"

#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS      // 某些 CString 构造函数将是显式的

#include <afxwin.h>         // MFC 核心组件和标准组件
#include <afxext.h>         // MFC 扩展

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxole.h>         // MFC OLE 类
#include <afxodlgs.h>       // MFC OLE 对话框类
#include <afxdisp.h>        // MFC 自动化类
#endif // _AFX_NO_OLE_SUPPORT

#ifndef _AFX_NO_DB_SUPPORT
#include <afxdb.h>                      // MFC ODBC 数据库类
#endif // _AFX_NO_DB_SUPPORT

#ifndef _AFX_NO_DAO_SUPPORT
#include <afxdao.h>                     // MFC DAO 数据库类
#endif // _AFX_NO_DAO_SUPPORT

#ifndef _AFX_NO_OLE_SUPPORT
#include <afxdtctl.h>           // MFC 对 Internet Explorer 4 公共控件的支持
#endif
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>                     // MFC 对 Windows 公共控件的支持
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