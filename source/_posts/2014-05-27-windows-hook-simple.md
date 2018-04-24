---
layout: post
title: Windows Hook Simple
tags: [windows,hook]
hidden: true
---

前段时间在参加ISCC，里面有一道与驱动Dll注入有关的题目，在大二的时候写过一点点MFC，但是对Hook技术接触的很少，所以利用这次机会又学习了一下Hook技术，下面的例子就是一个简单的键盘事件Hook的例子。

Windows程序是基于事件驱动机制的，一个事件消息产生，首先会进入系统的消息队列，然后系统接受该消息并查找该消息所对应的应用程序，把消息传递给对应的应用程序，交由应用程序调用相应的回调处理函数（CallBack）进行处理。

“钩子”及Hook的原理，实际上就是利用Windows提供的API，在消息队列和应用程序消息队列之间设置一道一道的关卡，截获操作系统发给应用程序的消息，对其进行修改或者屏蔽，达到“钩取”的作用。

下面以“钩取”记事本按键消息的程序为例，来简单说明这一过程。

首先简单的介绍几个Windows API：

SetWindowsHookEx()：安装钩子

    HHOOK SetWindowsHookEx(  
        int idHook,  
        HOOKPROC lpfn,  
        HINSTANCE hMod,  
        DWORD dwThreadId  
    };

* idHook：钩子的类型，即它处理的消息类型
* lpfn：钩子子程序的地址指针
* hMod：钩子子程序所属的Dll句柄
* dwThreadId：与安装的钩子子程序相关联的线程Id（若设置为0，及安装的钩子为“全局钩子”，将影响到系统所有进程）

函数成功则返回钩子子程序的句柄，失败返回NULL。

CallNextHookEx()：将消息传给下一个钩子处理程序

    LRESULT CallNextHookEx(  
        HHOOK hhk,  
        int nCode,  
        WPARAM wParam,  
        LPARAM lParam  
    };

* hhk：当前钩子的句柄
* nCode：传给钩子子程序的事件代码
* wParam：具体的消息值
* lParam：附带的信息

UnhookWindowshookEx()：卸载钩子

    LRESULT UnhookWindowsHookEx(  
        HHOOK hhk  
    };

* hhk：需要卸载的钩子的句柄

利用上面四个函数，我们就可以十分简单地安装钩子和卸载钩子，下面给出键盘事件Hook的源代码。

首先是Dll文件：KeyHook.cpp

```c
#include <stdio.h>  
#include <windows.h>  
#include <tchar.h>  

#define DEF_PROCESS_NAME "notepad.exe"  

HINSTANCE g_hInstance = NULL;  
HHOOK g_hHook = NULL;  
HWND g_hWnd = NULL;  

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvReserved) {  
    switch( dwReason ) {  
        case DLL_PROCESS_ATTACH:  
            g_hInstance = hinstDll;  
            break;  

        case DLL_PROCESS_DETACH:  
            break;  
    }  
    return TRUE;  
}  

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {  
    char szPath[MAX_PATH] = {0, };  
    char *p = NULL;  

    if( nCode == 0 ) {  
        if( !(lParam & 0x80000000) ) {  
            GetModuleFileNameA(NULL, szPath, MAX_PATH);  
            p = strrchr(szPath, '\\');  

            if( !_stricmp(p + 1, DEF_PROCESS_NAME) ) {  
                return 1;  
            }  
        }  
    }  

    return CallNextHookEx(g_hHook, nCode, wParam, lParam);  
}  

#ifdef __cplusplus  
extern "C" {  
#endif  
__declspec(dllexport) void HookStart() {  
    g_hHook = SetWindowsHookEx(WH_KEYBOARD, KeyboardProc, g_hInstance, 0);  
    _tprintf("Hook Starting...\n");  
}  

__declspec(dllexport) void HookStop() {  
    if( g_hHook ) {  
        UnhookWindowsHookEx(g_hHook);  
        g_hHook = NULL;  
        _tprintf("Hook Stoped...\n");  
    }  
}  
#ifdef __cplusplus  
}  
#endif
```

使用g++将其编译为dll文件（KeyHook.dll）：`g++ --share -o KeyHook.dll KeyHook.cpp`
（注：DllMain在每次LoadLibrary或FreeLibrary该dll文件时自动运行）

下面是主程序：HookMain.cpp

```c
#include <stdio.h>  
#include <conio.h>  
#include <Windows.h>  

#define DEF_DLL_NAME "KeyHook.dll"  
#define DEF_HOOKSTART "HookStart"  
#define DEF_HOOKSTOP "HookStop"  

typedef void(*PEN_HOOKSTART)();  
typedef void(*PEN_HOOKSTOP)();  

int main() {  
    HMODULE hDll = NULL;  
    PEN_HOOKSTART HookStart = NULL;  
    PEN_HOOKSTOP HookStop = NULL;  

    hDll = LoadLibraryA(DEF_DLL_NAME);  

    HookStart = (PEN_HOOKSTART)GetProcAddress(hDll, DEF_HOOKSTART);  
    HookStop = (PEN_HOOKSTOP)GetProcAddress(hDll, DEF_HOOKSTOP);  

    HookStart();  

    printf("Press 'q' to quit!\n");  
    while( _getch() != 'q' );  

    HookStop();  

    FreeLibrary(hDll);  

    return 0;  
}
```

编译该cpp为可执行文件（HookMain.exe）：`g++ -o KeyMain.exe KeyMain.cpp`

编译完成后，将KeyHook.dll和HookMain.exe放于同一目录下，首先运行notepad（记事本），然后运行HookMain.exe，通过终端输出可以看到钩子被成功安装

此时在notepad中敲击任何键都没有反应了，因为此消息已经被钩子程序忽略掉了（其他进程并不会）

若想钩取其他进程，将dll中DEF_PROCESS设置为其他进程名称，或者在 `SetWindowsHookEx()` 时，将dwThreadId设置为0即可。

一个简单的Hook程序到此就完成了！

有兴趣的朋友可以将源代码在自己的电脑上面编译一下，测试一下。（win7-32-sp1测试通过，64位系统可能会卡死）
