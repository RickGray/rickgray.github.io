---
layout: post
title: DLL 注入练习之远程注入 - CreateRemoteThread()
tags: [windows, serurity]
hidden: true
---


### 一、前言

最近在学习Windows API，觉得其中的一些函数比较有意思，就把它记录下来了。

DLL注入指的是向运行中的其他进程强制插入特定的DLL文件，从而使之运行特定代码。

DLL注入基本过程：运行程序使其他进程调用LoadLibrary()API，调用用户指定的DLL文件，从而在LoadLibrary()完成后，调用DLL文件中的DllMain()函数。

<!--more-->

（DLL注入是使远程进程调用LoadLibrary()，而非自身进程，编写DLL注入程序的时候需要注意这一点）

（DLL加载到进程后会自动运行DllMain()函数，用户可以把想要执行的代码放到DllMain()函数里，每当该DLL被加载时，添加的代码就会被执行。利用该过程可以修复程序bug，编写恶意DLL等）

### 二、实践

DllMain()函数示例

    BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvRevered) {  
        switch( dwReason ) {  
            case DLL_PROCESS_ATTACH:  
                // 被进程加载时运行的代码  
                break;  
            case DLL_PROCESS_DETACH:  
                // 被进程卸载时运行的代码  
                break;  
            case DLL_THREAD_ATTACH:  
                // 被线程加载时运行的代码  
                break;
            case DLL_THREAD_DETACH:  
                // 被线程卸载时运行的代码  
                break;
        }  
      
        return TRUE;  
    }
    
被注入的DLL拥有目标进程内存的访问权限，所以我们可以通过该技术向目标程序增加或修改某些功能。

向某个进程注入DLL时的方法主要有以下三种：

* 创建远程线程（CreateRemoteThread() API）

* 使用注册表（AppInit_DLLs值）

* 消息钩取（SetWindowsHookEx()）

下面就选择第一种方法-CreateRemoteThread() API来对DLL注入技术进行一个简要的说明。

（下面程序在Windows7 32位下测试通过）

首先说明一下，下面程序的执行过程：运行 RemoteInject.exe 向指定的进程注入用户指定路径的DLL文件（这里的示例DLL文件只是弹出一个 MessageBox 来说明DLL是否被成功加载）。

用到的工具：Process Explore（强大的进程管理工具）

MessageBox.cpp源码

    // MessageBox.cpp  
      
    #include <windows.h>  
    #include <tchar.h>  
      
    BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvRevered) {  
        switch( dwReason ) {  
            case DLL_PROCESS_ATTACH:  
                MessageBox(NULL, TEXT("Dll Inject Success!!!"), TEXT("info"), MB_OK);  // 被进程加载时弹出MessageBox("Dll Inject Success!!!")  
                break;  
            case DLL_PROCESS_DETACH:  
                MessageBox(NULL, TEXT("Dll unInject Ok!!!"), TEXT("info"), MB_OK);  // 被进程卸载时弹出MessageBox("Dll unInject Ok!!!")  
                break;  
        }  
        return TRUE;  
    }
    
使用g++编译一下生成MessageBox.dll：``g++ --share -o MessageBox.dll MessageBox.cpp``

RemoteInject.cpp源码

    // RemoteInject.cpp  
      
    #include <windows.h>  
    #include <tchar.h>  
      
    BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath) {  
        HANDLE hProcess = NULL;  
        HANDLE hThread = NULL;  
        HMODULE hMod = NULL;  
        LPVOID pRemoteBuf = NULL;  // 存储在目标进程申请的内存地址  
        DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);  // 存储DLL文件路径所需的内存空间大小  
        LPTHREAD_START_ROUTINE pThreadProc;  
      
        if( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) ) {  
            _tprintf(L"OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());  
            return FALSE;  
        }  
      
        pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);  // 在目标进程空间中申请内存  
      
        WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);  // 向在目标进程申请的内存空间中写入DLL文件的路径  
      
        hMod = GetModuleHandle(L"kernel32.dll");  
        pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");  // 获得LoadLibrary()函数的地址  
      
        hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf,0, NULL);  
      
        WaitForSingleObject(hThread, INFINITE);  
        CloseHandle(hThread);  
        CloseHandle(hProcess);  
      
        return TRUE;  
    }  
      
    int _tmain(int argc, TCHAR *argv[]) {  
        if( argc != 3) {  
            _tprintf(L"USAGE : %s pid dll_path\n", argv[0]);  
            return 1;  
        }  
      
        if( InjectDll((DWORD)_tstol(argv[1]), argv[2]) )  
            _tprintf(L"InjectDll(\"%s\") success!!!\n", argv[2]);  
        else  
            _tprintf(L"InjectDll(\"%s\") failed!!!\n", argv[2]);  
      
        return 0;  
    }
    
在vs2010中编译、链接生成RemoteInject.exe


在这里对上面源码中的部分函数进行简单剖析：

``hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);``

调用OpenProcess() API，通过参数dwPID，来获取dwPID所对应进程的句柄。在得到PROCESS_ALL_ACCESS权限以后，就可以使用获取的句柄（hProcess）来控制对应进程。

``pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGA_READWRITE);``

为即将写入目标进程的DLL文件的路径（字符串）在目标进程空间中申请内存。

（VirtualAllcEx()函数的返回值为分配所得缓冲区的地址。该地址并不是程序自身的内存地址，而是hProcess句柄所对应的进程中的内存地址）

``writeProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, dwBufSize, NULL);``

使用writeProcessMemory() API将DLL文件路径写入到分配所得的目标缓冲区地址。

现在我们已经有了RemoteInject.exe和MessageBox.dll两个文件，我们将其放到c:\Test目录下，如下图

![](/images/articles/2014-08-25-the-remote-injection-of-dll-injection/remote-1.png)

下面我们就拿”计算器“来进行注入测试吧，首先运行calc.exe，使用Process Explorer查看calc加载的Dll信息

![](/images/articles/2014-08-25-the-remote-injection-of-dll-injection/remote-2.png)

可以看到calc.exe的PID为3192（这个DLL注入时需要用到），且在Process Explore中搜索MessageBox.dll没有任何结果。

下面打开终端，并执行下面这条命令：

![](/images/articles/2014-08-25-the-remote-injection-of-dll-injection/remote-3.png)

运行后，可以看到屏幕中央弹出了MessageBox，说明DLL被成功载入并且执行了，下面再一次查看calc.exe进程所加载的Dll文件信息，并搜索MessageBox.dll

![](/images/articles/2014-08-25-the-remote-injection-of-dll-injection/remote-4.png)

通过上图可以看到，MessageBox.dll被成功的注入到calc.exe的进程当中，所以当我们关闭calc.exe时，肯定会弹出卸载成功的提示窗，如下图所示

![](/images/articles/2014-08-25-the-remote-injection-of-dll-injection/remote-5.png)

到这里，整个DLL远程注入的示例就完成了。

很多恶意代码都会通过DLL注入的方式向某些系统进程注入代码，控制系统进程，来到达一定的目的，只能说这是设计上的一个失误了。
