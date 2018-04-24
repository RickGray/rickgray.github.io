---
layout: post
title: DLL 注入练习之注册表 - AppInit_DLLs 表项
tags: [windows, security]
hidden: true
---


### 一、前言

上一遍介绍了DLL远程注入的基本原理，在这篇文章中，就来看看另一个DLL注入的方法，注册表DLL注入。

其实注册表注入相对远程DLL注入来说更简单、更方便一点，只需在注册表中修改AppInit_DLLs和LoadAppInit_DLLs的键值即可。

（User32.dll被加载到进程时，会获取AppInit_DLLs注册表项，若有值，则调用LoadLibrary() API加载用户DLL。所有，DLL注册表注入，并不会影响所有进程，只会影响加载了user32.dll的进程）

### 二、实践

（下面示例过程在windows 32位下测试成功）

下面给出测试的DLL文件源码

MessageBox.cpp

    // MessageBox.cpp  
      
    #include <windows.h>  
    #include <tchar.h>  
      
    #define DEF_PROCESS_NAME "cmd.exe"  // 目标进程 cmd.exe  
      
    BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvRevered) {  
        char szPath[MAX_PATH] = {0, };  
        char *p = NULL;  
      
        GetModuleFileNameA(NULL, szPath, MAX_PATH);  
        p = strrchr(szPath, '\\');  
      
        switch( dwReason ) {  
            case DLL_PROCESS_ATTACH:  
                if( !_stricmp(p + 1, DEF_PROCESS_NAME) )  
                    MessageBox(NULL, TEXT("Hello cmd!!!"), TEXT("info"), MB_OK);  // 被进程加载时弹出MessageBox("Dll Inject Success!!!")  
                break;  
            case DLL_PROCESS_DETACH:  
                if( !_stricmp(p + 1, DEF_PROCESS_NAME) )  
                    MessageBox(NULL, TEXT("Goodbye cmd!!!"), TEXT("info"), MB_OK);  // 被进程卸载时弹出MessageBox("Dll unInject Ok!!!")  
                break;  
        }  
        return TRUE;  
    }

编译该DLL：``g++ --share -o MessageBox.dll MessageBox.cpp``（我们将MessageBox.dll文件放在d:\下面）

改DLL被加载时，会检测进程名是否为“cmd.exe”，若为“cmd.exe”会弹出MessageBox进行相应提示。

下面我们修改注册表，来使得每次加载user32.dll时都会加载我们自己编写的MessageBox.dll

打开regedit.exe，进入如下路径。

``HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows``

编辑修改AppInit_DLLs表项的值为我们编译的MessageBox.dll所在的路径地址

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-1.png)

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-2.png)

然后修改LoadAppInit_DLLs注册表项的值为1，如下图所示

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-3.png)

注册表项修改完毕后，重启系统，使修改生效。重启完毕后，我们呢使用Process Explorer查看MessageBox.dll是否被注入进程。

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-4.png)

从上图可以看出，MessageBox.dll注入了部分进程，然后我们运行一下cmd.exe看是否或被注入MessageBox.dll。

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-5.png)

从上图红色框框所标识的部分来看，运行cmd.exe时因为加载了user32.dll，所以也同时加载了我们自己写的MessageBox.dll，在DllMain()运行时，检测到当前进程为“cmd.exe”因此弹出了MessageBox()，说明注册表DLL注入成功。

若我们关闭cmd.exe，会弹出如下窗口

![](/images/articles/2014-08-25-the-registration-injection-of-dll-injection/register-6.png)

MessageBox.dll被cmd.exe进程成功卸载。

总结：DLL注册表注入相对与DLL远程注入来说，更加容易、方便，攻击者可以编写恶意DLL来做他任何想做的事情，所以，在排查一些异常现象的时候，不要忘了检查注册表- -||
