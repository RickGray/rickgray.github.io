---
layout: post
title: ROP 技术绕过 DEP 初学习
tags: [windows,security]
hidden: true
---

### 一、前言

上周去参加了ISCC竞赛，在比赛的时候由于自己专于渗透方向的题目而忽略了RE、PWN等题导致最终成绩不太理想（后来看了下PWN，才发现原来那么简单，太可惜了！），赛后本地搭环境对赛中的两道PWN题进行了分析，并且写出了相应的exp，在这里就不再多分析了。
因为自己RE、PWN的水平也甚是一般，什么DEP、ASLR等windows下的防护措施也只是听说而已，从来都没有去仔细地了解和分析果，所以在这里也算是一个简单的学习笔记了吧。

下面就说说利用ROP技术绕过DEP的简单实践。

### 二、DEP与ROP

DEP（Data Execution Prevention）意为数据执行保护，是Windows的一项安全机制，主要能够在内存上执行额外检查以帮助防止在系统上运行恶意代码，简单的说也就是以前直接将shellcode插入到堆栈中执行的方法已经不可行了，因为在开启DEP后，堆栈上的shellcode默认不可执行，因此也就不能使用以前的技术来成功exp了。

DEP工作状态可分为四种：

* Optin：默认仅将DEP保护应用于Windows系统服务和组件，对其他程序不予保护。
* Optout：为排除列表程序外的所有程序和服务启用DEP。
* AlwaysOn：对所有进程启用DEP的保护，不存在排除列表，此模式下DEP不可被关闭，该模式只能工作在64位的操作系统上。
* AlwaysOff：对所有进程都禁用DEP，此模式下DEP不能被动态开启。

那么如何绕过DEP保护从而执行置于堆栈中的攻击代码？ROP就是绕过DEP保护技术之一。

ROP（Return-oriented Programming），通过从已有的库或可执行文件中提取代码片段，构建恶意代码。
ROP技术其实是通过从已有的库或可执行文件中提取代码片段（汇编指令＋retn指令），将所有的代码片段组合在一起构成ROP链，从而完成特定的功能来绕过DEP（通常是调用系统API来关闭DEP的保护，然后再转到shellcode执行）。

ROP链由一个个ROP小配件组成，ROP小配件由 “汇编指令＋retn指令” 组成。比如现在有个ROP小配件想实现`pop ebx`，那么这个小配件的指令就应该为 `pop ebx; retn;`，这是去系统内存中寻找，假设找到`0x77c23436`处恰好就是`pop ebx; retn;`，那么这个小配件就是：`0x77c23436`。

### 三、实践测试

测试环境：WindowsXP sp3，shellcode（ISCC2014 PWN1），Immnunity Debugger。

实验简介：shellcode.exe是我在参加ISCC2014的线下个人赛时做过的一道PWN题目，程序在启动时会在本地1000端口绑定socket并进行接听，当有用户连接并且用户发送大于64bytes的数据时，堆栈会发生溢出，从而产生exp。

首先，我们在不开启DEP保护的情况下，在XP上成功溢出并getshell（反弹）。接着，开启DEP保护，看能否成功溢出；最后，使用ROP技术绕过DEP，在开启DEP保护的情况下成功溢出。

#### 1、没有DEP保护，成功溢出

在WindowsXP sp3中，默认以Optin方式开启DEP，即仅将DEP保护应用于Windows系统服务和组件，对其他程序不予保护。shellcode.exe是用户进程，自然也不会受到DEP保护。下面我们直运行shellcode.exe（exp事先已经准备好）：

（DEP设置）

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/111-e1408992619685.png)

首先我们在主机上进行nc监听，等待shell反弹

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/112-e1408991885720.png)

然后在虚拟机里运行shellcode.exe程序，并通过准备好的exp进行溢出

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/113-e1408991847762.png)

（成功执行exp）

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/114-e1408991912914.png)

然后看看shell是否有反弹成功

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/115-e1408991936804.png)

（可以看到，在不开启DEP的情况下，通过溢出exp，已经成功得到反弹的shell）


#### 2、开启DEP保护，溢出失败

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/116-e1408992646908.png)

设置好后，重启电脑，再次运行shellcode.exe，可以看到出错了

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/117-e1408992028333.png)

使用OD进行调试，可以看到我们是成功溢出了并且执行了`JMP ESP (0x7ffa4512)`

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/118-e1408992055542.png)

从上图中可以知道，在DEP开启的情况下是溢出成功了，但是由于shellcode处在堆栈中，由于DEP的保护，因此并不能触发执行，因而报错。

那么，在这种情况下，如何才能执行堆栈上的shellcode呢？那就可以用到ROP链了。

绕过DEP的方法能大致分为两种：

* 新建可执行内存区域，将shellcode复制进去；相关函数：`VirtualAlloc()`、`HeapCreate()`、`WriteProcessMemory()`
        
* 通过系统API关掉DEP保护；相关函数：`SetProcessDEPPolicy()`、`NtSetInformationProccess()`、`VirtualProtect()`

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/1201-e1408992591802.png)

(1) ＝ don’t exist

(2) ＝ will fail because of default DEP policy settings

ROP链的作用就是用一连串的ROP小配件来实现这些函数的调用关闭DEP保护，然后转到shellcode上执行，下面通过一个简单的例子来说明如何利用ROP技术来绕过DEP执行shellcode。

#### 3、利用ROP绕过DEP执行shellcode

因为SetProcessDEPPolicy函数简单且ROP链构建相对容易，所有我们就构建ROP链来调用SetProcessDEPPolicy函数关闭DEP保护，然后专向我们shellcode执行。

上面已经提到，ROP链是有许多ROP小配件构造，那么我们如何快速地找到相应的小配件来构成链呢？这里就要说说Immunity Debugger上的一个python模块－[mona.py](http://redmine.corelan.be/projects/mona)。通过使用该模块，我们可以非常迅速地找到我们所需要各种小配件，如果没有对应的小配件，还可以通过各种变幻由其他小配件组合来达到相应的功能。

下面简单的介绍一下如何使用mona.py搜索ROP小配件。

这里以我们的测试程序shellcode.exe为例，使用Immunity Debugger载入 ”shellcode.exe” ，然后可以查看当前程序加载的可执行模块，如下图

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/120-e1408992095518.png)

在左下命令行处输入如下命令可以在对应的模块中查找（此处指在 ”kernel32.dll” 中进行扫描）：

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/121-e1408992126918.png)

查找完成后，会在IM Debugger的安装目录下生成报表文件，我们打开 “rop_chain.txt” 进行查看，找到SetProcessDEPPolicy的ROP链说明处：

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/122-e1408992192649.png)

前面已经说过，我们构造ROP链是为了调用`SetProcessDEPPolicy()`关闭DEP，然后转到shellcode执行。其实整个ROP链的最终构造结果是构造出一个特定的寄存器结果，就像上图所示的一样，为什么呢？这里有个比较特别的地方，我们知道 “PUSHAD” 是依次将EAX、ECX、EDX...ESI、EDI入栈，那么当我们通过ROP链构造好各个寄存器并通过小配件 “PUSHAD RETN” 后，此时堆栈的结构大概就是这个样子的：

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/123-e1408992720997.png)

这里可以看到，入栈前我们将EDI和ESI的值存储为 “RETN指令” 的地址，然后会执行EBP处的SetProcessDEPPolicy函数，因为`PUSHAD RETN`小配件在shellcode的上一个位置，执行完后ESP会指向shellcode，当SetProcessDEPPolicy执行完毕后会直接转到我们shellcode处执行（此时已经通过调用`SetProcessDEPPolicy()`取消DEP保护了）。

经过分析可以看到我们构造具体的ROP链：

    0x????????,  # POP EBP # RETN
    0x????????,  # ptr SetProcessDEPPolicy（ “SetProcessDEPPolicy“的指针）
    0x????????,  # POP EBX # RETN
    0x00000000,  # dwFlags
    0x????????,  # POP EDI # RETN
    0x????????,  # ptr RETN（ “retn指令” 的地址）
    0x????????,  # POP ESI # RETN
    0x????????,  # ptr RETN（ ”retn指令“ 的地址）
    0x????????,  # PUSHAD # RETN

上面的问号代表我们需要寻找的ROP小配件的地址，这里给出几个小配件的寻找方法即可（其他同理），这里还要指出一个问题，很多时候我们需要的小配件不一定能在当前程序的执行模块中直接找到，但是我们可以通过其他方法来实现，比如我想使得EBX为0x00000000，我们可以先找到`POP EBX; RETN;`将EBX先赋值为0xffffffff，然后在找到`INC EBX; RETN;`，这样两个小配件合在一起执行达到了我们的目的。

**# POP EBP # RETN 小配件的寻找**

其实，刚才通过执行mona.py已经在IM Debugger安装目录下记录了一些小配件的地址，打开rops.txt，通过查找我们可以找到在`0x7c87f30f`处找到我们想要的ROP小配件

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/124-e1408992298534.png)

**# RETN 小配件**

这里，我们可以重新在IM Debugger中利用mona.py模块来进行特定指令的查找，`retn`指令的机器码为`\xc3`，我们在命令行中输入：

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/125-e1408992322552.png)

命令执行完成后，结果会在IM Debugger安装目录下find.exe文件中，如下图所示

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/126-e1408992344343.png)

我们可以选择其中几个作为我们 “RETN” 小配件。

其他小配件的寻找这里就不多说了（同理），这里需要注意的是，在找ROP小配件时，若遇到RETN 0x??这种指令，此时我们需要往我们ROP链中插入与 RETN ＋0x?? 相同字节的无用数据，不然ROP链不能按预期的顺序执行，甚至导致ROP链出错。

下面就是我通过mona.py找到的各个ROP小配件构成的ROP链：

    0x77bf4f42,   # RETN
    0x90909090,
    0x7c80df32,   # POP EBP # RETN
    0x7c862144,   # ptr to SetProccessDEPPolicy()
    0x7c81ae28,   # POP EBX # RETN [kernel32.dll]
    0x00000000,   # 0x00000000（dwFlags）
    0x7c86ce63,   # POP EDI # RETN [kernel32.dll] 
    0x77bf54c4,   # ptr RETN
    0x7c87b976,   # POP ESI # RETN [msvcrt.dll]
    0x77bf5502,   # ptr RETN
    0x77d23ad9,   # PUSHAD # RETN [user32.dll]

因为shellcode.exe在溢出点函数返回时是`RETN 0x04`，因此我加入了前两个ROP小配件进行过渡，使得整个ROP链能够串起来。

下面我们将我们构造的ROP链与最开始的exp重新结合一下，构成新的exp（利用ROP绕过DEP）。

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/127-e1408992369637.png)

然后，我们在系统开启DEP保护的情况下，使用新的exp进行溢出尝试

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/128-e1408992392779.png)

执行exp

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/129-e1408992417574.png)

可以看到使用新的exp已经成功getshell了

![img](/images/articles/2014-08-26-bypass-dep-with-rop-study/130-e1408992437204.png)

至此整个实验就完了，我们使用ROP链成功DEP使得我们的shellcode执行，具体的调试过程这里就不过多演示了，后面有该测试程序的链接，有兴趣的同学可以自己手动实践一下，我也是彩笔一抹，互相学习！

（测试程序打包：[http://pan.baidu.com/s/1c0vkGpU](http://pan.baidu.com/s/1c0vkGpU)）
