---
layout: post
title: 简单的敏感文件扫描脚本
tags: [python,security]
hidden: true
---

好久没发文了，这次要说的只是一个小小的扫描工具，尽请实战，工具会不定期添加新功能（如果喜欢star一下吧 thx! :P）

项目地址：[https://github.com/RickGray/dirscan](https://github.com/RickGray/dirscan)

克隆项目至本地：

    git clone https://github.com/RickGray/dirscan.git

直接获取单文件（特定环境方便，你懂的）：

    curl -O https://github.com/RickGray/dirscan/raw/master/dirscan.py

或者：

    wget https://github.com/RickGray/dirscan/raw/master/dirscan.py

简单扫描：

    python dirscan.py http://testphp.vulnweb.com mulu.txt

使用代理：

    python dirscan.py -p socks5://<proxy_host>:<proxy_port> http://testphp.vulnweb.com common.txt

    python dirscan.py --proxy=http://<proxy_host>:<proxy_port> http://testphp.vulnweb.com common.txt

指定扫描线程数：

    python -t 30 http://testphp.vulnweb.com common.txt

如果遇到Bug请直接Git提issus :)

![img](/images/articles/2015-04-15-simple-python-script-to-scan-weak-things/screenshot.png)
