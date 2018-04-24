---
layout: post
title: wpa_supplicant - 强有力的终端 wifi 配置工具
tags: [linux]
hidden: true
---

最近网购了一套[Raspberry-Pi2](https://www.raspberrypi.org/blog/raspberry-pi-2-on-sale/)，用来跑一些神秘脚本。因为树莓派是基于 ARM 架构的，所以给它装上了 [Ubuntu专版](https://wiki.ubuntu.com/ARM/RaspberryPi)，对于终端下基本的 `iwconfig` 命令可能对现代的多种加密方式的 wifi 已经不太适应了，取而代之的是支持多种加密方式（WEP, WPA and WPA2等）的 `wpa_supplicant` 更符合我的需求。

### 一、安装

Debian/Ubuntu 下直接使用 `sudo apt-get install wpa_supplicant` 来进行安装，CentOS 下使用 `sudo yum install wpa_supplicant` 来安装。

### 二、配置并使用

使用 `iwconfig` 命令来查看当前机器上被识别出来的无线设备，例如这里我的树莓派上插入了一块腾达的USB无线网卡，则在系统中会得到识别。

![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-1.png)

然后在 `/etc/wpa_supplicant/` 目录下或者其它目录建立一个 wifi 的配置文件 `example.conf`，这里我创建在 `/etc/wpa_supplicant/example.conf`，并写入如下配置内容：

	ctrl_interface=/run/wpa_supplicant
	update_config=1

这样配置是为了后面可以使用 `wpa_cli` 命令来实时地扫描和配置网络，并能狗保存配置信息。

配置文件建立完毕后，运行 `wpa_supplicant` 命令来启动无线网络接口，并加载相关配置文件。

	sudo wpa_supplicant -B -D nl80211 -i wlan0 -c /etc/wpa_supplicant/example.conf
	
![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-2.png)

可以看到提示初始化成功，`-B`参数表示后台运行。如果遇到驱动不支持所插入的无线网卡，可选择`wired`或者`wext`等，具体详情可使用 `wpa_supplicant -h` 进行查看。

初始化完毕后，即可运行 `sudo wpa_cli` 来实时地配置网络。进入 `wpa_cli` 的交互界面后，它会自动地扫描周围的无线网络，你也可以使用 `scan` 命令进行手动扫描：

![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-3.png)

扫描完成后，使用 `scan_result` 打印扫描结果，选择你要连接的无线网络的 SSID（名称），然后新建一个网络配置信息（0代表了配置编号）：

	> add_network
	
然后对编号为 `1` 的网络配置信息进行设置：

	> set_network 1 ssid "Wifi名称"
	> set_network 1 psk "Wifi密码"
	> set_network 1 key_mgmt "Wifi的加密方式（WPA-PSK/WPA2-PSK）"

设置好后，即可使用 `enable_network 1` 来启用该配置并使用 `save_config` 来保存当前配置至 `/etc/wpa_supplicant/example.conf`。

![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-4.png)

这是可以再次使用 `iwconfig` 命令来查看无线网卡信息，可以看到已经连接上了对应的 Wifi 并有了相应的信息。

![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-5.png)

一般 Wifi 的 IP 地址获取都使用了 DHCP 协议，因此我们还需要手动 `dhclient wlan0` 来自动协商获取 IP 地址。

![](/images/articles/2015-08-03-useful-command-tool-for-wifi-connection/r-6.png)

下次启动时可以直接使用现有配置来对之前的 Wifi 进行连接，当然不要忘了使用相应命令来进行 DCHP 协商获取 IP 地址。

	sudo wpa_supplicant -B -D nl80211 -i wlan0 -c /etc/wpa_supplicant/example.conf
	sudo dhclient wlan0
	
至此就大功告成了，终端下连接 Wifi 就是这么简单 :)

### 参考

* [https://wiki.archlinux.org/index.php/WPA_supplicant](https://wiki.archlinux.org/index.php/WPA_supplicant)
* [https://wiki.ubuntu.com/ARM/RaspberryPi](https://wiki.ubuntu.com/ARM/RaspberryPi)
