---
layout: post
title: 使用 virtualenv 建立 Python 虚拟环境
tags: [python]
hidden: true
---

平时在进行Python项目开发的时候可能会遇到一个问题，两个项目使用了不同的版本的第三方库（例如django），如果是在同一开发环境下，肯定有一个项目的django版本不能满足其项目需求。

为了解决这类问题，就要需找一款能够产生相互独立Python环境的工具，幸运的是这里恰好有一款工具能够满足这样的要求-**virtualenv**，下面就来说说如何安装和使用virtualenv。

直接使用`easy_install`或者`pip`安装virtualenv：

    $ sudo easy_install install virtualenv
    (or)
    $ sudo pip install virtualenv

安装完成后，在任意位置建立你的项目目录（如demo）：

    $ cd ~
    $ mkdir demo

然后使用`virtualenv`初始化你的项目目录：

    $ virtualenv demo/
    New python executable in demo/bin/python
    Installing setuptools, pip...done.
    
通过初始化已经在`demo`中实现了一个默认的虚拟Python环境（没有配置任何参数，如果想查看更多初始化配置参数请查看官方[文档](https://virtualenv.pypa.io/en/latest/reference.html)），包括`bin/`目录下的一些可执行文件，例如`python`，`pip`，`easy_install`等，在虚拟环境下安装Python库都会被放到`lib/python2(3).x/site-packages/`中。

此时你需要激活该虚拟环境（bin/activate修改了与python相关的一些环境变量，使得其重新指向当前虚拟环境）：

    $ cd demo
    $ source bin/activate
    (demo)$ 
    
激活后，可以看到shell的prompt变为`(demo)`，这表示当前虚拟环境处在`demo`下，你可以`echo $PATH`看下当前的环境变量：

    (demo)$ echo $PATH
    /home/test/Desktop/demo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    
可以看到`demo`虚拟环境中的`bin/`路径已经被设置成了命令查找地址的首选目录，我们再看看当前`python`命令的路径：

    (demo)$ which python
    /home/test/Desktop/demo/bin/python
    (demo)$ which pip
    /home/test/Desktop/demo/bin/pip
    
这时你已经可以使用`pip`或者`easy_install`来安装你项目中所需的第三方库依赖，其会被安装至当前虚拟环境的`lib/python2(3).x/site-packages/`中，与系统Python环境完全隔离，当然你也可以建立多个相互隔离的虚拟Python环境来管理你不同的项目。

离开当前虚拟环境，直接`deactivate`即可：

    (demo)$ deactivate
    $
    
更多请查看官方[文档](https://github.com/pypa/virtualenv)。
