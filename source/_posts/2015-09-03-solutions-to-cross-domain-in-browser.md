---
layout: post
title: 浏览器中的跨域资源请求
tags: [web, security]
---

[同源策略](http://baike.baidu.com/view/3747010.htm)-是针对浏览器所设计的一项安全规定，页面中所渲染的资源（JavaScript脚本除外）都需要符合同源策略才能够正常访问。

在构建 Web 项目或者进行 XSS 攻击时，常常需要进行跨域资源访问。设想这样一个场景：攻击者 Attacker 在网站 A 上注入了一段恶意 JS 代码，用来盗取访问者的浏览器、Cookie、IP 等信息，并通过 ajax 请求将这些信息以参数的形式（GET、POST 皆可）发送至攻击者事先准备好的服务站 B 上。若按同源策略规定，在网站 A 上不能直接请求或者发送数据至网站 B，那么这里就要用到一些跨域资源请求的方法。

通过总结已公开的跨域方法并结合自己的理解和实践，将几种跨域资源请求的方法通过实例 Demo 的形式详细记录如下。

网站 A 要获取网站 B 上的资源内容，跨域方法分为 `网站 B 可控` 和 `网站 B 不可控` 两类（可控指能更改 Web 服务器设置或者页面内容）。

### 网站 B 可控的跨域方法：

1. 同主域名下iframe控制document.domain进行跨域
2. iframe集合location.hash进行跨域数据获取
3. 通过iframe.name跨域传递数据
4. 将数据通过 JS 进行直接加载
5. html5中的postMessage
6. 利用 CORS 进行跨域 

### 网站 B 不可控的跨域方法：

1. 代理服务（Proxy）


## 一、网站 B 可控的跨域

为了更好的进行 Demo 演示，事先设置域名解析情况如下（192.168.130.200为本地虚拟机）：

	a.0xfa.club ==> 192.168.130.200（网站 A）
	b.0xfa.club ==> 192.168.130.200（网站 B）

### 1. 同主域名下iframe控制document.domain进行跨域

网站 B 上有一资源文件 `data.html`，其 URL 为 `http://b.0xfa.club/data.html`，内容如下：

```html
<p id="data">Hello A Site!!</p>
```	
	
如果网站 A 想要获取 `id="data"` 的文本值 `Hello A Site!!`，在不考虑同源策略的情况下可以有如下代码：

```html
<html>
<head>
  <title>a.0xfa.club/in.html</title>
</head>
<body>
<script>
var iframe = document.createElement('iframe');
iframe.src = 'http://b.0xfa.club/location/data.html';
iframe.style.display = 'none';
iframe.onload = function() {
	var doc = iframe.contentDocument || iframe.contentWindow.document;
	console.log(doc.getElementById('data').textContent);
}
document.body.appendChild(iframe);
</script>
</body>
</html>
```

但是实际访问情况下，由于浏览器的同源策略限制，并不能成功获取数据并通过调试终端输出数据，浏览器一般会在终端下输出错误，提示跨域访问失败。（此处为 Chrome）

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/1.png)

这时候，由于网站 A 和 B 都属于 `0xfa.club` 的子域，加上网站 B 可控，设置网站 document.domain 为统一主域 `0xfa.club` 即可进行跨域访问，完整的代码示例如下：

`http://a.0xfa.club/in.html` 源码：

```html
<html>
<head>
  <title>a.0xfa.club/in.html</title>
</head>
<body>
<script>
document.domain = '0xfa.club';
var iframe = document.createElement('iframe');
iframe.src = 'http://b.0xfa.club/location/data.html';
iframe.style.display = 'none';
iframe.onload = function() {
	var doc = iframe.contentDocument || iframe.contentWindow.document;
  	console.log(doc.getElementById('data').textContent);
}
document.body.appendChild(iframe);
</script>
</body>
</html>
```

`http://b.0xfa.club/data.html` 源码：

```html
<script>
document.domain = '0xfa.club';
</script>
<p id="data">Hello A Site!!</p>
```

通过设置双方网站 `document.domain` 为同一主域，再次访问后，可以看到在访问 `http://a.0xfa.club/in.html` 页面时，成功获取 `http://b.0xfa.club/data.html` 中的数据并在调试窗口打印出来。

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/2.png)

### 2. iframe结合location.hash进行跨域数据获取

利用location.hash的变化来传递数据相对来说比较复杂，IE 和 Chrome 的安全机制无法在页面上直接更改父级窗口的 location.hash 值。在网站 A 的页面上创建了 `iframe` 来加载 网站 B 的页面内容，由于同源策略的关系和浏览器安全机制的关系，网站 B 的JS 脚本不能通过直接修改 `parent.location.hash`，因为其不同源。

但是，若再在网站 B 上创建 `iframe` 加载网站 A 上的一个代理页面，代理页面通过访问 `parent.parent`，因为代理页面和网站 A 同源，自然而然就能够修改 `parent.parent.location.hash` 的值了，Demo 代码如下。

`http://a.0xfa.club/hash/in.html` 源码：

```html
<html>
<head>
  <title>Site A</title>
</head>
<body>
<script>
var iframe = document.createElement('iframe');
iframe.style.display = 'none';
iframe.src = 'http://b.0xfa.club/hash/data.html#param';
document.body.appendChild(iframe);

var checkOut = function() {
	try {
		var data = location.hash ? location.hash.substring(1) : '';
		if (console.log) {
			console.log('new data is: ' + data);
		}
  	} catch(e) {}
}
setInterval(checkOut, 2000);
</script>
</body>
</html>
```

`http://b.0xfa.club/hash/data.html` 源码：

```html
<html>
<head>
  <title>Site B</title>
</head>
<body>
<script>
try {
	parent.location.hash = 'bsitedata';
} catch(e) {
	var ifr = document.createElement('iframe');
	ifr.style.display = 'none';
	ifr.src = 'http://a.0xfa.club/hash/proxy.html#bsitedata';
	document.body.appendChild(ifr);
}
</script>
</body>
</html>
```

`http://a.0xfa.club/hash/proxy.html` 源码：

```html
<script>
parent.parent.location.hash = self.location.hash.substring(1);
</script>
```

现在访问 `http://a.0xfa.club/hash/in.html` 页面时，网站 B 成功的修改了 `location.hash` 值并被网站 A 捕获，通过调试窗口打印出来。

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/3.png)

### 3. 通过iframe.name跨域传递数据

由于 `iframe` 加载后页面可以动态修改其 `contentWindow.location` 来使得本来不同源的情况下变得同源，而若网站 A 在加载网站 B 的页面 `data.html` 时，`data.html` 中设置了 `window.name` 的值，那么在网站 A 上通过修改 `iframe.contentWindow.location` 的值使得同源，然后就成功获取到网站 B 传递通过 `window.name` 传递过来的数据。

`http://a.0xfa.club/name/in.html` 源码：

```html
<html>
<head>
  <title>a.0xfa.club/name/in.html</title>
</head>
<body>
<script>
var state = 0;
var iframe = document.createElement('iframe');
iframe.src = 'http://b.0xfa.club/name/data.html';
iframe.style.display = 'none';
var loadfn = function() {
	if (state === 1) {
		var data = iframe.contentWindow.name;
		console.log(data);
	} else if (state === 0) {
		state = 1;
		iframe.contentWindow.location = 'http://a.0xfa.club';
	}
}
iframe.onload = loadfn;
document.body.appendChild(iframe);
</script>
</body>
</html>
```

`http://b.0xfa.club/name/data.html` 源码：

```html
<script>
window.name = 'content of "b.0xfa.club"';
</script>
```

访问网站 A 的页面 `http://a.0xfa.club/name/in.html`，页面动态创建 `iframe` 加载网站 B 的资源 `http://b.0xfa.club/name/data.html`，而网站 B 的页面将需要传递的数据通过 `window.name` 进行设置。待动态创建的 `iframe` 加载完毕后，网站 A 的页面再通过更改 `iframe.contentWindow.location` 来使得加载的内容符合同源策略，但是此时的 `iframe` 框的 `window.name` 值已经被网站 B 上的页面设置过了，所以其值会被设置为 `content of "b.0xfa.club"`。

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/4.png)

### 4. 将数据通过 JS 进行直接加载

因为页面可以外部加载 JS 的原因，因此不同源的两个站点可以通过 JS 来进行跨域传递数据。

`http://a.0xfa.club/script/in.html` 源码：

```html
<script src="http://b.0xfa.club/script/data.html" id="p"></script>
<script>
console.log(data);
</script>
```

`http://b.0xfa.club/script/data.html` 源码：

```html
var data = 'b site data';
```

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/5.png)

### 5. html5中的postMessage

html5 中提供了一个安全跨域传输的 API - postMessage ([详细文档](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage))，通过使用 `postMessage` 可以直接设置 Origin，来达到同源的作用。

`http://a.0xfa.club/html5/in.html` 源码：

```html
<html>
<head>
  <title>Html5 postMessage</title>
</head>
<body>
<iframe id="ai" src="http://b.0xfa.club/html5/data.html"></iframe>
<script>
function changeColor() {
	var ifr = document.getElementById('ai');
	var targetOrigin = 'http://b.0xfa.club';
	ifr.contentWindow.postMessage('rgb(0, 255, 0)', targetOrigin);
}
</script>
<a href="#" onclick="changeColor()">Click here to change "iframe" color</a>
</body>
</html>
```

`http://b.0xfa.club/html5/data.html` 源码：

```html
<html>
<head>
  <title>Site B</title>
  <style>
  body {
    background-color: rgb(255, 0, 0);
  }
  </style>
<body>
<script>
window.addEventListener('message', function() {
	document.body.style.backgroundColor = event.data;
	console.log(event.data);
});
</script>
</script>
</body>
</html>
```

这里网站 A 的页面通过向内嵌的网站 B 的页面发送新的背景颜色值，网站 B 页面收到新值后修改当前背景颜色。通过这个简单的演示足以说明 html5 中 postMessage 在进行跨域传输时的便捷性。

点击前：

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/6.png)

点击后：

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/7.png)

### 6. 利用 CORS 进行跨域 

CORS 名为跨域资源共享（Cross-Origin Resource Sharing），是通过控制网站 B 的相应头部字段来实现的。要实现CORS 必须对被请求的网站 B 做一定的设置，主要就是通过设置相应头中的 `Access-Control-Allow-Origin` 字段。`Access-Control-Allow-Origin` 响应字段说明了该资源或网站所允许被非同源站点访问的站点列表，当 `Access-Control-Allow-Origin` 中包含网站 A 或者设置为 `*` 时，网站 A 即可对网站 B 上的资源进行任意访问。

这里网站 B 使用 PHP 来设置 `Access-Control-Allow-Origin` 响应头字段。

```php
<?php
//header("Access-Control-Allow-Origin: *");  //先注释掉，看网站 A 是否能成功请求资源
echo "Site B PHP resource!!";
```

网站 A 的页面 `http://a.0xfa.club/cors/in.html` 通过 `XMLHttpRequest` 来请求网站 B 的页面资源 `http://b.0xfa.club/cors/data.php`：

```html
<script>
var xml = new XMLHttpRequest();
xml.open('get', 'http://b.0xfa.club/cors/data.php', true);
xml.onreadystatechange = function() {
	if (xml.readyState == 4 && xml.status==200) {
		console.log(xml.responseText);
	}
}
xml.send();
</script>
```

尝试访问，发现在不设置网站 B 页面的响应头字段 `Access-Control-Allow-Origin`，同样会被同源策略所限制。

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/8.png)

现在将 `//header("Access-Control-Allow-Origin: *");` 注释一行去掉，再次访问，就能够跨域了。

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/9.png)

## 二、网站 B 不可控

### 1. 代理服务（Proxy）

在网站 B 不可控，即不能设置网站 B 的相关设置时，最有效的方法就是建立中间代理了。

网站 A 将访问网站 B 的请求通过参数的形式发送给代理服务器（Proxy），代理服务器收到请求后转而去访问网站 B，然后将获取的信息再返回给网站 A，形成一个数据请求回路。

	A  --request-> C --request->  B
    A  <-response- C <-response-  B
	
`http://a.0xfa.club/proxy/in.html` 源码：

```html
<html>
<head>
  <title>Proxy Site A</title>
</head>
<body>
<script>
var xhr = new XMLHttpRequest();
var proxyUrl = 'http://a.0xfa.club/proxy/proxy.php';
xhr.open('post', proxyUrl, true);
xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
xhr.send('method=get&target=http://b.0xfa.club/proxy/data.html&data=');
xhr.onreadystatechange = function() {
	if (xhr.readyState == 4 && xhr.status==200) {
		console.log(xhr.responseText)
	}
}
</script>
</body>
</html>
```

`http://b.0xfa.club/proxy/data.html` 源码：

	Hello Site A!!
	
代理服务代码（可以不与网站 A 同源，设置 `Access-Control-Allow-Origin` 相应头即可），代码如下：

```php
<?php
header('Access-Control-Allow-Origin: *');

$method = $_REQUEST['method'];
$target = $_REQUEST['target'];
$data = $_REQUEST['data'];

$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $target);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, 0);

if ($method == 'post') {
	curl_setopt($curl, CURLOPT_POST, 1);
	curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
}

curl_exec($curl);
curl_close($curl);
```

具体参数接口可根据需求进行设定，该方法的好处就是灵活，定制型高，缺点就是需要自行构建代理服务。（上面代理代码小心测试，有漏洞噢！）

![](/images/articles/2015-09-03-solutions-to-cross-domain-in-browser/10.png)

### 记在最后

当然，上面所列出的这些跨域姿势并不是全部（还有 Flash 等），并不是每个都那么的好用和灵活，不同的项目有不同的需求，跨域方法需要根据实际需求进行调整和变换。：）

### 参考

* [http://www.cnblogs.com/rainman/archive/2011/02/20/1959325.html](http://www.cnblogs.com/rainman/archive/2011/02/20/1959325.html)
* [https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Access_control_CORS](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Access_control_CORS)
