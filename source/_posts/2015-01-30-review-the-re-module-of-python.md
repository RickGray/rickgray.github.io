---
layout: post
title: Python re 模块回顾
tags: [python]
---

使用Python大法已经有一段时间了，re正则模块却一直都还没有吃透，所以重新回顾了该模块和Python中的正则表达式。这里推荐一个在线测试正则表达式的站点-[liveregex.com](https://www.liveregex.com)，对于理解正则匹配的过程是十分有帮助的。

下面详细的给出正则表达式元字符和具体语法：

**一般元字符**：

| . | 匹配任意除换行符'\n'以外的字符，但在DOTALL模式下也可以匹配换行符
| \ | 转义字符，例如当需要匹配点号'.'时，就需使用 \. 或者字符集 [.]
| [...] | 字符集，表示对应的位置可以是字符集中的任意字符，如果字符集以^开头，则表示匹配字符集以外的字符。所有特殊字符在字符集中都将失去原有的特殊含义

**预定义元字符**：

| \d | 匹配数字 0-9 |
| \D | 匹配非数字 |
| \s | 匹配空白字符 [ \t\r\n\f\v] |
| \S | 匹配非空白字符 |
| \w | 匹配单词字符 [a-zA-Z0-9_] |
| \W | 匹配非单词字符 |

**数量词元字符**：

| \* | 匹配前一个字符0次或者多次 (*=0)
| \+ | 匹配前一个字符至少1次或者多次 (*=1)
| ? | 匹配前一个字符0次或者1次 (0 or 1)
| {m} | 匹配前一个字符m次 (m)
| {m,n} | 匹配前一个字符n次到m次，使用时也可以省略其中任意一个边界 (m<=i<=n)
| ? | 表示将其面的匹配模式变为非贪婪模式

**边界元字符**：

| ^ | 匹配字符串的开头，多行模式中匹配每一行的开头。
| $ | 匹配字符穿的结尾，多行模式中匹配每一行的结尾。
| \A | 仅匹配字符串开头
| \Z | 仅匹配字符串结尾
| \b | 匹配\w和\W之间
| \B | [^\b]

**分组**：

| \| | 表示匹配左右表达式中任意匹配一个，顺序从左往右，一旦匹配成功则跳过匹配右边表达式
| (...) | 使用括号括起来的表达式作为分组，且每个分组都有相应的编号，在表达式中能直接使用分组编号
| (?P\<name>...) | 作用同上，但是可以自定义该分组的名字
| \<number> | 引用编号为<number*的分组匹配到的字符串
| (?P=name) | 引用名字为<name*的分组匹配到的字符串

**特殊**：

| (?:...) | (...)的不分组形式，多用于(?:abc\|edf)这种多类匹配形式
| (?iLmsux) | 设置表达式的匹配模式，用于表达式的开头
| (?#...) | 表达式中的注释，#后面的内容会被注释
| (?=...) | 之后的表达式需要匹配...的内容才能最终匹配成功
| (?!...) | 之后的表达式需要不匹配...的内容才能最终匹配成功
| (?<=...) | 在之前的表达式需要匹配...的内容才能最终匹配成功
| (?<!...) | 在之前的表达式需要不匹配...的内容才能最终匹配成功
| (?(id/name)yes-pattern\|no-pattern) | 如果匹配到id/name的组字符，则需要匹配到yes-pattern，否则匹配no-pattern

re模块中有4个常用的匹配函数：

| match() | 始终从字符串开头开始匹配，匹配成功返回第一个匹配到的对象，否则返回None
| search() | 可以从字符串任意匹配，匹配成功返回第一个匹配到的对象，否则返回None
| findall() | 匹配字符串中所有符合正则表达式的匹配项，并以列表返回
| finditer() | 匹配字符串中所有符合正则表达式的匹配项，以迭代器形式返回

基本上正则中的元字符已经列举完了，下面开始一些实战练习。

e.g. email地址匹配：``([a-z0-9_\.-]+@[\da-z\.-]+\.[a-z\.]{2,20})``

```python
import re
s = '''
Description:
We begin by telling the parser to find the beginning of the string (^). Inside the first group, we match one or more lowercase letters, numbers, underscores, dots, or hyphens. I have escaped the dot because a non-escaped dot means any character. Directly after that, there must be an at sign. Next is the domain name which must be: one or more lowercase letters, numbers, underscores, dots, or hyphens. Then another (escaped) dot, with the extension being two to six letters or dots. I have 2 to 6 because of the country specific TLD's (.ny.us or .co.uk). Finally, we want the end of the string ($).
String that matches:
john@doe.com
String that doesn't match:
john@doe_something (TLD is too long)
'''
m = re.match('^.*\s([a-z0-9_\.-]+@[\da-z\.-]+\.[a-z\.]{2,20})', s, re.DOTALL)
print m.groups()
```

因为这里需要匹配的文本是多行，所以为了方便匹配进行多行匹配，这里显示使用了``DOTALL``匹配模式，使得``.``能够匹配``\n``。（若不使用多行匹配模式，则只能在正则表达式中显示的使用\s来匹配空白符）

这里还要说一个需要注意的地方，在使用re模块时可能会被忽视的地方。re模块中有两个相似的函数``match()``和``search()``，在使用并无太大区别，但在匹配方式上有一点点的小差别，``match()``是从字符串的起点开始做匹配，而``search()``是从字符串做任意匹配。下面这个小例子可以说明这一点：

```python
import re
s = 'Hello World!'
print re.match(r'e', s)
```

这里使用了``match()``函数，正则表达式并没有指定``e``字符之前的匹配，所以会匹配失败输出``None``。

```python
import re
s = 'Hello World!'
print re.search(r'e', s)
```

这里使用了``search()``函数，正则表达式并没有指定``e``字符之前的匹配，但是由于``search()``可以从字符串做任意匹配，所以会匹配失败输出实例对象``<_sre.SRE_Match object at 0x10e718648>``。

说了这么多，我们回到最开始的邮件匹配表达式``([a-z0-9_\.-]+@[\da-z\.-]+\.[a-z\.]{2,20})``，其中``[a-z0-9_\.-]+``匹配的是邮件地址用户名（由字母、数字、点、减号和下划线组成，只能以数字或字母开头he结尾），如果要比较严格的正则则应该为``[a-z0-9][a-z0-9_\.-]+[a-z0-9]``；``@``匹配@符号；``[\da-z\.-]+\.[a-z\.]{2,20}``匹配邮件所属域名（若想严格一点使用[a-z]作为表达式结尾，防止匹配到"rickchen.vip@gmail.com."这种格式）。

再来一段待匹配的文本，然后从中匹配出email地址：

    -*&*!#rickchen.vip@gmail.com=====163.com======123123%!@414842588@qq.com,root@0xfa.club

这里使用的正则表达式为：``([a-z0-9][a-z0-9_\.-]+[a-z0-9]@[\da-z\.-]+\.[a-z\.]{2,20}[a-z])``，因为``match()``和``search()``匹配到一个就会结束匹配，所以这里使用re模块中的``finditer()``来匹配所有满足正则表达式的文本，并将它们作为迭代器返回。

```python
import re
s = '-*&*!#rickchen.vip@gmail.com=====163.com======123123%!@414842588@qq.com,root@0xfa.club'
for m in re.finditer(r'([a-z0-9][a-z0-9_\.-]+[a-z0-9]@[\da-z\.-]+\.[a-z\.]{2,20}[a-z])', s):
    print m.group()
```

代码输出结果为：

    rickchen.vip@gmail.com
    414842588@qq.com
    root@0xfa.club

下面使用自定义名字分组来分别获取：email地址、email用户名、email所属域名。在Python里面指定分组名称表达式为``(?P<name>...)``，所以表达式在原有的基础上做一点分组命名处理：

    (?P<email>(?P<username>[a-z0-9][a-z0-9_\.-]+[a-z0-9])@(?P<domain>[\da-z\.-]+\.[a-z\.]{2,20}[a-z]))

更改代码；

```python
import re
s = '-*&*!#rickchen.vip@gmail.com=====163.com======123123%!@414842588@qq.com,root@0xfa.club'
for m in re.finditer(r'(?P<email>(?P<username>[a-z0-9][a-z0-9_\.-]+[a-z0-9])@(?P<domain>[\da-z\.-]+\.[a-z\.]{2,20}[a-z]))', s):
    print 'Email: "%s" (Username: "%s", Domain: "%s")' % (m.group('email'), m.group('username'), m.group('domain'))
```

代码输出结果为：

    Email: "rickchen.vip@gmail.com" (Username: "rickchen.vip", Domain: "gmail.com")
    Email: "414842588@qq.com" (Username: "414842588", Domain: "qq.com")
    Email: "root@0xfa.club" (Username: "root", Domain: "0xfa.club")

这里也可以不使用m.group('email')来获取``email``分组的值，可以使用``groupdict()``返回一个以别名为键值的字典（没有设置别名的不包含在内）。e.g.``m.groupdict()['email']``为匹配到的``email``分组的值。

上面是一个简单的email地址匹配的例子，下面给一个简单的匹配html闭合标签的例子。

这里有一段html文本，为了演示方便将其融为一行：

    <div><h1>Hello World!</h1><a href="http://rickgray.me">rickgray.me</a><div><p>This is testing!</p></div></div>

闭合标签指的是，<TAG>...</TAG>成对出现的标签，像``<div>...</div>``、``<h1>...</h1>``、``<a>...</a>``这些都属于闭合类型的标签，因为闭合标签成对出现所以一个简单的正则表达式可以这样写：``<(?P<tag>[^>]+)>(?P<value>.*)</(?P=tag)>``，看下面这段代码：

```python
import re
s = '<div><h1>Hello World!</h1><a href="http://rickgray.me">rickgray.me</a><div><p>This is testing!</p></div></div>'
m = re.search(r'<(?P<tag>[^>]+)>(?P<value>.*)</(?P=tag)>', s)
if m:
    print 'Tag: "%s"' % m.group('tag')
    print 'Value: "%s"' % m.group('value')
```

代码输出结果为：

    Tag: "div"
    Value: "<h1>Hello World!</h1><a href="http://rickgray.me">rickgray.me</a><div><p>This is testing!</p></div>"

这里可以更完善一点的使用``<(?P<tag>[^>]+)\b[^>]*>(?P<value>.*)</(?P=tag)>``来匹配像``<a href="http://rickgray.me">rickgray.me</a>``这种含有属性的标签。在匹配标签值是使用的是贪婪模式``.*``而不是非贪婪模式``.*?``，如果这里使用非贪婪模式则输出结果则应该为（以第一个</div>作为结束标志，并不是正确的）：

    Tag: "div"
    Value: "<h1>Hello World!</h1><a href="http://rickgray.me">rickgray.me</a><div><p>This is testing!</p>"

这里可以写个递归匹配闭合标签的函数``get_tags()``，如下：

```python
def get_tags(s, d=0):
    tag_regex = r'<(?P<tag>[^>]+)\b[^>]*>(?P<value>.*)</(?P=tag)>'
    for m in re.finditer(tag_regex, s, re.DOTALL):
        print ' '*d,'%s ==> %s' % (m.group('tag'), m.group('value'))
        get_tags(m.group('value'), d+4)
```

这里重新找段测试html文本，将其保存为``demo.txt``：

```html
<!DOCTYPE HTML>
<html lang="zh">
<head>
    <meta charset="utf-8">
    <title>Home - Quiet And Powerful</title>
</head>
<body>
<div class="container">
    <div class="left-col">
        <header id="header" class="inner">
            <h1><a href="/">Quiet And Powerful</a></h1>
        </header>
    </div>
    <div class="mid-col">
        <div class="mid-col-container">
            <h2 class="year">2014</h2>
            <ul>
                <li>
                    <h3 class="title"><a href="/2014/12/08/sctf2014-writeup.html">SCTF2014 Writeup</a>
                    </h3>
                </li>
            </ul>
        </div>
        <footer id="footer" class="inner"><p>
            Copyright &copy; 2015
        </p>
        </footer>
    </div>
</div>
</body>
</html>
```

下面是测试代码：

```python
import re

def get_tags(s, d=0):
    tag_regex = r'<(?P<tag>[^>]+)\b[^>]*>(?P<value>.*)</(?P=tag)>'
    for m in re.finditer(tag_regex, s, re.DOTALL):
        print ' '*d,'[[%s]] ==> "%s"' % (m.group('tag'), m.group('value'))
        get_tags(m.group('value'), d+4)

content = open('demo.txt', 'r').read()

get_tags(content)
```

代码输出太多这里就不贴出来了，可以亲手实践一下。这里的递归闭合标签的函数``get_tags()``并不是很完善，还存在着一些bug，可以对其进行完善，甚至DIY一个html解析器出来。

对于re的回顾暂时就这么多了，正则想要学好最重要的就是多练习多实践。：）
