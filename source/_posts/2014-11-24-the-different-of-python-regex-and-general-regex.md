---
layout: post
title: Python 正则表达式之异
tags: [python]
---


这里总结了python正则表达式与一般正则表达式在语法上的一些不同，和python写正则表达式时需要注意的地方。

关于正则表达式的学习这里有两个地方个人认为还不错的：[正则表达式30分钟入门教程](http://www.jb51.net/tools/zhengze.html) 和 [正则基础](http://blog.csdn.net/lxcnn/article/category/538256)。

前者用于快速入门，而后者对正则表达时的每个部分和各种匹配模式都有很详细地讲解，适合深入学习。

## 一、区别

### 1. 捕获与后向引用

python中给所捕获的组自定义命名与常规使用`(?<name>expression)`的语法不一样，python使用其特定的`P`标记给捕获的组命名，格式为`(?P<name>expression)`。

python中使用自定义命名进行后向引用时也有别于常规的`\k<name>`，同样适用`P`标记，并且其写法比较人性化（个人认为）格式为`(?P=name)`，例如：

* 测试字符串："word word go go fal fal"
* 正则式："\b(?P<word>\w+)\b\s+(?P=word)\b"
* 描述：匹配连续两次出现的单词

```python
>>> import re
>>> re.findall(r"\b(?P<word>\w+)\b\s+(?P=word)\b", "word word go go fal fal")
['word', 'go', 'fal']
>>>
```

## 二、注意

### 1. 转义字符与原始字符串

python写正则表达式的时候，要特别注意转义字符与原始字符串的问题。

例如我想要从字符串`I'm singing while you're dancing`中匹配出使用了动名词形式单词的ing前面部分（sing、danc），正则表达式为：`\b\w+(?=ing\b)`，如果在python用以下格式则不会匹配成功：

* 测试字符串："I'm singing while you're dancing"
* 正则式："\b\w+(?=ing\b)"
* 描述：匹配以动名词形式结尾的单词的ing前面部分

```python
>>> import re
>>> re.findall("\b\w+(?=ing\b)", "I'm singing while you're dancing")
[]
>>>
```

注意在上面的`re.findall()`中，正则表达式中存在`\b`字符，在python中具有退格的转义含义，但是`\b`在正则表达式中意为匹配单词的开始或结束，因此为了防止字符串被转移需要带上`r`标志，使用原始字符串形式：

```python
>>> import re
>>> re.findall(r"\b\w+(?=ing\b)", "I'm singing while you're dancing")
['sing', 'danc']
>>>
```

### 2. 贪婪与懒惰

在正则表达式中包含能够接受重复的元字符时（ '*' '?' ...），通常的行为是尽可能多的匹配字符。例如：

* 测试字符串："aabab"
* 正则式："a.*b"
* 描述：匹配以a开始，以b结束的最长字符串

```python
>>> import re
>>> re.findall(r"a.*b", "aabab")
['aabab']
>>>
```

上述情况被称为`贪婪`匹配。

但是有时候希望极可能少的匹配字符，这时候就需要进行``懒惰（非贪婪）``匹配了。要想使用懒惰（非贪婪）匹配模式，只需在具有重复意义的元字符后面加上一个问号 '?'。这样``.*?``匹配的含义就变为：匹配任意数量的重复，但是在能使整个匹配成功的前提下使用最少的重复。例如：

* 测试字符串："aabab"
* 正则式："a.*b?"
* 描述：匹配以a开始，以b结束的最长字符串

```python
>>> import re
>>> re.findall(r"a.*?b", "aabab")
['aab', 'ab']
>>>
```

通过上面的例子应该能很好的理解贪婪与懒惰（非贪婪）这两种匹配模式的差异了。
