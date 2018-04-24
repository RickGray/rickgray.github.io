---
layout: post
title: PyYAML 对象类型解析导致的命令执行问题
tags: [web, security]
---

近日回顾了 PyCon 2015 上 [@Tom Eastman](https://twitter.com/tveastman) 所讲的关于 Python 序列化格式的安全议题 -[《Serialization formats are not toys》](https://www.youtube.com/watch?v=kjZHjvrAS74)。议题主要介绍了 YAML、XML 和 JSON 三种格式用于 Python 序列化数据处理所存在的一些安全问题，其中 XML 部分讲解的是 Python 中的 XXE，而 Python 处理 JSON 数据本身不存在问题，但在前端 JavaScript 对返回 JSON 进行处理时常常直接使用 `eval()` 来转换类型从而留下安全隐患。

关于 XML 和 JSON 格式相关的安全问题本文就不多提了，本文仅记录下议题中所提到的 Python PyYAML 模块在处理 YAML 格式数据时所存在的问题。

### 一、Python 中处理 YAML 格式数据

YAML 在数据序列化和配置文件中使用比较广泛，在 Ruby On Rails 中就使用 YAML 作为配置文件。最新的 YAML 标准版本为 1.2，而目前大多数语言对 YAML 解析实现都为 1.1 甚至 1.0 版本，各版本标准可通过官方 [yaml.org](http://www.yaml.org) 进行查阅。一个简单的 YAML 数据为：

```yaml
---
date: !!str 2016-03-09
weekday: Wednesday
weather: sunny
plans: &plans
    1: daliy resarch
    2: daliy meals
    3: play games tonight
todo:
    <<: *plans
    3: others
...
```

保存为 `sample.yml` 然后使用 Python 第三方模块 PyYAML（pip install PyYAML) 来对其进行解析并输出：

```python
import yaml
import pprint

pprint.pprint(yaml.load(file('sample.yml', 'r')))
```

运行代码可以得到输出：

```
(env)➜  python python test.py
{'date': '2016-03-09',
 'plans': {1: 'daliy resarch', 2: 'daliy meals', 3: 'play games tonight'},
 'todo': {1: 'daliy resarch', 2: 'daliy meals', 3: 'others'},
 'weather': 'sunny',
 'weekday': 'Wednesday'}
```

PyYAML 在解析数据的时候遇到特定格式的时间数据会将其自动转化为 Python 时间对象，例如 `sample.yml` 中 `date` 节点的值使用 `!!str` 指定其在解析的时候转换为字符串，如果不使用强制类型转换，会自动将 `2016-09-03` 解析为 Python 中的 `datetime.date` 对象。如下代码和输出：

```python
import yaml
import pprint

content = '''---
date: 2016-03-09
...'''
pprint.pprint(yaml.load(content))
# (env)➜  python python test1.py
# {'date': datetime.date(2016, 3, 9)}
```

（本文重点不在 YAML 格式上，详情可参考官方文档和 wiki）

### 二、PyYAML 特有类型解析 Python 对象

除开 YAML 格式中常规的列表、字典和字符串整形等类型转化外，各个语言的 YAML 解析器或多或少都会针对其语言实现一套特殊的对象转化规则。例如 Ruby 中可以将类对象 dump 为 YAML 格式的文本数据（文件 `person.rb`）：

```ruby
require 'yaml'

class Person
  attr_accessor :name, :age, :children
  def initialize(name, age, children=nil)
    @name = name
    @age = age
    @children = children
  end
end
children = [Person.new('John Smith', 12), Person.new('Jan Smith', 11)]
tom = Person.new('Tom Smith', 23, children)
File.open('sample2.yml', 'w') do |os|
  YAML::dump(tom, os)
end
```

运行脚本得到输出为（为了突入结构将其格式化，默认情况缩紧不严谨）：

```
--- 
!ruby/object:Person
    name: Tom Smith
    age: 23
    children:
        - !ruby/object:Person
            name: John Smith
            age: 12
            children:
        - !ruby/object:Person
            name: Jan Smith
            age: 11
            children:
```

其中 `!ruby/object:Person` 指代的是 `person.rb` 中的 `Person` 类，是 Ruby 里 yaml 模块针对 Ruby 语言的特有实现，如果使用其他语言的 YAML 解析器来加载这段 YAML 文本必定会报错。不同语言针对 YAML 基本都有一套其对语言对象的解析扩展，这也是 YAML 在各语言之间兼容性差的原因之一。

而在 Python 中，一个对象序列化为 YAML 数据是这个样子的：

```python
import yaml

class Person(object):
    def __init__(self, name, age, sponse=None, children=None):
        self.name = name
        self.age = age
        self.sponse = sponse
        self.children = children

jane = Person('Jane Smith', 25)
children = [Person('Jimmy Smith', 15), Person('Jenny Smith', 12)]
john = Person('John Smith', 37, jane, children)

print yaml.dump(john)
print yaml.dump(open('sample.yml', 'r'))
```

运行脚本输出结果为：

```
(env)➜  python python person.py
!!python/object:__main__.Person
age: 37
children:
- !!python/object:__main__.Person {age: 15, children: null, name: Jimmy Smith, sponse: null}
- !!python/object:__main__.Person {age: 12, children: null, name: Jenny Smith, sponse: null}
name: John Smith
sponse: !!python/object:__main__.Person {age: 25, children: null, name: Jane Smith,
  sponse: null}

!!python/object:__builtin__.file {}
```

可以看到 `!!python/object:__main__.Person` 为 PyYAML 中对 Python 对象的类型转化标签，在解析时会将后面的值作为 `Person` 类的实例化参数进行对象还原。在上面的测试代码中特地 dump 了一下文件对象 `open('sample.yml', 'r')`，在 YAML 中对应的数据为 `!!python/object:__builtin__.file {}`，这里参数为空，其实通过 PyYAML load() 还原回去会发现是一个为初始化参数并已经处于关闭状态的畸形 file 实例对象。

然而看到 `__builtin__` 这个关键字就应该敏感起来，通过查看 PyYAML 源码可以得到其针对 Python 语言特有的标签解析的处理函数对应列表（`$PYTHON_HOME/lib/site-packages/yaml/constructor.py`612 - 674 行）：

```
!!python/none             =>  Constructor.construct_yaml_nul
!!python/bool             =>  Constructor.construct_yaml_boo
!!python/str              =>  Constructor.construct_python_str
!!python/unicode          =>  Constructor.construct_python_unicode
!!python/int              =>  Constructor.construct_yaml_int
!!python/long             =>  Constructor.construct_python_long
!!python/float            =>  Constructor.construct_yaml_float
!!python/complex          =>  Constructor.construct_python_complex
!!python/list             =>  Constructor.construct_yaml_seq
!!python/tuple            =>  Constructor.construct_python_tuple
!!python/dict             =>  Constructor.construct_yaml_map
!!python/name:            =>  Constructor.construct_python_name
!!python/module:          =>  Constructor.construct_python_module
!!python/object:          =>  Constructor.construct_python_object
!!python/object/apply:    =>  Constructor.construct_python_object_apply
!!python/object/new:      =>  Constructor.construct_python_object_new
```

其中需要特别指出的是 `!!python/object/apply` 这个对象标签，通过该标签可以在 PyYAML 解析 YAML 数据时，动态的创建 Python 对象，关键代码如下（`$PYTHON_HOME/lib/site-packages/yaml/constructor.py` 574 - 607 行）：

```python
    def construct_python_object_apply(self, suffix, node, newobj=False):
        # ...
        if isinstance(node, SequenceNode):
            args = self.construct_sequence(node, deep=True)
            kwds = {}
            state = {}
            listitems = []
            dictitems = {}
        else:
            value = self.construct_mapping(node, deep=True)
            args = value.get('args', [])
            kwds = value.get('kwds', {})
            state = value.get('state', {})
            listitems = value.get('listitems', [])
            dictitems = value.get('dictitems', {})
        instance = self.make_python_instance(suffix, node, args, kwds, newobj)  # 使用参数实例化指定对象
        if state:
            self.set_python_instance_state(instance, state)
        if listitems:
            instance.extend(listitems)
        if dictitems:
            for key in dictitems:
                instance[key] = dictitems[key]
        return instance
```

例如提供 Python 标签 `!!python/object/apply:time.ctime []`，最终在解析过程中会动态加载 time 模块然后调用 `ctime()` 函数，具体实现在 `make_python_instance()` 中，处理过程可自行查看源码，这里就不单独分析了。

### 三、load() 和 safe_load()

前面已经说过通过 `!!python/object/apply` 这个对象标签可以在 PyYAML 解析（反序列化）的时候构造 Python 对象实例和调用函数，既然能够调用函数了那正常情况下命令执行也是没有问题的了，示例代码如下：

```python
import yaml

content = '''---
!!python/object/apply:subprocess.check_output [[ls]]
...'''
print yaml.load(content)
```

运行结果如下：

![](/images/articles/2016-03-09-pyyaml-tags-parse-to-command-execution/1.png)

这里只是举了一个通过 PyYAML 解析 YAML 数据来执行 `subprocess.check_output` 函数的例子，更复杂的 Payload 可以自行尝试构造。

其实这里有个很严重的问题就是 PyYAML 在解析创建 Python 对象时，并没有限制函数类型的传递：

```python
    def make_python_instance(self, suffix, node,
            args=None, kwds=None, newobj=False):
        if not args:
            args = []
        if not kwds:
            kwds = {}
        cls = self.find_python_name(suffix, node.start_mark)
        if newobj and isinstance(cls, type(self.classobj))  \
                and not args and not kwds:
            instance = self.classobj()
            instance.__class__ = cls
            return instance
        elif newobj and isinstance(cls, type):
            return cls.__new__(cls, *args, **kwds)
        else:
            return cls(*args, **kwds)  # 如果 cls 为函数则直接进行调用
```

可以看到如果需要实例化的对象为函数类型，在最后会直接 `return cls(*args, **kwds)` 进行函数调用（cls 此时为 function），从而导致通过该特性可以直接调用一些危险函数。

PyYAML 的 `load()` 函数为非安全的解析方法，可以解析其针对 Python 对象实现的扩展标签。但是为了防止一些情况下 YAML 数据受到控制，可以使用 `safe_load()` 函数来进行安全解析，在 `SafeLoader` 中去掉了对 Python 对象标签的支持，可以防止恶意数据造成的命令执行等问题。

### 四、总结

虽然 YAML 一般不会做为用户可控的数据传递给服务器解析，但是针对 PyYAML 这种存在隐患的解析方式，应该采取默认安全解析的方式，也就是使用 `safe_load()` 作为默认的数据解析方法来禁止特有对象标签的解析。这样虽然去掉了针对 Python 对象的支持，但是一定程度上确保了安全。

（不能为了便利而舍弃了安全，两者应该做到一种平衡，而不是过度倾向于某一边。）

### 参考

* [https://en.wikipedia.org/wiki/YAML](https://en.wikipedia.org/wiki/YAML)
* [https://www.youtube.com/watch?v=kjZHjvrAS74](https://www.youtube.com/watch?v=kjZHjvrAS74)
* [http://www.yaml.org/](http://www.yaml.org/)
