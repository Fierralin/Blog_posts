---
layout: post
title: "Paxos"
date: 2016-12-06 16:25:06
description: Paxos
tags: UNIX OS
share: true
intensedebate: true
---


[wiki][1]

[zhihu][2]

### 分布式系统中节点通信存在两个模型

- 共享内存 Shared Memory
- 消息传递 Messages passing

### Paxos城邦
#### 人员
- **Proposers**
 - 提出提案**`proposal`**(`number`, `value`)
- **Acceptors**
 - 只能接受(accept)提案
- **Learners**
 - 只能学习提案
 - 只能获得被批准(chosen)的`value`

#### 提案**`proposal`**
- 属性
 - **`number`**
 - **`value`**
-

#### 规则
- P1：一个acceptor必须接受（accept）第一次收到的提案。
 - P1a：当且仅当acceptor没有回应过编号大于n的prepare请求时，acceptor接受（accept）编号为n的提案。
- P2：一旦一个具有value v的提案被批准，则之后任何proposer提出的提案必须具有value v —— 此处包含了：之后被批准的提案必须具有value v；accepotor再次接受的提案必须具有value v





[1]:https://zh.wikipedia.org/wiki/Paxos%E7%AE%97%E6%B3%95
[2]:https://www.zhihu.com/question/19787937
