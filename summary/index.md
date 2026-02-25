---
tags: [blockchain/defi, blockchain/security, index]
created: 2026-02-23
updated: 2026-02-23
---

# Damn Vulnerable DeFi 漏洞知识库

> 共 18 个关卡，按漏洞类型分为 6 大类别。核心记忆原则：**每类漏洞都有一个根因，根因决定利用路径。**

---

## 快速索引表

| 关卡 | 漏洞类别 | 核心关键词 | 难度 |
|------|----------|-----------|------|
| [[unstoppable]] | 闪电贷滥用 | 不变量破坏 | ⭐ |
| [[naive-receiver]] | 闪电贷滥用 | 无权限调用 + 元交易伪造 | ⭐⭐ |
| [[side-entrance]] | 闪电贷滥用 | 余额 vs 记账分离 | ⭐ |
| [[truster]] | 闪电贷滥用 | 任意调用 approve | ⭐⭐ |
| [[puppet]] | 预言机操纵 | V1 现货价单池操控 | ⭐⭐ |
| [[puppet-v2]] | 预言机操纵 | V2 现货价单池操控 | ⭐⭐ |
| [[puppet-v3]] | 预言机操纵 | V3 TWAP 短窗口扭曲 | ⭐⭐⭐ |
| [[compromised]] | 预言机操纵 | 私钥泄露 → 报价篡改 | ⭐⭐ |
| [[curvy-puppet]] | 重入攻击 | Read-only Reentrancy | ⭐⭐⭐⭐ |
| [[free-rider]] | 业务逻辑 | 支付对象错误 + 批量校验缺失 | ⭐⭐ |
| [[selfie]] | 治理攻击 | 闪电贷借票 → 提案 | ⭐⭐ |
| [[climber]] | 治理攻击 | 先执行后检查 → Timelock 自杀 | ⭐⭐⭐ |
| [[backdoor]] | 初始化漏洞 | Safe setup delegatecall | ⭐⭐⭐ |
| [[wallet-mining]] | 初始化漏洞 | 可升级合约 init 可重入 + Create2 挖矿 | ⭐⭐⭐⭐ |
| [[abi-smuggling]] | 编码绕过 | calldata 固定偏移检查绕过 | ⭐⭐⭐ |
| [[shards]] | 业务逻辑 | 精度舍入 + 退款计算错误 | ⭐⭐⭐ |
| [[the-rewarder]] | 业务逻辑 | Bitmap 记录时机滞后 | ⭐⭐⭐ |
| [[withdrawal]] | 跨链桥 | Operator 跳过 Merkle 验证 | ⭐⭐⭐ |

---

## 分类一：闪电贷滥用 Flash Loan Abuse

> **记忆口诀**：闪贷给力量，别让它乱晃——权限、余额、调用三道关卡缺一不可。

### 共同根因

闪电贷天然赋予调用者**巨大的临时资产控制权**，若合约没有严格限制其**触发者、归还校验方式、借款期间行为**，就会被滥用。

---

### [[unstoppable]] — 不变量破坏型

**一句话**：直接给金库转一笔代币，打破 `shares == assets` 的严格相等校验，让闪电贷永远 revert。

```
attack: token.transfer(vault, 1)
result: convertToShares(totalSupply) != totalAssets() → 永久 DoS
```

**记忆点**：`ERC4626` 用 `totalAssets()` 读余额，任何人直接 transfer 都能破坏不变量。

---

### [[naive-receiver]] — 无权限触发 + 元交易伪造

**两个漏洞叠加：**

1. `flashLoan()` 没有 `receiver == msg.sender` 检查 → 任何人可以向任意地址发起贷款，强收手续费耗尽目标资产
2. `_msgSender()` 从 calldata 末尾 20 字节读取发送者 → 通过 Multicall + Forwarder 伪造身份提款

**记忆点**：**谁能触发 receiver？谁的 calldata 末尾说了算？**

---

### [[side-entrance]] — 余额 vs 内部记账分离

**一句话**：在闪电贷的 `execute()` 回调里调用 `deposit()`，用借来的钱存款，归还时余额不变但记账里有了余额，最后提走。

```
flashLoan(1000 ETH) → execute() → deposit(1000 ETH) ← 余额不变，还清了！
withdraw(1000 ETH) → 真实提走
```

**记忆点**：余额检查 ≠ 资产所有权检查，二者必须一致。

---

### [[truster]] — 任意调用注入

**一句话**：闪电贷过程中以 pool 身份执行任意 `target.call(data)`，攻击者传入 `token.approve(attacker, MAX)` 的 calldata，之后直接 `transferFrom` 掏空。

```
flashLoan(0, attacker, token, approve(attacker, MAX)) → transferFrom 掏空
```

**记忆点**：**借款期间禁止执行外部调用**，或严格限制可调用的 target/selector。

---

## 分类二：预言机操纵 Oracle Manipulation

> **记忆口诀**：单源报价必有危，现货更是一推低。TWAP 要够长，多源才安心。

### 共同根因

借贷协议用**可被操纵的价格**来计算抵押要求，攻击者先压价再借款，用极少抵押借走大量资产。

---

### [[puppet]] / [[puppet-v2]] — Uniswap 现货价操控

**渐进关系**：

| | puppet | puppet-v2 |
|--|--|--|
| AMM | Uniswap V1 | Uniswap V2 |
| 抵押 | ETH | WETH |
| 系数 | 2x | 3x |
| **本质** | **现货价 = 可即时操控** | **同上** |

**攻击路径**：
```
大量卖出 DVT → pool 中 DVT↑ ETH↓ → ETH/DVT 价格崩溃
→ calculateDepositRequired 大幅下降 → 用少量 ETH 借空池子
```

**记忆点**：**单池现货 = 可被同笔交易操纵**，2x/3x 系数治标不治本。

---

### [[puppet-v3]] — Uniswap V3 TWAP 短窗口扭曲

**改进**：用 10 分钟 TWAP 代替现货，但：
- 仍是单一 V3 池，无外部锚定
- 通道流动性浅 → 大额 swap 可把 tick 推到极端
- 攻击须在 TWAP 窗口出现足够大的偏移

**记忆点**：TWAP 抗操纵，但**窗口越短、流动性越浅，仍可攻击**。

---

### [[compromised]] — 私钥泄露 → 报价伪造

**一句话**：HTTP 响应里泄露了两个预言机报价者的私钥（hex → base64 → 私钥），用泄露私钥把 NFT 价格压到 0 后买入，再拉高到 Exchange 全部余额后卖出。

**攻击路径**：
```
泄露私钥 → postPrice(0) × 2 → 以 0 买入 NFT → postPrice(999ETH) × 2 → 卖出套现
```

**记忆点**：**预言机的安全性 = 私钥管理的安全性**，链上验证再严格，私钥泄露即归零。

---

## 分类三：重入攻击 Reentrancy

> **记忆口诀**：重入不只写，读也能出妖——View 函数在状态混沌时同样不可信。

---

### [[curvy-puppet]] — Read-only Reentrancy

**这是最精妙的重入变体：**

目标合约 `CurvyPuppetLending` 有 `nonReentrant`，但：
1. 清算健康度检查调用 `curvePool.get_virtual_price()`
2. Curve 在 `remove_liquidity` 过程中向回调合约转 ETH
3. 在 ETH 转账的 `receive()` 回调里，重入 `liquidate()`
4. 此时 Curve 状态未完整，`get_virtual_price()` 返回异常高值
5. 借款价值被高估 → 健康仓位被清算

```
remove_liquidity → ETH callback → liquidate() → get_virtual_price() [读到异常] → 触发清算
```

**记忆点**：**外部协议的 view 函数在执行中间态时不可信**，read-only reentrancy 绕过了所有写保护。

---

## 分类四：治理攻击 Governance Attack

> **记忆口诀**：治理要看快照，快照要看时机——闪贷那一刻的票，能撬动一切。

---

### [[selfie]] — 闪电贷借票提案

**一句话**：在闪电贷借出 DVT 期间（持有超过 50% 投票权），立即调用 `queueAction(emergencyExit)`，2 天后执行提案，掏空池子。

```
flashLoan(超过50%DVT) → delegate(self) → queueAction(emergencyExit) → 还款
→ 2天后 → executeAction() → pool 资金归 recovery
```

**记忆点**：**投票权快照必须在闪贷还款后，不能用借来的票做决定**。

---

### [[climber]] — Timelock 先执行后检查

**一句话**：`execute()` 先执行所有 calls，再检查操作是否 ready。攻击者在 calls 里把延迟改成 0、给自己加 proposer 权限、然后把当前操作 schedule——让最终检查通过。

```
execute([
  setDelay(0),           // 把延迟改成0
  grantRole(PROPOSER, attacker),  // 自己变提案人
  attackerContract.schedule()     // 在这里把当前操作加入队列
]) → 检查 → 发现已 ready → 通过！
→ 升级实现合约 → 掏空金库
```

**记忆点**：**"先执行后验证"是致命的——它让合约在执行过程中自我修改，绕过了所有预置条件**。

---

## 分类五：初始化 & 访问控制漏洞

> **记忆口诀**：初始化只能一次，权限检查不能有洞——Setup 里的每个参数都是攻击面。

---

### [[backdoor]] — Safe Setup delegatecall 滥用

**一句话**：`WalletRegistry` 只检查 Safe 的表面配置（threshold、owners、fallbackManager），没有限制 `setup(to, data)` 里的 delegatecall 目标，攻击者在初始化时悄悄 `approve` 自己，registry 发奖励后立刻 `transferFrom` 全部转走。

```
createProxyWithCallback(
  setup(to=攻击者helper, data=approveToken(attacker))  // 初始化时做delegatecall
) → registry 发 10 DVT → transferFrom 提走
```

**记忆点**：**验证结果，不只验证配置**。Safe.setup 的 delegatecall 是扩展点，也是攻击面。

---

### [[wallet-mining]] — 可升级合约 init 可重调用

**两个漏洞组合：**

1. `AuthorizerUpgradeable.init()` 没有锁，任何人可以重新初始化，把自己设置为 ward
2. Create2 地址可预测，爆破 `saltNonce` 找到能部署到 `USER_DEPOSIT_ADDRESS` 的值

```
调用 init([attacker], [USER_DEPOSIT_ADDRESS]) → 成为 ward
→ drop(saltNonce) 把 Safe 部署到该地址 → 里面的 DVT 通过 Safe 转走
```

**记忆点**：**可升级合约的 `initialize()` 必须有 `initializer` 修饰符防止重入**，Create2 地址对任何人都是透明的。

---

## 分类六：业务逻辑 & 编码绕过

> **记忆口诀**：数字精度失一位，逻辑顺序错一步，编码假设差一格——每一个都是致命的。

---

### [[free-rider]] — 支付逻辑双重错误

**两个 bug 叠加，效果相乘：**

1. **批量校验错误**：`buyMany` 用同一个 `msg.value` 分别检查每个 NFT，实际上只需付单个 NFT 的价格就能买 N 个
2. **付款对象错误**：先 `safeTransferFrom` 转 NFT，再 `ownerOf` 取收款方 → owner 已变成买家，钱打给了自己

```
buyMany([0,1,2,3,4,5]) { value: 15 ETH } → 买了6个NFT，还把15 ETH收回来了
```

**记忆点**：**转移所有权之前必须完成所有付款操作**，批量操作必须累加总价。

---

### [[shards]] — 精度舍入 + 退款公式错误

**两个精度相关 bug：**

1. `fill()` 用 `mulDivDown` 向下取整 → 购买微小份额时 `priceToPay = 0`，免费获得份额
2. `cancel()` 退款公式使用 `purchase.rate`（×1e6 单位）而非 `offer.price/totalShards`，计算出错

**记忆点**：**精度处理应始终向协议有利方向取整**，退款公式必须和购买公式互为逆运算。

---

### [[the-rewarder]] — Bitmap 记录时机滞后

**一句话**：`claimRewards` 先合并统计再一次性写入 bitmap，同一 batch 的重复 claim 在写入前 amount 一直累加，可以重复领取。

```
输入: [claim(batch0, 100), claim(batch0, 100)]
同 token 时，bit 不变但 amount 累加 → 最后写一次 bitmap → 实付 200 而非 100
```

**记忆点**：**每次 claim 必须立即标记已领取**，"批量优化"不能牺牲逐条验证。

---

### [[abi-smuggling]] — calldata 固定偏移检查绕过

**一句话**：合约从固定字节偏移 `0x64` 读取 `actionSelector` 来拦截 `withdraw`，但 ABI 编码允许动态类型的 offset 字段自由填写，攻击者通过填入非标准 offset，把 `withdraw` selector 推到 `0x64` 之后读不到的位置。

```
标准: offset=0x40 → actionData 从 0x64 开始 → selector 在 0x64 被检测
攻击: offset=0x80 → actionData 从 0xa4 开始 → 0x64 处放无害 selector → 通过！
```

**记忆点**：**不要用固定偏移解析 calldata**，动态类型必须跟随 offset 字段读取，或使用 ABI 解码器。

---

### [[withdrawal]] — Operator 跳过 Merkle 验证

**一句话**：跨链桥 L1Gateway 的 `finalizeWithdrawal` 对 `OPERATOR_ROLE` 跳过 Merkle proof 验证，允许 operator 构造任意提款消息（包括把桥里的 DVT 转走）。

```
isOperator = true → 跳过 if (!isOperator) { MerkleProof.verify(...) }
→ 直接执行任意 call → 转走 TokenBridge 的全部 DVT
```

**记忆点**：**特权角色也不应绕过内容验证**——operator 的权限是"无需 proof"，不应扩展为"无需任何验证"。

---

## 漏洞模式速记卡

### 📌 看到这些，立刻联想

| 特征 | 潜在漏洞 |
|------|---------|
| 闪电贷 + 治理投票 | 借票提案（Selfie） |
| 先执行后检查 | Timelock 自毁（Climber）  |
| AMM 现货价作 Oracle | 价格操纵（Puppet 系列） |
| View 函数 + receive() 回调 | Read-only Reentrancy（Curvy Puppet） |
| `initialize()` 无保护 | 重初始化（Wallet Mining） |
| Safe.setup `to/data` 未限制 | delegatecall 后门（Backdoor） |
| 固定 offset 读 calldata | ABI Smuggling |
| `mulDivDown` + 微量购买 | 精度归零（Shards） |
| bitmap 批量更新 | 重复领取（The Rewarder） |
| 付款在转移后 | 付款逻辑反转（Free Rider） |
| 余额检查代替记账检查 | 存款混淆还款（Side Entrance） |
| flashLoan 调 target.call | 任意授权注入（Truster） |

---

## 推荐学习顺序

```
入门 (⭐)     → unstoppable → side-entrance
基础 (⭐⭐)   → naive-receiver → truster → puppet → puppet-v2 → compromised → free-rider → selfie
进阶 (⭐⭐⭐) → puppet-v3 → climber → backdoor → abi-smuggling → shards → the-rewarder → withdrawal
专家 (⭐⭐⭐⭐) → curvy-puppet → wallet-mining
```
