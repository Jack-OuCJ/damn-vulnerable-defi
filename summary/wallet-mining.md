# Wallet Mining 漏洞分析

## 1. 合约功能概述

本关围绕“把一个 Safe 钱包部署到指定地址，并把该地址里的 DVT 转走”展开。

系统主要组件：

- **`WalletDeployer`**：负责部署 Safe Proxy（Create2），并向 `ward` 支付一笔 DVT 作为报酬
- **`AuthorizerUpgradeable`（带透明代理）**：用于限制谁能调用 `WalletDeployer.drop()` 在哪些地址部署
- **Safe 体系**：`Safe`（singleton copy）、`SafeProxyFactory`、`SafeProxy`
- **CreateX / SafeSingletonFactory**：用预签名交易部署到固定地址，便于复现实验环境

挑战目标（从测试断言可见）：

1. 在 `USER_DEPOSIT_ADDRESS` 生成代码（Safe Proxy 被部署到该地址）
2. `USER_DEPOSIT_ADDRESS` 与 `WalletDeployer` 不能留有 DVT
3. `user` 的 nonce 必须仍为 0（用户不能发交易）
4. `player` 只能执行 1 笔交易
5. 20,000,000 DVT 必须转到 `user`
6. `ward` 必须收到 `WalletDeployer.pay()` 的报酬

## 2. 漏洞根因

### 2.1 `AuthorizerUpgradeable.init()` 可被任意人重初始化

本关的授权本意是：只有 `ward` 被允许在 `USER_DEPOSIT_ADDRESS` 部署。

但 `AuthorizerUpgradeable` 作为可升级合约，其初始化函数 `init(wards, aims)` 没有被正确地“一次性锁死”，导致攻击者可以在任意时刻调用 `init()`：

- 把自己设为 ward
- 把目标 aim 设为 `walletDeployer` 允许的部署地址（这里就是 `USER_DEPOSIT_ADDRESS`）

从而绕过“只有 ward 才能部署”的限制。

### 2.2 地址挖矿：用 Create2 saltNonce 把 Safe Proxy 部署到指定地址

`WalletDeployer.drop(copy, initializer, saltNonce)` 通过 `SafeProxyFactory.createProxyWithNonce` 使用 Create2 部署代理。

Create2 地址由以下要素决定：

- `deployer = proxyFactory`
- `salt = keccak256(keccak256(initializer), saltNonce)`（Safe 工厂的常见做法）
- `initCodeHash = keccak256(SafeProxy.creationCode + singletonCopy)`

所以只要爆破（或计算）出合适的 `saltNonce`，就能让部署地址恰好等于 `USER_DEPOSIT_ADDRESS`。

## 3. 利用流程（对应本仓库 PoC）

PoC 位于 `test/wallet-mining/WalletMining.t.sol`。

### 3.1 计算正确的 `saltNonce`

测试里直接用 Foundry 内置 `vm.computeCreate2Address` 循环找 nonce：

1) 构造 Safe initializer（`Safe.setup`），把唯一 owner 设为 `user`
2) 从 nonce=0 开始，计算预测地址
3) 命中 `USER_DEPOSIT_ADDRESS` 时停止

这样无需链上试错，纯本地计算即可得到正确 nonce。

### 3.2 构造一笔由 `user` 签名的 Safe 交易（但不让 user 发链上交易）

Safe 的第一笔交易 nonce=0。

PoC 计算 EIP-712 hash 并用 `userPrivateKey` 签名，生成 `signatures`，最终拼出：

- `execTransaction(to=token, data=token.transfer(user, DEPOSIT_TOKEN_AMOUNT), signatures=userSig)`

注意：

- 签名发生在测试里（off-chain），不消耗 `user` nonce
- 链上执行由 Safe 合约完成，`user` 仍保持 `vm.getNonce(user) == 0`

### 3.3 单笔交易完成全部动作（player nonce 仍为 1）

PoC 使用一个 `Exploit` 合约把全部步骤塞进 constructor，使得 `player` 只需部署一次合约：

1) 调用 `authorizer.init()` 重置授权：允许 exploit 在 `USER_DEPOSIT_ADDRESS` 部署
2) 调用 `walletDeployer.drop(...)`：把 Safe Proxy 部署到 `USER_DEPOSIT_ADDRESS`
3) 将 `WalletDeployer` 预先持有的 DVT 报酬 `transfer` 给 `ward`
4) 用 `safe.call(txData)` 调 `execTransaction`：把 `USER_DEPOSIT_ADDRESS` 上的 20,000,000 DVT 转给 `user`

这样满足“player 一笔交易完成”的限制。

## 4. 知识点总结

1. **可升级合约初始化一定要防重入/防二次初始化**：`init()` 若可被任意人再次调用，授权/角色等安全边界会被直接改写。
2. **Create2 地址可预测性**：当目标地址固定（deposit address）时，salt 的搜索空间可能成为攻击面（地址挖矿）。
3. **Safe 的签名与执行分离**：用户不需要链上交易，也能通过签名授权 Safe 执行（满足“user nonce 仍为 0”这类约束）。
4. **把多步攻击压缩成 1 tx**：constructor / 单次外部调用常用来满足 CTF 的“交易数限制”。
