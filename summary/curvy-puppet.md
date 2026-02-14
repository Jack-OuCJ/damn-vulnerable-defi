# Curvy Puppet 漏洞分析

## 1. 合约功能概述

本关实现一个借贷合约 `CurvyPuppetLending`：

- **抵押品**：DVT
- **借出资产**：Curve stETH/ETH 池的 LP token（`curvePool.lp_token()`）
- **清算规则**：当债务价值超过抵押价值时，任何人可通过偿还债务拿走全部抵押品
- **授权管理**：集成 Permit2，借款人/清算人通过 Permit2 让 `CurvyPuppetLending` 拉取代币

关键估值：

- 抵押价值：`collateralAmount * oraclePrice(DVT)`
- 借款价值：`borrowAmount * lpTokenPrice`
- **lpTokenPrice = oraclePrice(ETH) * curvePool.get_virtual_price()`**

也就是说，借款资产价格完全依赖 Curve 池的 `get_virtual_price()`。

## 2. 漏洞根因（Read-only Reentrancy）

### 2.1 关键代码路径

`CurvyPuppetLending` 在清算时会做健康度检查：

```solidity
uint256 collateralValue = getCollateralValue(collateralAmount) * 100;
uint256 borrowValue = getBorrowValue(borrowAmount) * 175;
if (collateralValue >= borrowValue) revert HealthyPosition(...);
```

其中 `getBorrowValue()` 会调用：

```solidity
oracle.getPrice(ETH).value.mulWadDown(curvePool.get_virtual_price())
```

问题在于：Curve 池在执行 `remove_liquidity`/`remove_liquidity_one_coin` 等复杂流程时，会经历“内部状态未完全一致”的短窗口。

- 在该窗口里调用 `get_virtual_price()`，可能读到**异常偏高**的虚拟价格。
- 这不需要你真正“用小资金操纵主网价格”，而是利用了**读状态不一致**导致的短暂错误定价。

### 2.2 为什么叫“只读重入”

这里的“重入”不是为了在 `CurvyPuppetLending` 内做多次写入（它有 `nonReentrant`），而是：

- 在 Curve 合约向你合约转 ETH 的回调（`receive()`）中，
- **重入调用** `CurvyPuppetLending.liquidate()`，
- 让 `liquidate()` 内部再次读取 Curve 的 `get_virtual_price()`，
- 读到“移除流动性过程中”的异常值，从而把 `borrowValue` 抬高到足以触发清算。

这就是典型 read-only reentrancy：目标合约自身的写保护没问题，但它依赖的外部协议在某些执行阶段对 view 的返回值不稳定。

## 3. 为什么需要双 Flashloan

本关限制：Treasury 只给 **200 WETH** 与约 **6.5 LP**。

要触发 Curve 的只读重入窗口并让虚拟价格变化“够大”，通常需要：

1) 先向 Curve 池 **add_liquidity** 一笔很大的头寸
2) 紧接着 **remove_liquidity**，在池子给你转 ETH 的瞬间重入清算

但你还必须同时满足两个现实约束：

- 清算要偿还每个用户的 LP 借款（本题是 3 个用户各 1 LP），你需要持有/能被 Permit2 拉取 LP。
- add/remove + 还 flashloan 时存在费用/滑点/溢价（尤其 Aave premium），小资金很容易“差一点点”导致回滚。

因此采用：

- **Aave V2 flashloan**：借 `stETH + WETH` 作为主资金
- **Balancer Vault flashloan（0 fee）**：额外借一笔 `WETH`，专门承担 Curve 操作时的资金缓冲

这样做的目的不是“赚”，而是把资金曲线拉平：保证足额支付 add/remove + 回补 Aave premium。

## 4. 利用流程（对应本仓库 PoC）

PoC 实现在 `test/curvy-puppet/CurvyPuppet.t.sol` 的 `CurvyPuppetExploit`。

### 4.1 准备

1. 从 Treasury 通过 `transferFrom` 把 **6.5 LP + 200 WETH** 转进 exploit 合约
2. 给 Permit2 做授权，使 `CurvyPuppetLending` 能在清算时从 exploit 合约拉 LP：

```solidity
curveLpToken.approve(permit2, type(uint256).max);
permit2.approve(token=LP, spender=lending, amount=max, expiration=now+1d);
```

### 4.2 Aave flashloan（外层）

向 Aave 借：

- `172,000 stETH`
- `20,500 WETH`

进入 Aave 回调 `executeOperation()` 后：

1) 再向 Balancer flashloan 借 `37,991 WETH`（0 fee）
2) Balancer 回调里做 Curve 操作并触发清算
3) 返回 Aave 回调后，补齐 `stETH/WETH` 以覆盖 `amount + premium` 并 `approve` Aave 拉取还款

### 4.3 Balancer 回调：Curve add/remove 并触发只读重入

在 `receiveFlashLoan()` 内：

1) 把 `58,685 WETH` unwrap 成 ETH
2) 调 `curvePool.add_liquidity{value:...}([ETH, stETH], 0)` 增加巨额流动性
3) 立刻 `curvePool.remove_liquidity(lpBalance - tinyLeftover, [0,0])`
4) Curve 在 remove 过程中会向 exploit 合约发送 ETH，触发 `receive()`

在 `receive()` 里（仅当 `msg.sender == curvePool` 且只执行一次）：

```solidity
for users:
    lending.liquidate(user)
```

此时 `lending` 读取到异常的 `get_virtual_price()`，使 3 个“过度抵押”的用户头寸瞬间变成可清算。

### 4.4 回补 Aave premium 的关键点：避免“差一点”

在 Aave 回调中必须覆盖 `amount + premium`：

- **stETH**：通过 `curvePool.get_dy(0,1,dx)` 做二分搜索，找到“刚够买到 deficit stETH”的最小 `dx`，再执行 `exchange{value:dx}(0,1,dx,1)`。
- **WETH**：如果 ETH 不够 wrap，就先用少量 `exchange(1,0,...)` 卖一点 stETH 换回 ETH，再 wrap。

这样能避免因为“多换了几十/上百 ETH”导致另一边还款资金不足。

### 4.5 资产归集与过关条件

清算后 exploit 合约会拿到所有抵押的 DVT（3 * 2500 DVT），并在结尾：

- 把 **7500 DVT** 全部转回 Treasury
- 把剩余 LP / stETH / WETH / ETH 都转回 Treasury
- 额外确保 Treasury 的 WETH **> 0**（测试要求），如果刚好归零则 wrap 1 wei WETH 再转回

最终满足：

- 所有用户仓位清空
- Treasury 仍有 LP
- Treasury 仍有 7500 DVT
- Player 的 DVT/stETH/WETH/LP 都为 0

## 5. 知识点总结

1. **read-only reentrancy**：目标不一定需要可重入写入；只要其依赖的外部协议在某些执行阶段返回不稳定的 view 值，就可能被利用。
2. **不要把外部 AMM/Pool 的瞬时 view 当作“强预言机”**：特别是像 `get_virtual_price()` 这种依赖当前储备/总供给的派生指标。
3. **资金曲线与可执行性**：即使漏洞成立，也可能因为 premium/滑点导致“现实不可执行”；多路 flashloan（尤其 0 fee 的 Balancer）能把策略从理论变成可落地。
