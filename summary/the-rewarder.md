# The Rewarder 漏洞分析

## 1. 合约功能概述

`TheRewarderDistributor` 是一个基于 Merkle Tree 的代币分发器，支持同一笔交易批量领取多个 token 的奖励。

**核心组件：**
- **TheRewarderDistributor.sol**: 管理分发批次、Merkle Root、领取位图（bitmap）与转账
- **dvt-distribution.json / weth-distribution.json**: 两类 token 的受益人和金额快照
- **TheRewarder.t.sol**: 初始化分发与验证攻击目标（尽可能清空分发器并转入 recovery）

**业务流程：**
1. 运营方调用 `createDistribution()` 为某 token 创建一个分发批次（batch）
2. 用户提交 `Claim[]`（包含 batch、amount、proof、tokenIndex）调用 `claimRewards()`
3. 合约验证 Merkle proof，通过后转账 token
4. 通过 bitmap 记录“该地址在该 batch 是否已领取”

---

## 2. 漏洞位置

### 漏洞代码（TheRewarderDistributor.sol）

```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    // 当前正在处理的 claim
    Claim memory inputClaim;
    // 当前聚合的 token（用于把同 token 的多个 claim 合并结算）
    IERC20 token;
    // 聚合后的 bitmask（同一个 word 内所有已出现的 batch bit）
    uint256 bitsSet;
    // 聚合后的总领取数量（会把同 token 的 claim.amount 一直累加）
    uint256 amount;

    for (uint256 i = 0; i < inputClaims.length; i++) {
        inputClaim = inputClaims[i];

        // bitmap 定位：每 256 个 batch 共用一个 word
        uint256 wordPosition = inputClaim.batchNumber / 256;
        uint256 bitPosition = inputClaim.batchNumber % 256;

        // token 发生变化：先把上一组 token 的聚合结果统一落账
        if (token != inputTokens[inputClaim.tokenIndex]) {
            if (address(token) != address(0)) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            // 初始化新 token 的聚合上下文
            token = inputTokens[inputClaim.tokenIndex];
            bitsSet = 1 << bitPosition;
            amount = inputClaim.amount;
        } else {
            // 同 token 下继续聚合：bit 做 OR，amount 持续累加
            // ⚠️ 问题点：重复 claim 同一 batch 时，bit 不会增加，但 amount 会继续增加
            bitsSet = bitsSet | 1 << bitPosition;
            amount += inputClaim.amount;
        }

        // 最后一条 claim 时，再统一写入一次 claimed 状态
        // ⚠️ 问题点：写入太晚，前面已发生多次 transfer
        if (i == inputClaims.length - 1) {
            if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
        }

        // 校验 leaf = keccak256(msg.sender, amount)
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
        bytes32 root = distributions[token].roots[inputClaim.batchNumber];

        if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

        // 每次循环都会真实转账一次
        // ⚠️ 因此同一条合法 claim 重复 N 次，会转账 N 次
        inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
    }
}
```

### 漏洞本质

`claimRewards()` 只在 token 切换或循环结束时调用一次 `_setClaimed()`，并用 `bitsSet` 合并 batch bit；
但 `amount` 会对每一条 claim 做累加。若在同一 token、同一 batch 重复提交同一个合法 claim：

- `bitsSet` 仍只有一个 bit（不会反映重复次数）
- `amount` 却不断增加
- 循环内每次都会执行一次真实 `transfer`

结果：**同一 batch 可在同一交易被重复领取多次，但最终仅标记为“已领取一次”**。

---

## 3. 漏洞原理分析

### 3.1 期望行为 vs 实际行为

**期望行为：**
```
同一地址 + 同一 token + 同一 batch
=> 最多领取一次
```

**实际行为：**
```
同一交易中重复放入同一条 claim N 次
=> proof 每次都通过
=> transfer 执行 N 次
=> 末尾仅做一次 bitmap 检查与置位
```

### 3.2 为什么 `AlreadyClaimed` 没拦住

`_setClaimed()` 检查的是链上已有位图：

```solidity
uint256 currentWord = distributions[token].claims[msg.sender][wordPosition];
if ((currentWord & newBits) != 0) return false;
```

在同一笔交易前半段，位图尚未写入（延迟到 token 切换或末尾），所以重复 claim 不会触发冲突；
等到末尾统一写入时，资金已经多次转出。

### 3.3 本关的可利用性（结合测试数据）

从测试数据中可得：

- `player` 地址：`0x44E97aF4418b7a17AABD8090bEA0A471a366305C`
- `player` 在 DVT 分发中的合法额度：`11,524,763,827,831,882 wei`
- `player` 在 WETH 分发中的合法额度：`1,171,088,749,244,340 wei`

Alice 已领取后，分发器剩余：

- DVT: `9,997,497,975,612,005,191 wei`
- WETH: `999,771,617,011,871,775 wei`

若重复使用 player 自己的有效 claim：

- DVT 最多可重复领取 `867` 次，剩余 dust `5,527,736,881,763,497 wei`
- WETH 最多可重复领取 `853` 次，剩余 dust `832,913,906,449,755 wei`

与关卡断言一致（只要求剩余小于阈值，而非精确归零）：

- DVT 剩余 `< 1e16`
- WETH 剩余 `< 1e15`

---

## 4. 修复方案

### 方案一：逐条 claim 即时置位（推荐）

每条 claim 在验证 proof 后，立即检查并写入该 batch 对应 bit，再执行转账。

```solidity
function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
    for (uint256 i = 0; i < inputClaims.length; i++) {
        // 1) 读取单条 claim
        Claim memory c = inputClaims[i];
        IERC20 token = inputTokens[c.tokenIndex];

        // 2) 先验证 Merkle proof（不合法直接回滚）
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, c.amount));
        bytes32 root = distributions[token].roots[c.batchNumber];
        if (!MerkleProof.verify(c.proof, root, leaf)) revert InvalidProof();

        // 3) 计算该 batch 对应的 bitmap 位置
        uint256 wordPosition = c.batchNumber / 256;
        uint256 bitPosition = c.batchNumber % 256;
        uint256 mask = 1 << bitPosition;

        // 4) 立即检查是否已领取（防同交易重复）
        uint256 currentWord = distributions[token].claims[msg.sender][wordPosition];
        if ((currentWord & mask) != 0) revert AlreadyClaimed();

        // 5) 立即写状态（Effects）
        distributions[token].claims[msg.sender][wordPosition] = currentWord | mask;
        distributions[token].remaining -= c.amount;

        // 6) 最后再转账（Interactions）
        SafeTransferLib.safeTransfer(address(token), msg.sender, c.amount);
    }
}
```

**为什么有效：**
- 同一笔交易内的第二次重复 claim 会立刻命中 `AlreadyClaimed`
- 检查与状态更新的时序正确（Checks-Effects-Interactions）

### 方案二：保持聚合，但增加“本地去重检查”

若仍要做 gas 优化聚合，需要在内存中维护 `(token, wordPosition)` 的临时 bitset，
在循环中先检测是否已在本交易出现过同一 bit；若重复立即 revert。

**权衡：**
- 可保留批量聚合思路
- 逻辑复杂度更高，容易再引入边界 bug

### 方案三：补强输入约束与安全传输

- 强制 `inputClaims` 按 `(tokenIndex, batchNumber)` 排序并去重
- 使用 `SafeTransferLib.safeTransfer` 替代裸 `transfer`

**说明：**
输入约束只能降低风险，不能替代链上状态级防重校验。

---

## 5. Exploit 思路（PoC 级）

1. 从 JSON 中找到 `player` 的合法记录（索引、amount）
2. 用同一条合法 proof 构造大量重复 claim（DVT 一组、WETH 一组）
3. 调用一次 `claimRewards()`，让合约重复转出奖励
4. 将收到的 DVT/WETH 全部转入 `recovery`

简化伪代码：

```solidity
// claims 中重复放入同一 token + 同一 batch + 同一 proof
claims = [sameValidClaim, sameValidClaim, ..., sameValidClaim];
// 一次调用，循环里会执行多次 transfer
distributor.claimRewards(claims, tokens);

// 将提取到的余额全部转移到 recovery
dvt.transfer(recovery, dvt.balanceOf(player));
weth.transfer(recovery, weth.balanceOf(player));
```

---

## 6. 总结

这是一个典型的**批处理优化引入业务安全回归**案例：

- 优化目标：减少重复写 storage / 支持多 token 一次领取
- 实际后果：状态防重检查被延后，导致同交易内可重复兑现

在涉及“领取、铸造、发放”类逻辑时，**防重校验必须与状态写入强耦合，并在每次资产转移前完成**，
否则非常容易出现“一次授权、多次兑现”的漏洞。
