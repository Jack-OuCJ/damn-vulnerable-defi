# Climber 漏洞分析

## 1. 合约功能概述

`ClimberVault` 是一个 UUPS 可升级金库，初始持有 10,000,000 DVT。Vault 的 `owner` 不是普通 EOA，而是一个 `ClimberTimelock`。

**核心组件：**
- **ClimberVault.sol**: UUPS Vault，只有 owner（Timelock）能 `withdraw`、授权升级
- **ClimberTimelock.sol**: Timelock，只有 `PROPOSER_ROLE` 能 `schedule`，任何人可 `execute`
- **Climber.t.sol**: 关卡测试，要求把 Vault 里全部 DVT 转入 `recovery`

**业务流程（预期）：**
1. Proposer 调 `schedule(targets, values, data, salt)`，登记一个 operationId，并设置 `readyAt = now + delay`
2. 延迟到期后，任何人可 `execute(...)` 执行这些操作
3. Timelock 作为 Vault owner，可升级或提款

---

## 2. 漏洞位置

### 漏洞代码（ClimberTimelock.sol）

```solidity
function execute(address[] calldata targets, uint256[] calldata values, bytes[] calldata dataElements, bytes32 salt)
    external
    payable
{
    bytes32 id = getOperationId(targets, values, dataElements, salt);

    // ⚠️ 先执行所有 calls
    for (uint8 i = 0; i < targets.length; ++i) {
        targets[i].functionCallWithValue(dataElements[i], values[i]);
    }

    // ⚠️ 再检查是否 ready（顺序反了）
    if (getOperationState(id) != OperationState.ReadyForExecution) {
        revert NotReadyForExecution(id);
    }

    operations[id].executed = true;
}
```

### 漏洞本质

Timelock 的安全不变量应该是：

> “只有已 schedule 且到期的操作才能执行”

但这里的实现是：

> “先执行，再看最后是不是已经变成 ready”

这给了攻击者一个窗口：**在执行过程中动态修改 timelock 的状态（例如把 delay 改成 0、授予 proposer 权限、立刻 schedule 当前操作）**，让最终检查通过。

---

## 3. 漏洞原理分析

### 3.1 关键能力：Timelock 自管理 + AccessControl

`ClimberTimelock` 继承 `AccessControl`，而且在构造函数里给了自己 `ADMIN_ROLE`：

- `ADMIN_ROLE` 的 admin 也是 `ADMIN_ROLE`
- Timelock 给 `address(this)` 授予了 `ADMIN_ROLE`

因此，只要能让 Timelock “以自己的身份发起调用”（在 `execute` 循环里 target 指向 timelock），就能调用：

- `grantRole(PROPOSER_ROLE, attacker)`
- `updateDelay(0)`（该函数也要求 `msg.sender == address(this)`）

### 3.2 完整攻击链条

1. 在 `execute` 批次的第 1 步：`timelock.updateDelay(0)` 把 delay 变为 0
2. 第 2 步：`timelock.grantRole(PROPOSER_ROLE, scheduler)` 给 scheduler proposer 权限
3. 第 3 步：作为 Vault owner，调用 `vault.upgradeToAndCall(newImpl, drainData)`
   - 将实现升级为恶意实现
   - 立即通过 `upgradeToAndCall` 在同一笔中执行 `drain` 把 DVT 转走
4. 第 4 步：调用 `scheduler.schedule()`，用 delay=0 立刻把“本次 execute 的 operationId”登记为 ready
5. 循环结束后，`execute` 末尾检查通过（operation 已 ready）

### 3.3 为什么需要 scheduler（实现细节）

如果把 `schedule(targets,values,data,salt)` 直接作为 `dataElements` 的一部分，会出现“自引用编码”的坑：

- `dataElements[最后一项]` 里面又要包含 `dataElements` 本身
- 很容易导致 schedule 记录的 operationId 与 execute 最终检查的 operationId 不一致

因此用一个独立合约 `scheduler` 存储整套参数，并提供无参数 `schedule()`，让 bytes 固定、避免自引用。

---

## 4. 修复方案

### 方案一：先检查再执行（推荐）

把 `execute` 改为：

1) 计算 `id`
2) 检查 `id` 已 ready
3) 执行 calls
4) 标记 executed

### 方案二：禁止在 execute 中修改关键参数

- `updateDelay` 不允许在同一 operation 中与其他敏感动作组合
- 或引入额外的“变更延迟”冷却期

### 方案三：限制可调用目标

对 `targets` 做白名单，至少禁止在 timelock 执行中调用 `grantRole/updateDelay` 等自管理函数。

---

## 5. Proof of Concept（关键代码）

```solidity
// 1) updateDelay(0)
targets[0] = address(timelock);
data[0] = abi.encodeCall(ClimberTimelock.updateDelay, (uint64(0)));

// 2) grant proposer role
targets[1] = address(timelock);
data[1] = abi.encodeWithSignature("grantRole(bytes32,address)", PROPOSER_ROLE, address(scheduler));

// 3) UUPS upgrade + drain
targets[2] = address(vault);
data[2] = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(newImpl), drainCall);

// 4) schedule same operation id
targets[3] = address(scheduler);
data[3] = abi.encodeCall(ClimberScheduler.schedule, ());
```

---

## 6. 总结

`Climber` 的根因不是 UUPS 本身，而是 Timelock 的 **执行顺序错误（先执行后校验）**。

当 timelock 既是 Vault owner 又能自管理权限/延迟时，这种顺序 bug 会被放大：攻击者可以在一次 `execute` 内临时变更 delay 与角色，从而绕过“必须等待 1 小时”的设计。
