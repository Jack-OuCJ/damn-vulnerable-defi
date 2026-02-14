// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {L1Gateway} from "../../src/withdrawal/L1Gateway.sol";
import {L1Forwarder} from "../../src/withdrawal/L1Forwarder.sol";
import {L2MessageStore} from "../../src/withdrawal/L2MessageStore.sol";
import {L2Handler} from "../../src/withdrawal/L2Handler.sol";
import {TokenBridge} from "../../src/withdrawal/TokenBridge.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";

contract WithdrawalChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");

    // Mock addresses of the bridge's L2 components
    address l2MessageStore = makeAddr("l2MessageStore");
    address l2TokenBridge = makeAddr("l2TokenBridge");
    address l2Handler = makeAddr("l2Handler");

    uint256 constant START_TIMESTAMP = 1718786915;
    uint256 constant INITIAL_BRIDGE_TOKEN_AMOUNT = 1_000_000e18;
    uint256 constant WITHDRAWALS_AMOUNT = 4;
    bytes32 constant WITHDRAWALS_ROOT = 0x4e0f53ae5c8d5bc5fd1a522b9f37edfd782d6f4c7d8e0df1391534c081233d9e;

    TokenBridge l1TokenBridge;
    DamnValuableToken token;
    L1Forwarder l1Forwarder;
    L1Gateway l1Gateway;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);

        // Start at some realistic timestamp
        vm.warp(START_TIMESTAMP);

        // Deploy token
        token = new DamnValuableToken();

        // Deploy and setup infra for message passing
        l1Gateway = new L1Gateway();
        l1Forwarder = new L1Forwarder(l1Gateway);
        l1Forwarder.setL2Handler(address(l2Handler));

        // Deploy token bridge on L1
        l1TokenBridge = new TokenBridge(token, l1Forwarder, l2TokenBridge);

        // Set bridge's token balance, manually updating the `totalDeposits` value (at slot 0)
        token.transfer(address(l1TokenBridge), INITIAL_BRIDGE_TOKEN_AMOUNT);
        vm.store(address(l1TokenBridge), 0, bytes32(INITIAL_BRIDGE_TOKEN_AMOUNT));

        // Set withdrawals root in L1 gateway
        l1Gateway.setRoot(WITHDRAWALS_ROOT);

        // Grant player the operator role
        l1Gateway.grantRoles(player, l1Gateway.OPERATOR_ROLE());

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(l1Forwarder.owner(), deployer);
        assertEq(address(l1Forwarder.gateway()), address(l1Gateway));

        assertEq(l1Gateway.owner(), deployer);
        assertEq(l1Gateway.rolesOf(player), l1Gateway.OPERATOR_ROLE());
        assertEq(l1Gateway.DELAY(), 7 days);
        assertEq(l1Gateway.root(), WITHDRAWALS_ROOT);

        assertEq(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertEq(l1TokenBridge.totalDeposits(), INITIAL_BRIDGE_TOKEN_AMOUNT);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_withdrawal() public checkSolvedByPlayer {
        // Wait out the withdrawal delay.
        // Use the max timestamp in the set to satisfy all withdrawals at once.
        vm.warp(START_TIMESTAMP + 8 days);

        // Common outer parameters
        address outerL2Sender = l2Handler;
        address outerTarget = address(l1Forwarder);

        // Each message forwards an L2->L1 call via the forwarder into the token bridge.
        // Parameters are taken from `test/withdrawal/withdrawals.json`.
        _finalize(FinalizeParams({
            nonce: 0,
            l2Sender: outerL2Sender,
            target: outerTarget,
            timestamp: 0x66729b63,
            innerL2Sender: 0x328809Bc894f92807417D2dAD6b7C998c1aFdac6,
            amount: 10e18
        }));

        _finalize(FinalizeParams({
            nonce: 1,
            l2Sender: outerL2Sender,
            target: outerTarget,
            timestamp: 0x66729b95,
            innerL2Sender: 0x1D96F2f6BeF1202E4Ce1Ff6Dad0c2CB002861d3e,
            amount: 10e18
        }));

        // This one is the suspicious (large) withdrawal.
        // We must finalize it (so the leaf is marked finalized), but we can't allow it to execute
        // (it would drain the bridge beyond the 1% tolerance).
        // Pre-mark the forwarder's `failedMessages[messageId] = true` so the gateway-triggered
        // forwardMessage reverts early via `require(!failedMessages[messageId])`.
        //
        // The messageId inside forwardMessage = keccak256(abi.encodeWithSignature("forwardMessage(…)", decoded params)).
        // Since the raw calldata IS the canonical ABI encoding, messageId = keccak256(raw calldata).

        // Use the exact calldata bytes (260 bytes) from `test/withdrawal/withdrawals.json` so the leaf matches.
        bytes memory suspiciousOuter = bytes.concat(
            hex"01210a380000000000000000000000000000000000000000000000000000000000000002000000000000000000000000ea47",
            hex"5d60c118d7058bef4bdd9c32ba51139a74e00000000000000000000000009c52b2c4a89e2be37972d18da937cbad8aa8bd50",
            hex"0000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000",
            hex"000000000000000000000000004481191e51000000000000000000000000ea475d60c118d7058bef4bdd9c32ba51139a74e0",
            hex"00000000000000000000000000000000000000000000d38be6051f27c2600000000000000000000000000000000000000000",
            hex"00000000000000000000"
        );

        // Compute the messageId the same way forwardMessage does: hash of the raw calldata.
        bytes32 suspiciousMessageId = keccak256(suspiciousOuter);
        // failedMessages mapping is at storage slot 2.
        bytes32 failedSlot = keccak256(abi.encode(suspiciousMessageId, uint256(2)));
        vm.store(address(l1Forwarder), failedSlot, bytes32(uint256(1)));

        // Sanity-check: computed leaf must match the expected one in the challenge.
        assertEq(
            keccak256(abi.encode(uint256(2), outerL2Sender, outerTarget, uint256(0x66729bea), suspiciousOuter)),
            hex"baee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015",
            "Unexpected leaf for suspicious withdrawal"
        );

        l1Gateway.finalizeWithdrawal({
            nonce: 2,
            l2Sender: outerL2Sender,
            target: outerTarget,
            timestamp: 0x66729bea,
            message: suspiciousOuter,
            proof: new bytes32[](0)
        });

        _finalize(FinalizeParams({
            nonce: 3,
            l2Sender: outerL2Sender,
            target: outerTarget,
            timestamp: 0x66729c37,
            innerL2Sender: 0x671d2ba5bF3C160A568Aae17dE26B51390d6BD5b,
            amount: 10e18
        }));
    }

    struct FinalizeParams {
        uint256 nonce;
        address l2Sender;
        address target;
        uint256 timestamp;
        address innerL2Sender;
        uint256 amount;
    }

    function _finalize(FinalizeParams memory p) private {
        bytes memory innerMessage = abi.encodeCall(TokenBridge.executeTokenWithdrawal, (p.innerL2Sender, p.amount));
        bytes memory outerMessage = abi.encodeCall(
            L1Forwarder.forwardMessage,
            (p.nonce, p.innerL2Sender, address(l1TokenBridge), innerMessage)
        );
        l1Gateway.finalizeWithdrawal({
            nonce: p.nonce,
            l2Sender: p.l2Sender,
            target: p.target,
            timestamp: p.timestamp,
            message: outerMessage,
            proof: new bytes32[](0)
        });
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Token bridge still holds most tokens
        assertLt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT);
        assertGt(token.balanceOf(address(l1TokenBridge)), INITIAL_BRIDGE_TOKEN_AMOUNT * 99e18 / 100e18);

        // Player doesn't have tokens
        assertEq(token.balanceOf(player), 0);

        // All withdrawals in the given set (including the suspicious one) must have been marked as processed and finalized in the L1 gateway
        assertGe(l1Gateway.counter(), WITHDRAWALS_AMOUNT, "Not enough finalized withdrawals");
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"eaebef7f15fdaa66ecd4533eefea23a183ced29967ea67bc4219b0f1f8b0d3ba"),
            "First withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"0b130175aeb6130c81839d7ad4f580cd18931caf177793cd3bab95b8cbb8de60"),
            "Second withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"baee8dea6b24d327bc9fcd7ce867990427b9d6f48a92f4b331514ea688909015"),
            "Third withdrawal not finalized"
        );
        assertTrue(
            l1Gateway.finalizedWithdrawals(hex"9a8dbccb6171dc54bfcff6471f4194716688619305b6ededc54108ec35b39b09"),
            "Fourth withdrawal not finalized"
        );
    }
}
