// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @notice Same staking pool with all accounting settled before any external call.
contract GuardedNftStakingPool {
    IERC721 public immutable collection;
    mapping(uint256 => address) public stakedBy;
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public stakeCount;
    uint256 public rewardPerClaim = 1 ether;
    uint256 private _status = 1;

    modifier nonReentrant() {
        require(_status == 1, "reentrant call");
        _status = 2;
        _;
        _status = 1;
    }

    constructor(address _collection) {
        collection = IERC721(_collection);
    }

    function stake(uint256 tokenId) external {
        collection.transferFrom(msg.sender, address(this), tokenId);
        stakedBy[tokenId] = msg.sender;
        stakeCount[msg.sender] += 1;
        pendingRewards[msg.sender] += rewardPerClaim;
    }

    function claimAndUnstake(uint256 tokenId) external nonReentrant {
        require(stakedBy[tokenId] == msg.sender, "not staker");
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "nothing to claim");

        pendingRewards[msg.sender] = 0;
        stakeCount[msg.sender] -= 1;
        delete stakedBy[tokenId];

        collection.transferFrom(address(this), msg.sender, tokenId);
        IERC721Receiver(msg.sender).onERC721Received(address(this), msg.sender, tokenId, "");

        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "reward transfer failed");
    }

    receive() external payable {}
}
