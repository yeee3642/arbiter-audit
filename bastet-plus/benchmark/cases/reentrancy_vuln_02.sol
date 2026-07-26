// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4);
}

interface IERC721 {
    function transferFrom(address from, address to, uint256 tokenId) external;
}

/// @notice NFT staking pool paying a flat reward per claim.
contract NftStakingPool {
    IERC721 public immutable collection;
    mapping(uint256 => address) public stakedBy;
    mapping(address => uint256) public pendingRewards;
    mapping(address => uint256) public stakeCount;
    uint256 public rewardPerClaim = 1 ether;

    constructor(address _collection) {
        collection = IERC721(_collection);
    }

    function stake(uint256 tokenId) external {
        collection.transferFrom(msg.sender, address(this), tokenId);
        stakedBy[tokenId] = msg.sender;
        stakeCount[msg.sender] += 1;
        pendingRewards[msg.sender] += rewardPerClaim;
    }

    /// @dev Notifies the receiver before clearing the reward accounting.
    function claimAndUnstake(uint256 tokenId) external {
        require(stakedBy[tokenId] == msg.sender, "not staker");
        uint256 reward = pendingRewards[msg.sender];
        require(reward > 0, "nothing to claim");

        collection.transferFrom(address(this), msg.sender, tokenId);
        IERC721Receiver(msg.sender).onERC721Received(address(this), msg.sender, tokenId, "");

        pendingRewards[msg.sender] = 0;
        stakeCount[msg.sender] -= 1;
        delete stakedBy[tokenId];

        (bool ok, ) = msg.sender.call{value: reward}("");
        require(ok, "reward transfer failed");
    }

    receive() external payable {}
}
