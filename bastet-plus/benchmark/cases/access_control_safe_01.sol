// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Same treasury, with a two-step ownership handover.
contract GuardedFeeTreasury {
    address public owner;
    address public pendingOwner;
    address public feeRecipient;
    uint256 public feeBps = 300;

    event OwnershipTransferStarted(address indexed from, address indexed to);
    event OwnerChanged(address indexed from, address indexed to);
    event Swept(address indexed token, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address _feeRecipient) {
        owner = msg.sender;
        feeRecipient = _feeRecipient;
    }

    function setFeeBps(uint256 newFeeBps) external onlyOwner {
        require(newFeeBps <= 1000, "fee too high");
        feeBps = newFeeBps;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero owner");
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "not pending owner");
        emit OwnerChanged(owner, pendingOwner);
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function sweep(address token, uint256 amount) external onlyOwner {
        bool ok = IERC20(token).transfer(feeRecipient, amount);
        require(ok, "token transfer failed");
        emit Swept(token, amount);
    }
}
