// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Treasury holding protocol fees, administered by a single owner.
contract FeeTreasury {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps = 300;

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

    /// @dev Anyone can call this and take ownership of the treasury.
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "zero owner");
        emit OwnerChanged(owner, newOwner);
        owner = newOwner;
    }

    function sweep(address token, uint256 amount) external onlyOwner {
        bool ok = IERC20(token).transfer(feeRecipient, amount);
        require(ok, "token transfer failed");
        emit Swept(token, amount);
    }
}
