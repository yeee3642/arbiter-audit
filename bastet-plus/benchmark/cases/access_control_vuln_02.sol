// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Upgradeable-style vault where the implementation slot is administered.
contract UpgradeableVault {
    address public admin;
    address public implementation;
    bool public paused;
    mapping(address => uint256) public deposits;

    event Upgraded(address indexed newImplementation);
    event Paused(bool state);

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    constructor(address _implementation) {
        admin = msg.sender;
        implementation = _implementation;
    }

    function deposit() external payable {
        require(!paused, "paused");
        deposits[msg.sender] += msg.value;
    }

    function setPaused(bool state) external onlyAdmin {
        paused = state;
        emit Paused(state);
    }

    /// @dev No access modifier: any address can point the vault at its own logic.
    function upgradeTo(address newImplementation) external {
        require(newImplementation != address(0), "zero impl");
        implementation = newImplementation;
        emit Upgraded(newImplementation);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
