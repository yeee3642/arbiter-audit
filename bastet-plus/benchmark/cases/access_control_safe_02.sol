// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Same vault with the upgrade path locked to the admin behind a timelock.
contract GuardedUpgradeableVault {
    address public admin;
    address public implementation;
    address public queuedImplementation;
    uint256 public queuedAt;
    uint256 public constant UPGRADE_DELAY = 2 days;
    bool public paused;
    mapping(address => uint256) public deposits;

    event UpgradeQueued(address indexed newImplementation, uint256 eta);
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

    function queueUpgrade(address newImplementation) external onlyAdmin {
        require(newImplementation != address(0), "zero impl");
        queuedImplementation = newImplementation;
        queuedAt = block.timestamp;
        emit UpgradeQueued(newImplementation, block.timestamp + UPGRADE_DELAY);
    }

    function executeUpgrade() external onlyAdmin {
        require(queuedImplementation != address(0), "nothing queued");
        require(block.timestamp >= queuedAt + UPGRADE_DELAY, "timelock active");
        implementation = queuedImplementation;
        queuedImplementation = address(0);
        emit Upgraded(implementation);
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}
