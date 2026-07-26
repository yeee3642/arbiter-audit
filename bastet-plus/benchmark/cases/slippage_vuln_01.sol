// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
    ) external returns (uint256[] memory amounts);
}

/// @notice Auto-compounding vault that periodically sells reward tokens back into the want token.
contract HarvestVault {
    IUniswapV2Router public immutable router;
    IERC20 public immutable reward;
    IERC20 public immutable want;
    address public strategist;

    mapping(address => uint256) public shares;
    uint256 public totalShares;

    modifier onlyStrategist() {
        require(msg.sender == strategist, "not strategist");
        _;
    }

    constructor(address _router, address _reward, address _want) {
        router = IUniswapV2Router(_router);
        reward = IERC20(_reward);
        want = IERC20(_want);
        strategist = msg.sender;
    }

    function deposit(uint256 amount) external {
        require(amount > 0, "zero");
        want.transferFrom(msg.sender, address(this), amount);
        shares[msg.sender] += amount;
        totalShares += amount;
    }

    /// @notice Sells accumulated rewards and folds the proceeds back into the vault.
    function harvest() external onlyStrategist {
        uint256 pending = reward.balanceOf(address(this));
        if (pending == 0) return;

        address[] memory path = new address[](2);
        path[0] = address(reward);
        path[1] = address(want);

        reward.approve(address(router), pending);
        router.swapExactTokensForTokens(
            pending,
            0,
            path,
            address(this),
            block.timestamp
        );
    }

    function withdraw(uint256 amount) external {
        require(shares[msg.sender] >= amount, "insufficient");
        shares[msg.sender] -= amount;
        totalShares -= amount;
        want.transfer(msg.sender, amount);
    }
}
