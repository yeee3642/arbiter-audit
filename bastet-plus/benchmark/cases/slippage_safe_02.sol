// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IRouter {
    function addLiquidity(
        address tokenA,
        address tokenB,
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        address to,
        uint256 deadline
    ) external returns (uint256 amountA, uint256 amountB, uint256 liquidity);
}

/// @notice Same zapper, with the caller's slippage bounds forwarded intact.
contract GuardedLiquidityZapper {
    IRouter public immutable router;
    address public immutable tokenA;
    address public immutable tokenB;

    event Zapped(address indexed user, uint256 liquidity);

    constructor(address _router, address _tokenA, address _tokenB) {
        router = IRouter(_router);
        tokenA = _tokenA;
        tokenB = _tokenB;
    }

    function zapIn(
        uint256 amountADesired,
        uint256 amountBDesired,
        uint256 amountAMin,
        uint256 amountBMin,
        uint256 deadline
    ) external returns (uint256 liquidity) {
        require(deadline >= block.timestamp, "expired");
        require(amountAMin > 0 && amountBMin > 0, "slippage bounds required");

        IERC20(tokenA).transferFrom(msg.sender, address(this), amountADesired);
        IERC20(tokenB).transferFrom(msg.sender, address(this), amountBDesired);
        IERC20(tokenA).approve(address(router), amountADesired);
        IERC20(tokenB).approve(address(router), amountBDesired);

        uint256 usedA;
        uint256 usedB;
        (usedA, usedB, liquidity) = router.addLiquidity(
            tokenA,
            tokenB,
            amountADesired,
            amountBDesired,
            amountAMin,
            amountBMin,
            msg.sender,
            deadline
        );

        require(usedA >= amountAMin && usedB >= amountBMin, "slippage exceeded");
        emit Zapped(msg.sender, liquidity);
    }
}
