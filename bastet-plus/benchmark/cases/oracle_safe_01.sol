// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

/// @notice Same market, validating every field of the Chainlink round.
contract GuardedLendingMarket {
    AggregatorV3Interface public immutable priceFeed;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV_BPS = 7000;
    uint256 public constant MAX_STALENESS = 1 hours;

    constructor(address feed) {
        priceFeed = AggregatorV3Interface(feed);
    }

    function getPrice() public view returns (uint256) {
        (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) =
            priceFeed.latestRoundData();
        require(answer > 0, "invalid price");
        require(updatedAt != 0 && startedAt != 0, "incomplete round");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price");
        require(answeredInRound >= roundId, "stale round");
        return uint256(answer);
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 scale = 10 ** priceFeed.decimals();
        uint256 collateralValue = (collateral[msg.sender] * price) / scale;
        uint256 maxDebt = (collateralValue * LTV_BPS) / 10000;
        require(debt[msg.sender] + amount <= maxDebt, "undercollateralised");
        debt[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
