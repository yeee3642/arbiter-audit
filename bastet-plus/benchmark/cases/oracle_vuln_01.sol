// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

/// @notice Collateralised lending market priced off a Chainlink feed.
contract LendingMarket {
    AggregatorV3Interface public immutable priceFeed;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    uint256 public constant LTV_BPS = 7000;

    constructor(address feed) {
        priceFeed = AggregatorV3Interface(feed);
    }

    /// @dev Takes the answer and ignores every freshness and sanity field the feed returns.
    function getPrice() public view returns (uint256) {
        (, int256 answer, , , ) = priceFeed.latestRoundData();
        return uint256(answer);
    }

    function depositCollateral() external payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        uint256 price = getPrice();
        uint256 collateralValue = (collateral[msg.sender] * price) / 1e8;
        uint256 maxDebt = (collateralValue * LTV_BPS) / 10000;
        require(debt[msg.sender] + amount <= maxDebt, "undercollateralised");
        debt[msg.sender] += amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
