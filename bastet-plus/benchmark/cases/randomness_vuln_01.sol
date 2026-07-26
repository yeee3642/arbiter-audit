// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Raffle that draws a winner from the current ticket holders.
contract Raffle {
    address[] public players;
    address public lastWinner;
    uint256 public ticketPrice = 0.01 ether;
    address public operator;

    constructor() {
        operator = msg.sender;
    }

    function buyTicket() external payable {
        require(msg.value == ticketPrice, "wrong price");
        players.push(msg.sender);
    }

    /// @dev The seed is built entirely from values a proposer or caller can observe or influence.
    function drawWinner() external returns (address) {
        require(msg.sender == operator, "not operator");
        require(players.length > 0, "no players");
        uint256 seed = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, blockhash(block.number - 1), players.length))
        );
        uint256 index = seed % players.length;
        lastWinner = players[index];
        uint256 pot = address(this).balance;
        delete players;
        payable(lastWinner).transfer(pot);
        return lastWinner;
    }
}
