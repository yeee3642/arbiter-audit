// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVRFCoordinatorV2 {
    function requestRandomWords(
        bytes32 keyHash,
        uint64 subId,
        uint16 minimumRequestConfirmations,
        uint32 callbackGasLimit,
        uint32 numWords
    ) external returns (uint256 requestId);
}

/// @notice Same raffle drawing its winner from Chainlink VRF.
contract VrfRaffle {
    address[] public players;
    address public lastWinner;
    uint256 public ticketPrice = 0.01 ether;
    address public operator;

    IVRFCoordinatorV2 public immutable coordinator;
    bytes32 public immutable keyHash;
    uint64 public immutable subId;
    uint16 public constant REQUEST_CONFIRMATIONS = 20;
    uint256 public pendingRequestId;

    constructor(address _coordinator, bytes32 _keyHash, uint64 _subId) {
        operator = msg.sender;
        coordinator = IVRFCoordinatorV2(_coordinator);
        keyHash = _keyHash;
        subId = _subId;
    }

    function buyTicket() external payable {
        require(pendingRequestId == 0, "draw in progress");
        require(msg.value == ticketPrice, "wrong price");
        players.push(msg.sender);
    }

    /// @dev Ticket sales close before randomness is requested, so nobody can bet on a known seed.
    function requestDraw() external {
        require(msg.sender == operator, "not operator");
        require(players.length > 0, "no players");
        require(pendingRequestId == 0, "already requested");
        pendingRequestId = coordinator.requestRandomWords(
            keyHash, subId, REQUEST_CONFIRMATIONS, 200000, 1
        );
    }

    function rawFulfillRandomWords(uint256 requestId, uint256[] memory randomWords) external {
        require(msg.sender == address(coordinator), "only coordinator");
        require(requestId == pendingRequestId, "unknown request");
        uint256 index = randomWords[0] % players.length;
        lastWinner = players[index];
        uint256 pot = address(this).balance;
        delete players;
        pendingRequestId = 0;
        payable(lastWinner).transfer(pot);
    }
}
