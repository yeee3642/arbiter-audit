# Cross-Chain Vulnerabilities

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Cross-Chain Vulnerabilities**
Cross-chain protocols bridge assets and messages between heterogeneous chains, introducing verification gaps that single-chain contracts do not face. A trusted address or relayer registered for one chain must be cryptographically bound to that chain's identifier; otherwise an attacker can register a malicious address for a different chain and bypass authorization. Address encoding differs across ecosystems (EVM 20-byte, Cosmos bech32, Solana ed25519), so storing or comparing source addresses as fixed-size `address` types loses information and breaks approval lookups for non-EVM origins. Refund addresses and execution metadata must be supplied by the caller, not defaulted to `msg.sender`, because the original sender on the source chain is not the relayer executing on the destination chain. Remote deployment or initialization entry points must enforce ownership or minter authorization before mutating cross-chain state, otherwise anyone can zero out balances or register unauthorized token managers. Rebase tokens change total supply continuously; locking a static amount and later transferring that fixed value causes underpayment on positive rebase and reverts on negative rebase. Decimal mismatches between chains (e.g., 6 vs 18 decimals for USDC) require explicit normalization before burning, minting, or emitting amounts, otherwise value is misrepresented.

### Detection Checks

1. Verify that `setTrustedAddress` or similar registration functions validate the `chain` parameter against an allowlist of supported chain identifiers and reject unknown chains.
2. Ensure cross-chain approval hashes encode `sourceAddress` as a generic `bytes` or `string` rather than `address` to preserve non-EVM formats (bech32, ed25519).
3. Confirm that `callContract` and `callContractWithToken` accept an explicit `refundAddress` parameter and emit it in events instead of using `msg.sender`.
4. Check that `_deployRemoteTokenManager` or equivalent remote initialization functions gate access with `onlyOwner`, `onlyMinter`, or a role check before emitting deployment events and sending cross-chain messages.
5. Validate that token transfer amounts for rebase tokens are read from the token contract at execution time (`balanceOf` or `totalSupply` delta) rather than trusting a stale `amount` parameter.
6. Verify that `callContractWithToken`, `_burnTokenFrom`, and mint/burn logic normalize `amount` by `10^(18 - decimals())` when source and destination chain decimals differ.
7. Ensure replay protection uses a globally unique `commandId` (e.g., `keccak256(sourceChain, sourceAddress, nonce)`) and that `isCommandExecuted` is checked before any state mutation.
8. Confirm that rollback or refund logic exists for failed cross-chain executions (e.g., `onRevert` handlers, `refundAddress` funding) and is not omitted.

### Examples

#### Example 1: Incorrect Example

```solidity
function setTrustedAddress(string memory chain, string memory address_) external onlyOwner {
    _setTrustedAddress(chain, address_);
}

function _getIsContractCallApprovedWithMintKey(
    bytes32 commandId,
    string memory sourceChain,
    string memory sourceAddress,
    address contractAddress,
    bytes32 payloadHash,
    string memory symbol,
    uint256 amount
) internal pure returns (bytes32) {
    return keccak256(abi.encode(
        PREFIX_CONTRACT_CALL_APPROVED_WITH_MINT,
        commandId,
        sourceChain,
        sourceAddress,
        contractAddress,
        payloadHash,
        symbol,
        amount
    ));
}

function callContract(
    string calldata destinationChain,
    string calldata destinationContractAddress,
    bytes calldata payload
) external {
    emit ContractCall(msg.sender, destinationChain, destinationContractAddress, keccak256(payload), payload);
}

function _deployRemoteTokenManager(
    bytes32 tokenId,
    string calldata destinationChain,
    uint256 gasValue,
    TokenManagerType tokenManagerType,
    bytes calldata params
) internal {
    validTokenManagerAddress(tokenId);
    emit TokenManagerDeploymentStarted(tokenId, destinationChain, tokenManagerType, params);
    bytes memory payload = abi.encode(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER, tokenId, tokenManagerType, params);
    _callContract(destinationChain, payload, IGatewayCaller.MetadataVersion.CONTRACT_CALL, gasValue);
}

function expressExecuteWithToken(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload,
    string calldata symbol,
    uint256 amount
) external payable virtual {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    address gatewayToken = gateway.tokenAddresses(symbol);
    bytes32 payloadHash = keccak256(payload);
    emit ExpressExecutedWithToken(commandId, sourceChain, sourceAddress, payloadHash, symbol, amount, expressExecutor);
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, payloadHash, symbol, amount, expressExecutor);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), amount);
    _executeWithToken(sourceChain, sourceAddress, payload, symbol, amount);
}

function callContractWithToken(
    string calldata destinationChain,
    string calldata destinationContractAddress,
    bytes calldata payload,
    string calldata symbol,
    uint256 amount
) external {
    _burnTokenFrom(msg.sender, symbol, amount);
    emit ContractCallWithToken(msg.sender, destinationChain, destinationContractAddress, keccak256(payload), payload, symbol, amount);
}
```

Multiple cross-chain flaws: trusted address registration lacks chain validation; approval hash encodes contractAddress as EVM address losing non-EVM source formats; callContract uses msg.sender as refund address; _deployRemoteTokenManager missing caller authorization; expressExecuteWithToken trusts static amount for rebase tokens; callContractWithToken burns raw amount without decimal normalization.

#### Example 2: Correct Example

```solidity
function setTrustedAddress(string memory chain, string memory address_) external onlyOwner {
    require(supportedChains[chain], "unsupported chain");
    _setTrustedAddress(chain, address_);
}

function _getIsContractCallApprovedWithMintKey(
    bytes32 commandId,
    string memory sourceChain,
    string memory sourceAddress,
    bytes memory contractAddress,
    bytes32 payloadHash,
    string memory symbol,
    uint256 amount
) internal pure returns (bytes32) {
    return keccak256(abi.encode(
        PREFIX_CONTRACT_CALL_APPROVED_WITH_MINT,
        commandId,
        sourceChain,
        sourceAddress,
        contractAddress,
        payloadHash,
        symbol,
        amount
    ));
}

function callContract(
    string calldata destinationChain,
    string calldata destinationContractAddress,
    bytes calldata payload,
    address refundAddress
) external {
    emit ContractCall(refundAddress, destinationChain, destinationContractAddress, keccak256(payload), payload);
}

function _deployRemoteTokenManager(
    bytes32 tokenId,
    string calldata destinationChain,
    uint256 gasValue,
    TokenManagerType tokenManagerType,
    bytes calldata params
) internal {
    require(hasRole(MINTER_ROLE, msg.sender) || msg.sender == owner(), "unauthorized");
    validTokenManagerAddress(tokenId);
    emit TokenManagerDeploymentStarted(tokenId, destinationChain, tokenManagerType, params);
    bytes memory payload = abi.encode(MESSAGE_TYPE_DEPLOY_TOKEN_MANAGER, tokenId, tokenManagerType, params);
    _callContract(destinationChain, payload, IGatewayCaller.MetadataVersion.CONTRACT_CALL, gasValue);
}

function expressExecuteWithToken(
    bytes32 commandId,
    string calldata sourceChain,
    string calldata sourceAddress,
    bytes calldata payload,
    string calldata symbol,
    uint256 amount
) external payable virtual {
    if (gateway.isCommandExecuted(commandId)) revert AlreadyExecuted();
    address expressExecutor = msg.sender;
    address gatewayToken = gateway.tokenAddresses(symbol);
    uint256 currentAmount = IERC20(gatewayToken).balanceOf(expressExecutor);
    bytes32 payloadHash = keccak256(payload);
    emit ExpressExecutedWithToken(commandId, sourceChain, sourceAddress, payloadHash, symbol, currentAmount, expressExecutor);
    _setExpressExecutorWithToken(commandId, sourceChain, sourceAddress, payloadHash, symbol, currentAmount, expressExecutor);
    IERC20(gatewayToken).safeTransferFrom(expressExecutor, address(this), currentAmount);
    _executeWithToken(sourceChain, sourceAddress, payload, symbol, currentAmount);
}

function callContractWithToken(
    string calldata destinationChain,
    string calldata destinationContractAddress,
    bytes calldata payload,
    string calldata symbol,
    uint256 amount
) external {
    uint8 decimals = IERC20Metadata(gateway.tokenAddresses(symbol)).decimals();
    uint256 normalized = amount * 10**(18 - decimals);
    _burnTokenFrom(msg.sender, symbol, normalized);
    emit ContractCallWithToken(msg.sender, destinationChain, destinationContractAddress, keccak256(payload), payload, symbol, normalized);
}
```

Fixes: chain validation in setTrustedAddress; contractAddress as bytes for non-EVM compatibility; explicit refundAddress parameter; MINTER_ROLE check in _deployRemoteTokenManager; dynamic balance read for rebase tokens; decimal normalization before burn/emit.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
