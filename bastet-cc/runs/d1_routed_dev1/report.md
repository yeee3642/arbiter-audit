# Bastet-CC report — d1_routed_dev1

55 findings — 31 High, 18 Medium, 6 Low

55/55 localised to a specific function.

| severity | tag | location | detector |
|---|---|---|---|
| High | call / delegatecall | `contracts/VotingEscrow.sol:675` | `owasp2025__sc062025_unchecked_external_calls` |
| High | ERC721 | `contracts/VotingEscrow.sol:403` | `4naly3er__4naly3er_m_nftredefinesmint` |
| High | call / delegatecall | `contracts/VotingEscrow.sol:430` | `owasp2025__sc062025_unchecked_external_calls` |
| High | Access Control | `contracts/VotingEscrow.sol:170` | `access_control__lack_of_access_control` |
| High | ERC721 | `contracts/VotingEscrow.sol:440` | `4naly3er__4naly3er_m_nftredefinesmint` |
| High | DoS | `contracts/VotingEscrow.sol:440` | `owasp2025__sc102025_denial_of_service` |
| High | call / delegatecall | `contracts/VotingEscrow.sol:483` | `owasp2025__sc062025_unchecked_external_calls` |
| High | DoS | `contracts/VotingEscrow.sol:493` | `owasp2025__sc102025_denial_of_service` |
| High | ERC721 | `contracts/VotingEscrow.sol:632` | `4naly3er__4naly3er_m_nftredefinesmint` |
| High | Logic Error | `contracts/VotingEscrow.sol:632` | `owasp2025__sc032025_logic_errors` |
| High | call / delegatecall | `contracts/VotingEscrow.sol:655` | `owasp2025__sc062025_unchecked_external_calls` |
| High | Reentrancy | `contracts/VotingEscrow.sol:632` | `owasp2025__sc052025_reentrancy` |
| High | Access Control | `contracts/VotingEscrow.sol:139` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/VotingEscrow.sol:139` | `access_control__lack_of_two_step_process_for_contract_ownership_changes` |
| High | Access Control | `contracts/VotingEscrow.sol:161` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/VotingEscrow.sol:146` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/VotingEscrow.sol:153` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | ERC721 | `contracts/VotingEscrow.sol:526` | `4naly3er__4naly3er_m_nftredefinesmint` |
| High | call / delegatecall | `contracts/VotingEscrow.sol:544` | `owasp2025__sc062025_unchecked_external_calls` |
| High | Reentrancy | `contracts/VotingEscrow.sol:526` | `owasp2025__sc052025_reentrancy` |
| High | Access Control | `contracts/features/Blocklist.sol:23` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/Authorizable.sol:38` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/Authorizable.sol:13` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/Authorizable.sol:44` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/Authorizable.sol:18` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/Authorizable.sol:50` | `access_control__lack_of_two_step_process_for_contract_ownership_changes` |
| High | Access Control | `contracts/libraries/Authorizable.sol:50` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | DoS | `contracts/libraries/ERC20Permit.sol:188` | `owasp2025__sc102025_denial_of_service` |
| High | DoS | `contracts/libraries/ERC20PermitWithMint.sol:56` | `owasp2025__sc102025_denial_of_service` |
| High | Access Control | `contracts/libraries/ERC20PermitWithMint.sol:49` | `4naly3er__4naly3er_m_centralizationrisk` |
| High | Access Control | `contracts/libraries/ERC20PermitWithMint.sol:29` | `4naly3er__4naly3er_m_centralizationrisk` |
| Medium | Arithmetic | `contracts/VotingEscrow.sol:222` | `4naly3er__4naly3er_m_blocknumberl` |
| Medium | Arithmetic | `contracts/VotingEscrow.sol:770` | `4naly3er__4naly3er_m_blocknumberl` |
| Medium | Access Control | `contracts/VotingEscrow.sol:673` | `4naly3er__4naly3er_m_centralizationrisk` |
| Medium | ERC721 | `contracts/VotingEscrow.sol:673` | `4naly3er__4naly3er_m_nftredefinesmint` |
| Medium | Arithmetic | `contracts/VotingEscrow.sol:100` | `4naly3er__4naly3er_m_blocknumberl` |
| Medium | Reentrancy | `contracts/VotingEscrow.sol:403` | `owasp2025__sc052025_reentrancy` |
| Medium | Access Control | `contracts/VotingEscrow.sol:170` | `4naly3er__4naly3er_m_centralizationrisk` |
| Medium | Reentrancy | `contracts/VotingEscrow.sol:440` | `owasp2025__sc052025_reentrancy` |
| Medium | Logic Error | `contracts/VotingEscrow.sol:652` | `4naly3er__4naly3er_gas_addplusequal` |
| Medium | Arithmetic | `contracts/VotingEscrow.sol:871` | `4naly3er__4naly3er_m_blocknumberl` |
| Medium | Input Validation | `contracts/VotingEscrow.sol:139` | `owasp2025__sc042025_lack_of_input_validation` |
| Medium | Input Validation | `contracts/VotingEscrow.sol:146` | `owasp2025__sc042025_lack_of_input_validation` |
| Medium | Input Validation | `contracts/VotingEscrow.sol:153` | `owasp2025__sc042025_lack_of_input_validation` |
| Medium | DoS | `contracts/VotingEscrow.sol:526` | `denial_of_service__refund_failed` |
| Medium | DoS | `contracts/features/Blocklist.sol:23` | `owasp2025__sc102025_denial_of_service` |
| Medium | call / delegatecall | `contracts/features/Blocklist.sol:23` | `owasp2025__sc062025_unchecked_external_calls` |
| Medium | Input Validation | `contracts/features/Blocklist.sol:23` | `owasp2025__sc042025_lack_of_input_validation` |
| Medium | Input Validation | `contracts/libraries/Authorizable.sol:50` | `owasp2025__sc042025_lack_of_input_validation` |
| Low | Logic Error | `contracts/VotingEscrow.sol:285` | `4naly3er__4naly3er_gas_addplusequal` |
| Low | Logic Error | `contracts/VotingEscrow.sol:420` | `4naly3er__4naly3er_gas_addplusequal` |
| Low | Logic Error | `contracts/VotingEscrow.sol:453` | `4naly3er__4naly3er_gas_addplusequal` |
| Low | Logic Error | `contracts/libraries/ERC20Permit.sol:140` | `4naly3er__4naly3er_gas_addplusequal` |
| Low | Logic Error | `contracts/libraries/ERC20Permit.sol:124` | `4naly3er__4naly3er_gas_addplusequal` |
| Low | Logic Error | `contracts/libraries/ERC20PermitWithMint.sol:42` | `4naly3er__4naly3er_gas_addplusequal` |

## Access Control

### High — VotingEscrow.forceUndelegate (Lack of access control)

**Location** `contracts/VotingEscrow.sol:170`  
**Detector** `access_control__lack_of_access_control`  
**Confidence** 0.90  

The forceUndelegate function only checks that msg.sender == blocklist, but the blocklist address can be changed by the owner via updateBlocklist. If the owner sets blocklist to a malicious address, that address can call forceUndelegate to forcibly undelegate any user's locked tokens, breaking delegation integrity.

### High — VotingEscrow.transferOwnership (Single Point of Failure - Ownership Transfer)

**Location** `contracts/VotingEscrow.sol:139`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The contract uses a single owner model with no multi-signature or timelock protection. The owner can unilaterally transfer ownership to any address, creating a centralization risk where a compromised owner key could permanently transfer control to an attacker.

### High — VotingEscrow.transferOwnership (ownership-transfer)

**Location** `contracts/VotingEscrow.sol:139`  
**Detector** `access_control__lack_of_two_step_process_for_contract_ownership_changes`  
**Confidence** 0.95  

The transferOwnership function implements a single-step ownership transfer without a two-step confirmation process. If ownership is accidentally transferred to an incorrect address (e.g., address with lost private key, zero address, or non-whitelisted address), all owner-only functions become permanently inaccessible, including critical functions like updateBlocklist, updatePenaltyRecipient, unlock, and forceUndelegate.

### High — VotingEscrow.unlock (Single Point of Failure - Protocol Parameter Change)

**Location** `contracts/VotingEscrow.sol:161`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The owner can unilaterally set maxPenalty to 0, effectively disabling the penalty mechanism for early withdrawals. This could be used maliciously to allow penalty-free exits or to manipulate the protocol's economic incentives.

### High — VotingEscrow.updateBlocklist (Single Point of Failure - Critical Parameter Change)

**Location** `contracts/VotingEscrow.sol:146`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The owner can unilaterally change the blocklist contract address. A compromised owner could set a malicious blocklist that blocks all users or allows blocked addresses, effectively controlling who can interact with the protocol.

### High — VotingEscrow.updatePenaltyRecipient (Single Point of Failure - Fund Diversion)

**Location** `contracts/VotingEscrow.sol:153`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The owner can unilaterally change the penalty recipient address. A compromised owner could redirect all accumulated penalties (from users quitting locks early) to an attacker-controlled address.

### High — Blocklist.block (single-point-of-failure)

**Location** `contracts/features/Blocklist.sol:23`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The `block` function is restricted to a single `manager` address with no multi-signature, timelock, or governance oversight. If the manager key is compromised, an attacker can arbitrarily block any contract address and force undelegation of voting power, disrupting protocol operations and potentially censoring users.

### High — Authorizable.authorize (single-owner-no-safeguards)

**Location** `contracts/libraries/Authorizable.sol:38`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.90  

The authorize function allows the single owner to grant privileged authorized status to any address without multi-sig approval or timelock. A compromised owner can authorize malicious addresses.

### High — Authorizable.constructor (single-owner-no-safeguards)

**Location** `contracts/libraries/Authorizable.sol:13`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The contract initializes a single owner (msg.sender) with no multi-signature, timelock, or governance safeguards. This creates a centralization risk where a single compromised private key can fully control the contract.

### High — Authorizable.deauthorize (single-owner-no-safeguards)

**Location** `contracts/libraries/Authorizable.sol:44`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.90  

The deauthorize function allows the single owner to revoke authorized status from any address without multi-sig approval or timelock. A compromised owner can remove legitimate authorized addresses.

### High — Authorizable.onlyOwner (single-owner-no-safeguards)

**Location** `contracts/libraries/Authorizable.sol:18`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The onlyOwner modifier grants exclusive control to a single address with no multi-sig, timelock, or quorum requirements. Any function using this modifier (authorize, deauthorize, setOwner) can be unilaterally executed by the owner.

### High — Authorizable.setOwner (ownership-transfer)

**Location** `contracts/libraries/Authorizable.sol:50`  
**Detector** `access_control__lack_of_two_step_process_for_contract_ownership_changes`  
**Confidence** 0.95  

The setOwner function allows immediate ownership transfer without a two-step process. If an incorrect address is provided (e.g., address with lost private key, zero address, or typo), all owner-only functions become permanently inaccessible with no recovery mechanism.

### High — Authorizable.setOwner (single-owner-no-safeguards)

**Location** `contracts/libraries/Authorizable.sol:50`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The setOwner function allows the single owner to transfer ownership to any address without multi-sig approval, timelock, or two-step ownership transfer (Ownable2Step). A compromised owner can transfer ownership to an attacker.

### High — ERC20PermitWithMint.burn (single-owner-unrestricted-burn)

**Location** `contracts/libraries/ERC20PermitWithMint.sol:49`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The burn function is restricted to a single owner via onlyOwner modifier, allowing unilateral burning of any account's tokens without multi-sig, timelock, or governance safeguards. If the owner key is compromised, an attacker can destroy token holdings.

### High — ERC20PermitWithMint.mint (single-owner-unrestricted-mint)

**Location** `contracts/libraries/ERC20PermitWithMint.sol:29`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.95  

The mint function is restricted to a single owner via onlyOwner modifier, allowing unilateral token supply inflation without multi-sig, timelock, or governance safeguards. If the owner key is compromised, an attacker can mint arbitrary amounts of tokens.

### Medium — VotingEscrow.collectPenalty (Single Point of Failure - Fund Withdrawal)

**Location** `contracts/VotingEscrow.sol:673`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.85  

The collectPenalty function has no access control - anyone can call it to transfer accumulated penalties to the penaltyRecipient. While this doesn't directly allow theft (funds go to penaltyRecipient), combined with updatePenaltyRecipient it enables the owner to drain penalties to any address.

### Medium — VotingEscrow.forceUndelegate (Single Point of Failure - Delegation Control)

**Location** `contracts/VotingEscrow.sol:170`  
**Detector** `4naly3er__4naly3er_m_centralizationrisk`  
**Confidence** 0.90  

The blocklist contract (controlled by owner via updateBlocklist) can force undelegation of any user's voting power. This allows centralized control over delegation relationships, which could be used to manipulate governance voting power.

## Arithmetic

### Medium — VotingEscrow._checkpoint (block.number-usage-l2-inconsistency)

**Location** `contracts/VotingEscrow.sol:222`  
**Detector** `4naly3er__4naly3er_m_blocknumberl`  
**Confidence** 0.95  

The `_checkpoint` function records `block.number` in multiple `Point` structs (user checkpoints, global checkpoints, and slope change iterations). It also uses `block.number` to compute `blockSlope` (blocks per second) for extrapolating future block numbers. On Arbitrum, `block.number` advances only when L1 blocks are produced (~12-13s), not per L2 block (~0.25s), causing severe inaccuracies in time-to-block estimations and breaking `balanceOfAt`/`totalSupplyAt` accuracy.

### Medium — VotingEscrow.balanceOfAt (block.number-usage-l2-inconsistency)

**Location** `contracts/VotingEscrow.sol:770`  
**Detector** `4naly3er__4naly3er_m_blocknumberl`  
**Confidence** 0.90  

The function requires `_blockNumber <= block.number` and uses `block.number` to compute `dBlock` and `dTime` for the latest epoch. On Arbitrum, `block.number` is the L1 block number, so a caller passing an L2 block number will revert incorrectly, and the time estimation formula `(dTime * (_blockNumber - point0.blk)) / dBlock` produces wrong results due to L1/L2 block rate mismatch.

### Medium — VotingEscrow.constructor (block.number-usage-l2-inconsistency)

**Location** `contracts/VotingEscrow.sol:100`  
**Detector** `4naly3er__4naly3er_m_blocknumberl`  
**Confidence** 0.90  

The constructor initializes the first global checkpoint with `block.number`. On Arbitrum, `block.number` returns the L1 block number, while on Optimism it returns the L2 block number. This inconsistency causes the initial checkpoint's block reference to differ across L2s, breaking cross-chain consistency for voting power calculations and historical queries.

### Medium — VotingEscrow.totalSupplyAt (block.number-usage-l2-inconsistency)

**Location** `contracts/VotingEscrow.sol:871`  
**Detector** `4naly3er__4naly3er_m_blocknumberl`  
**Confidence** 0.90  

Similar to `balanceOfAt`, this function validates `_blockNumber <= block.number` and uses `block.number` in the `dTime` calculation for the current epoch. On Arbitrum, the L1 block number does not correspond to L2 block progression, causing incorrect supply queries and potential reverts for valid L2 block numbers.

## DoS

### High — VotingEscrow.increaseAmount (Incorrect Checkpoint State)

**Location** `contracts/VotingEscrow.sol:440`  
**Detector** `owasp2025__sc102025_denial_of_service`  
**Confidence** 0.95  

When increasing amount for a delegated lock, the function checkpoints the delegatee using the delegatee's lock state *after* the sender's amount was increased but *before* the delegatee's delegated amount is increased. This causes the checkpoint to miss the delegation increase, resulting in incorrect voting power accounting for the delegatee.

### High — VotingEscrow.increaseUnlockTime (Incorrect Checkpoint State)

**Location** `contracts/VotingEscrow.sol:493`  
**Detector** `owasp2025__sc102025_denial_of_service`  
**Confidence** 0.95  

When extending lock time for an undelegated lock, the function creates oldLocked as a copy of the *new* state (with updated end time) rather than the original state before the extension. This causes the checkpoint to compare identical states, missing the voting power increase from the longer lock duration.

### High — ERC20Permit.permit (replay-attack)

**Location** `contracts/libraries/ERC20Permit.sol:188`  
**Detector** `owasp2025__sc102025_denial_of_service`  
**Confidence** 0.85  

The permit function uses a nonce-based replay protection mechanism, but the DOMAIN_SEPARATOR is computed only once in the constructor using the initial name, symbol, and chainId. If the contract is deployed on a chain that later undergoes a chain ID change (e.g., Ethereum mainnet to a fork, or L2 chain ID migration), or if the contract is deployed at the same address on multiple chains with the same name/symbol, the DOMAIN_SEPARATOR will be identical across chains. This allows signatures to be replayed across chains. Additionally, the nonce is incremented after signature verification, but if the same nonce is used with the same domain separator on another chain, the permit can be replayed.

### High — ERC20PermitWithMint._burn (accounting-mismatch)

**Location** `contracts/libraries/ERC20PermitWithMint.sol:56`  
**Detector** `owasp2025__sc102025_denial_of_service`  
**Confidence** 0.95  

The _burn function decreases totalSupply by the full requested amount even when the account's balance is less than that amount, causing totalSupply to diverge from the sum of balances. This can lead to totalSupply underflow or an invariant violation where totalSupply < sum(balances).

### Medium — VotingEscrow.withdraw (Refund failed)

**Location** `contracts/VotingEscrow.sol:526`  
**Detector** `denial_of_service__refund_failed`  
**Confidence** 0.85  

The withdraw function uses token.transfer to refund locked tokens to the user. If the token implements a blacklist (e.g., USDC, USDT) and the user's address is blacklisted, or if the token is an ERC777 that reverts in tokensReceived, the transfer will fail and the user's funds will be permanently locked in the contract. The function has no fallback mechanism (e.g., pull-based withdrawal) to recover from such failures.

### Medium — Blocklist.block (missing-input-validation)

**Location** `contracts/features/Blocklist.sol:23`  
**Detector** `owasp2025__sc102025_denial_of_service`  
**Confidence** 0.85  

The block function does not validate that the input address is not the zero address. Blocking address(0) would waste a storage slot and could cause unexpected behavior in downstream integrations that check isBlocked.

## ERC721

### High — VotingEscrow.createLock (Fee-On-Transfer Accounting)

**Location** `contracts/VotingEscrow.sol:403`  
**Detector** `4naly3er__4naly3er_m_nftredefinesmint`  
**Confidence** 0.95  

The function uses `token.transferFrom(msg.sender, address(this), _value)` and assumes the full `_value` is received. If the token charges a fee on transfer, the contract will receive less than `_value` but still records `_value` in `locked_.amount` and emits a `Deposit` event with `_value`, causing accounting mismatch and potential loss of funds.

### High — VotingEscrow.increaseAmount (Fee-On-Transfer Accounting)

**Location** `contracts/VotingEscrow.sol:440`  
**Detector** `4naly3er__4naly3er_m_nftredefinesmint`  
**Confidence** 0.95  

The function uses `token.transferFrom(msg.sender, address(this), _value)` and assumes the full `_value` is received. If the token charges a fee on transfer, the contract will receive less than `_value` but still increments `locked_.amount` and `locked_.delegated` by `_value`, causing accounting mismatch and potential loss of funds.

### High — VotingEscrow.quitLock (Fee-On-Transfer Accounting)

**Location** `contracts/VotingEscrow.sol:632`  
**Detector** `4naly3er__4naly3er_m_nftredefinesmint`  
**Confidence** 0.95  

The function uses `token.transfer(msg.sender, remainingAmount)` and assumes the full `remainingAmount` is sent. If the token charges a fee on transfer, the user receives less than `remainingAmount`, but the contract still reduces `locked_.amount` by `value` and emits a `Withdraw` event with `value`, causing accounting mismatch.

### High — VotingEscrow.withdraw (Fee-On-Transfer Accounting)

**Location** `contracts/VotingEscrow.sol:526`  
**Detector** `4naly3er__4naly3er_m_nftredefinesmint`  
**Confidence** 0.95  

The function uses `token.transfer(msg.sender, value)` and assumes the full `value` is sent. If the token charges a fee on transfer, the user receives less than `value`, but the contract still reduces `locked_.amount` by `value` and emits a `Withdraw` event with `value`, causing accounting mismatch.

### Medium — VotingEscrow.collectPenalty (Fee-On-Transfer Accounting)

**Location** `contracts/VotingEscrow.sol:673`  
**Detector** `4naly3er__4naly3er_m_nftredefinesmint`  
**Confidence** 0.90  

The function uses `token.transfer(penaltyRecipient, amount)` and assumes the full `amount` is sent. If the token charges a fee on transfer, the recipient receives less than `amount`, but the contract still resets `penaltyAccumulated` to 0 and emits a `CollectPenalty` event with `amount`, causing accounting mismatch.

## Input Validation

### Medium — VotingEscrow.transferOwnership (Missing Zero Address Validation)

**Location** `contracts/VotingEscrow.sol:139`  
**Detector** `owasp2025__sc042025_lack_of_input_validation`  
**Confidence** 0.95  

The transferOwnership function does not validate that the new owner address is not the zero address. Setting ownership to address(0) would permanently lock administrative functions (updateBlocklist, updatePenaltyRecipient, unlock, etc.) as no valid caller could ever satisfy msg.sender == owner.

### Medium — VotingEscrow.updateBlocklist (Missing Zero Address Validation)

**Location** `contracts/VotingEscrow.sol:146`  
**Detector** `owasp2025__sc042025_lack_of_input_validation`  
**Confidence** 0.90  

The updateBlocklist function does not validate that the new blocklist address is not the zero address. Setting blocklist to address(0) would cause IBlocklist(blocklist).isBlocked calls to always return false (or revert), effectively disabling the blocklist protection for all users.

### Medium — VotingEscrow.updatePenaltyRecipient (Missing Zero Address Validation)

**Location** `contracts/VotingEscrow.sol:153`  
**Detector** `owasp2025__sc042025_lack_of_input_validation`  
**Confidence** 0.90  

The updatePenaltyRecipient function does not validate that the new penalty recipient address is not the zero address. Setting penaltyRecipient to address(0) would cause any penalty tokens (from quitLock) to be sent to the zero address, permanently burning those funds.

### Medium — Blocklist.block (missing-zero-address-validation)

**Location** `contracts/features/Blocklist.sol:23`  
**Detector** `owasp2025__sc042025_lack_of_input_validation`  
**Confidence** 0.85  

The block function does not validate that the input address is not the zero address (address(0)). Blocking address(0) could cause unexpected behavior in downstream logic that relies on the blocklist, and it represents an invalid contract address that should be rejected explicitly.

### Medium — Authorizable.setOwner (Lack of Input Validation)

**Location** `contracts/libraries/Authorizable.sol:50`  
**Detector** `owasp2025__sc042025_lack_of_input_validation`  
**Confidence** 0.95  

The setOwner function allows the current owner to set the new owner to address(0), which would permanently lock out administrative functions (authorize, deauthorize, setOwner) since onlyOwner modifier would then require msg.sender == address(0). This is a lack of input validation for the 'who' parameter.

## Logic Error

### High — VotingEscrow.quitLock (Logic Errors)

**Location** `contracts/VotingEscrow.sol:632`  
**Detector** `owasp2025__sc032025_logic_errors`  
**Confidence** 0.85  

The quitLock function applies a penalty to the user's locked tokens but does not transfer the penalty amount to the contract or the penalty recipient. The penalty is only tracked in the penaltyAccumulated variable, but the full token amount (value) is transferred back to the user minus the penalty, leaving the penalty tokens in the contract without a mechanism to ensure they are actually collected. This creates a logic error where the penalty is accounted for but not enforced on-chain.

### Medium — VotingEscrow.quitLock (unchecked-arithmetic)

**Location** `contracts/VotingEscrow.sol:652`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.70  

The `penaltyAccumulated += penaltyAmount` operation uses unchecked arithmetic (Solidity 0.8+ built-in overflow checks will revert on overflow, but the pattern of accumulating penalties without a cap or withdrawal mechanism could lead to a denial of service if `penaltyAccumulated` approaches `type(uint256).max`, causing subsequent `quitLock` calls to revert on overflow. While Solidity 0.8+ prevents silent overflow, the lack of a safety check or circuit breaker for extreme accumulation is a design flaw.

### Low — VotingEscrow._checkpoint (unchecked-arithmetic)

**Location** `contracts/VotingEscrow.sol:285`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.40  

Multiple `+=` operations on `lastPoint.slope`, `lastPoint.bias`, `oldSlopeDelta`, and `newSlopeDelta` within the `_checkpoint` function perform arithmetic on `int128` values without explicit overflow/underflow checks beyond the `if (lastPoint.slope < 0)` guards. While the logic attempts to clamp negative values, the intermediate additions could theoretically overflow `int128` before the check, though the constraints of the system (bounded slopes, time) make this unlikely in practice.

### Low — VotingEscrow.createLock (unchecked-arithmetic)

**Location** `contracts/VotingEscrow.sol:420`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.60  

The `locked_.amount += int128(int256(_value))` and `locked_.delegated += int128(int256(_value))` operations cast `uint256 _value` to `int128` without validating that `_value <= type(int128).max`. Similar to `increaseAmount`, a very large `_value` could cause truncation during the cast, leading to incorrect lock amounts.

### Low — VotingEscrow.increaseAmount (unchecked-arithmetic)

**Location** `contracts/VotingEscrow.sol:453`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.60  

The `locked_.amount += int128(int256(_value))` and `newLocked.delegated += int128(int256(_value))` operations cast `uint256 _value` to `int128` without validating that `_value <= type(int128).max`. If a token with very high decimals or a malicious token returns a massive balance, this cast could truncate the value, leading to incorrect accounting. The `require(_value > 0)` check is insufficient.

### Low — ERC20Permit._mint (unchecked-arithmetic)

**Location** `contracts/libraries/ERC20Permit.sol:140`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.60  

The `+=` operator is used to increase `balanceOf[account]` without an overflow check. Same version-dependent concern as above.

### Low — ERC20Permit.transferFrom (unchecked-arithmetic)

**Location** `contracts/libraries/ERC20Permit.sol:124`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.60  

The `+=` operator is used to increase `balanceOf[recipient]` without an overflow check. In Solidity <0.8.0 this could wrap; in >=0.8.0 it reverts. Since the pragma version is not visible in the provided snippet, the pattern is flagged as a potential unchecked-arithmetic issue.

### Low — ERC20PermitWithMint._mint (arithmetic-overflow)

**Location** `contracts/libraries/ERC20PermitWithMint.sol:42`  
**Detector** `4naly3er__4naly3er_gas_addplusequal`  
**Confidence** 0.60  

The `+=` operator on `totalSupply` in `_mint` is unchecked. In Solidity >=0.8.0 this will revert on overflow rather than wrap, which is safe behavior, but the pattern is flagged because explicit unchecked arithmetic or SafeMath usage is preferred for clarity and to avoid accidental wrapping in older compiler versions.

## Reentrancy

### High — VotingEscrow.quitLock (reentrancy)

**Location** `contracts/VotingEscrow.sol:632`  
**Detector** `owasp2025__sc052025_reentrancy`  
**Confidence** 0.85  

The quitLock function updates the user's locked balance and checkpoints before transferring tokens out. If the token is an ERC777 or has a transfer hook, the recipient can reenter quitLock (or other nonReentrant functions) before the penaltyAccumulated state is fully settled. Although nonReentrant prevents reentry into the same function, cross-function reentrancy into withdraw, increaseAmount, delegate, etc. is possible because they share the same ReentrancyGuard. The state changes (locked[msg.sender] = newLocked, _checkpoint) occur before the external call token.transfer, violating checks-effects-interactions.

### High — VotingEscrow.withdraw (reentrancy)

**Location** `contracts/VotingEscrow.sol:526`  
**Detector** `owasp2025__sc052025_reentrancy`  
**Confidence** 0.85  

The withdraw function updates the user's locked balance and checkpoints before transferring tokens out. If the token is an ERC777 or has a transfer hook, the recipient can reenter withdraw (or other nonReentrant functions) before the external call completes. State changes (locked[msg.sender] = newLocked, _checkpoint) occur before the external call token.transfer, violating checks-effects-interactions.

### Medium — VotingEscrow.createLock (reentrancy)

**Location** `contracts/VotingEscrow.sol:403`  
**Detector** `owasp2025__sc052025_reentrancy`  
**Confidence** 0.75  

The createLock function updates the user's locked balance and checkpoints before pulling tokens in via token.transferFrom. If the token is an ERC777 or has a transfer hook, the sender can reenter createLock (or other nonReentrant functions) during the transferFrom call. State changes (locked[msg.sender] = locked_, _checkpoint) occur before the external call token.transferFrom, violating checks-effects-interactions.

### Medium — VotingEscrow.increaseAmount (reentrancy)

**Location** `contracts/VotingEscrow.sol:440`  
**Detector** `owasp2025__sc052025_reentrancy`  
**Confidence** 0.75  

The increaseAmount function updates the user's (and possibly delegatee's) locked balances and checkpoints before pulling tokens in via token.transferFrom. If the token is an ERC777 or has a transfer hook, the sender can reenter increaseAmount (or other nonReentrant functions) during the transferFrom call. State changes occur before the external call token.transferFrom, violating checks-effects-interactions.

## call / delegatecall

### High — VotingEscrow.collectPenalty (unchecked-external-call)

**Location** `contracts/VotingEscrow.sol:675`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.95  

The external call `token.transfer(penaltyRecipient, amount)` is not checked for a return value. If the token contract returns `false` on failure, the function proceeds to emit a `CollectPenalty` event and zeros out `penaltyAccumulated`, resulting in permanent loss of accumulated penalties.

### High — VotingEscrow.createLock (unchecked-external-call)

**Location** `contracts/VotingEscrow.sol:430`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.95  

The external call `token.transferFrom(msg.sender, address(this), _value)` is not checked for a return value. If the token contract does not revert on failure but returns `false`, the function will continue execution and emit a `Deposit` event, incorrectly recording a deposit that never occurred.

### High — VotingEscrow.increaseAmount (unchecked-external-call)

**Location** `contracts/VotingEscrow.sol:483`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.95  

The external call `token.transferFrom(msg.sender, address(this), _value)` is not checked for a return value. If the token contract returns `false` on failure, the function proceeds to emit a `Deposit` event, creating an inconsistent state where voting power is increased without receiving tokens.

### High — VotingEscrow.quitLock (unchecked-external-call)

**Location** `contracts/VotingEscrow.sol:655`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.95  

The external call `token.transfer(msg.sender, remainingAmount)` is not checked for a return value. If the token contract returns `false` on failure, the function proceeds to emit a `Withdraw` event and zeros out the user's lock, resulting in permanent loss of the remaining tokens after penalty.

### High — VotingEscrow.withdraw (unchecked-external-call)

**Location** `contracts/VotingEscrow.sol:544`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.95  

The external call `token.transfer(msg.sender, value)` is not checked for a return value. If the token contract returns `false` on failure, the function proceeds to emit a `Withdraw` event and zeros out the user's lock, resulting in permanent loss of funds for the user.

### Medium — Blocklist.block (unchecked-external-call)

**Location** `contracts/features/Blocklist.sol:23`  
**Detector** `owasp2025__sc062025_unchecked_external_calls`  
**Confidence** 0.85  

The external call to IVotingEscrow(ve).forceUndelegate(addr) does not check the return value. If the call fails (e.g., ve is not a contract, reverts, or returns false), the block function will still succeed and set _blocklist[addr] = true, leading to inconsistent state where the address is blocklisted but the forced undelegation did not occur.
