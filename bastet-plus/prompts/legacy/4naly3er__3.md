You are a smart contract auditor, you should strictly follow the following steps to detect the **using _msgSender() while not supporting EIP-2771** issue in the given contract code.

### Detecting Improper Use of `_msgSender()` in Smart Contracts

In Solidity, using `_msgSender()` is only necessary when supporting EIP-2771, which introduces a trusted forwarder for meta-transactions. If the contract does not implement EIP-2771, using `_msgSender()` increase gas costs, adds complexity and may introduce security risks. It may incorrectly interpret the caller’s address if the call data is manipulated, potentially allowing unauthorized access
. Instead, use `msg.sender` directly. 

### Detection Process

1. **Initial Filtering Using Regular Expression**

   - First, scan the smart contract code for occurrences of the following pattern:
     ```
     /_msgSender\(\)/gi
     ```
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If a match is found, proceed to step 2.

2. **Manual Review for Improper `_msgSender()` Usage**

   - Verify whether the contract is designed to support EIP-2771.
   - If not, check if `_msgSender()` can be replaced with `msg.sender`.

### Issue Examples

#### Example 1: **Improper Usage of `_msgSender()`**

```solidity
function transferOwnership(address newOwner) public {
    require(_msgSender() == owner, "Caller is not owner"); // @audit inefficient `_msgSender()`
    owner = newOwner;
}
```

**Explanation:**
- `_msgSender()` is used without any indication that the contract supports EIP-2771.

#### Example 2: **Correct Usage (Using `msg.sender`)**

```solidity
function transferOwnership(address newOwner) public {
    require(msg.sender == owner, "Caller is not owner");
    owner = newOwner;
}
```

**Explanation:**
- The function uses `msg.sender`, which is more gas-efficient when EIP-2771 support is not required.

#### Example 3: **Valid Use of `_msgSender()` With EIP-2771**

```solidity
contract MetaTransaction is ERC2771Context {
    function executeMetaTransaction(address user, bytes memory callData) public {
        require(_msgSender() == user, "Unauthorized");
        (bool success,) = address(this).call(callData);
        require(success, "Transaction failed");
    }
}
```

**Explanation:**
- `_msgSender()` is correctly used because the contract inherits from `ERC2771Context`, indicating EIP-2771 support.

### Task to Perform

Follow the examples above to examine each contract to check if `_msgSender()` is used without EIP-2771 support. The process should first scan using the regex filter and then proceed to analyze the contract logic.

### Output Format

If NO concrete vulnerability found, output a empty array

Otherwise, follow the format below:

```
[
    {
        "summary":  "summary of the vulnerabilities",
        "Vulnerability Details": {
            "function_name": "Name of the function",
            "description": "a brief description of the vulnerability"
        },
    
        "code_snippet": [
            "code snippet in the file"
        ],
    
        "recommendation": "recommendation of how to fix the vulnerability"
    
    }
]
```