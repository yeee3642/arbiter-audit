You are a smart contract auditor, you should strictly follow the following steps to detect **using `delegatecall` inside a loop** in the given contract code.

## Using `delegatecall` Inside a Loop

Using `delegatecall` inside a loop can lead to unintended consequences, as the same `msg.value` will be credited multiple times. This can result in security vulnerabilities, reentrancy risks, and incorrect state updates. Developers must avoid using `delegatecall` in loops and instead restructure their contracts to execute delegate calls more securely.

### Detection Process

1. **Initial Filtering Using Regular Expression**

   - use code to scan the smart contract for occurrences of the following pattern, a `delegatecall()` function call should be directly found inside a loop:
     ```
     /(for|while|do)[^\(]?(\([^\)]*\))?.?\{(([^\}]*\n)*(([^\}]*\{)([^\{\}]*\n)*([^\{\}]*\}[^\}]*)\n))*[^\}]*delegatecall/g
     ```
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If a match is found, proceed to step 2.

2. **Manual Review for Unsafe **``** Usage**

   - Verify that `delegatecall` is not executed inside a loop where `msg.value` could be incorrectly credited multiple times.
   - Check whether the contract logic can be rewritten to safely handle delegated execution.

### Issue Examples

#### Example 1: **Unsafe **``** Inside a Loop**

```solidity
for (uint256 i = 0; i < addresses.length; i++) {
    (bool success, ) = addresses[i].delegatecall(abi.encodeWithSignature("execute()")); // @audit Unsafe: `delegatecall` inside a loop
}
```

**Explanation:**

- The loop calls `delegatecall` multiple times, potentially crediting `msg.value` repeatedly.

#### Example 2: **Correct Use (Avoiding **``** Inside Loop)**

```solidity
function executeDelegatedCalls(address[] memory addresses) external {
    for (uint256 i = 0; i < addresses.length; i++) {
        executeSingleDelegateCall(addresses[i]);
    }
}

function executeSingleDelegateCall(address target) internal {
    (bool success, ) = target.delegatecall(abi.encodeWithSignature("execute()"));
    require(success, "Delegatecall failed");
}
```

**Explanation:**

- The function ensures that each `delegatecall` is handled separately, reducing unintended re-credits.

### Task to Perform

Follow the examples above to examine each contract to check if `delegatecall` is incorrectly placed inside a loop. The process should first scan using the regex filter and then proceed to analyze the contract logic.

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