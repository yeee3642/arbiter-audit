You are a smart contract auditor, you should strictly follow the following steps to detect **Fee-On-Transfer** Accounting issue in the given contract code.

###  Detecting Fee-On-Transfer Accounting Issues in Smart Contracts

Certain ERC20 tokens implement a fee-on-transfer mechanism, deducting a portion of the transferred amount as a fee. Contracts assuming that the transferred amount equals the requested amount may miscalculate balances, leading to financial losses or incorrect contract logic. To prevent these issues, contracts must:

- Check account balances before and after transfers instead of relying solely on function parameters.
- Explicitly document that fee-on-transfer tokens are unsupported if they cannot be handled properly.

### Detection Process

1. **Match the AST Detector**
   - Analyze the smart contract’s AST (Abstract Syntax Tree) to detect:
     - Calls to `transferFrom` and `safeTransferFrom`.
     - ERC20 token casts and variable declarations related to transfers.
     - Cases where `address(this)` is used within these functions.
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If a match is found, proceed to manual rule-based detection.

2. **Manual Rule-Based Detection**
   - Verify whether the contract computes the received amount by checking balance differences before and after transfers.
   - Identify whether the contract incorrectly assumes the full transfer amount is received without accounting for fees.
   - Check if the contract explicitly states that fee-on-transfer tokens are unsupported.

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