You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Zero Slippage Required**
A function that requires zero slippage is likely to revert presenting a persistent Denial Of Service to users. Expecting zero slippage is unrealistic which is why developers must allow users to specify slippage parameters.

### Task to Perform
Follow the examples above to examine each contract and check if it contains this issue. If you find any potential issues, record them using the format below.

### Output Format

If NO concrete vulnerability found, output a empty array

Otherwise, follow the format below:

```
[
    {
        "summary":  "summary of the vulnerabilities",
        "vulnerability_details": {
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