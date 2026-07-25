---
id: 4naly3er__4naly3er_m_blocknumberl
name: "4naly3er-M-blockNumberL"
source_workflow: 4naly3er
upstream_model: gpt-4o-mini
tags: ["Arithmetic"]
routing_hints: ["address", "arbBlockNumber", "block.number", "vote"]
prompt_chars: 3901
---

# 4naly3er-M-blockNumberL

## Detection prompt

You are a smart contract auditor, you should strictly follow the following steps to detect the usage of `block.number` in different Layer2 (L2) environments, particularly focusing on the differences between Optimism and Arbitrum, as well as OpenZeppelin's modifications.

### **Detecting `block.number` Issues on Layer 2 (L2) Networks**

`block.number` behaves differently on various Layer 2 (L2) networks. On Optimism, it represents the L2 block number, while on Arbitrum, it refers to the L1 block number. This inconsistency can cause issues, especially when using block numbers for timing, such as in voting mechanisms or governance proposals. 

To avoid these problems:
- On **Arbitrum**, you need to use `ArbSys(address(100)).arbBlockNumber()`.
- **OpenZeppelin Contracts** introduced a fix in version 4.9 to avoid using block numbers for timing in their governance system, instead implementing a clock.

#### **Detection Process**

1. **Pattern Detection Using Regex**:
   - Use code and the following regex to search the contract code for instances of `block.number`:
     ```js
     /block\.number/gi
     ```
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If matches are found, proceed to step 2 for a manual review.

2. **Manual Review**:
   - If `block.number` is found, determine if the contract is running on an L2 network like Optimism or Arbitrum.
   - Review whether the contract uses `block.number` for timing or voting, which could lead to inconsistencies due to the differences in L2 block numbers.
   - Ensure that the correct approach is used based on the network, such as `arbBlockNumber()` for Arbitrum, or implementing a **clock** for L2 as suggested by OpenZeppelin.

#### **Example Issue:**

##### **Example 1: Incorrect Use of `block.number` for Timing on L2**

```solidity
function vote(uint256 proposalId) public {
    require(block.number >= proposals[proposalId].startBlock, "Voting hasn't started yet");
    require(block.number <= proposals[proposalId].endBlock, "Voting has ended");
    // Vote logic
}
```

**Explanation:**
- This contract uses `block.number` for timing-based logic. However, `block.number` behaves differently on L2 networks like Optimism and Arbitrum. This can lead to inconsistencies across chains, especially if this is used for cross-chain voting or timing-related logic.

##### **Example 2: Correct Use with `arbBlockNumber()` for Arbitrum**

```solidity
function vote(uint256 proposalId) public {
    require(ArbSys(address(100)).arbBlockNumber() >= proposals[proposalId].startBlock, "Voting hasn't started yet");
    require(ArbSys(address(100)).arbBlockNumber() <= proposals[proposalId].endBlock, "Voting has ended");
    // Vote logic
}
```

**Explanation:**
- On Arbitrum, the correct function `arbBlockNumber()` must be used instead of `block.number`, ensuring consistent timing logic across different Layer 2 environments.

#### **Task to Perform**

1. **Scan through smart contracts** for any usage of `block.number` using the regex.
2. **Manually verify** if the use of `block.number` is in the context of **timing**, **voting**, or other related operations.
3. Ensure that contracts either:
   - Use `arbBlockNumber()` for Arbitrum or another L2-specific solution.
   - Implement a **clock** for timing in L2 networks, as recommended by OpenZeppelin Contracts version 4.9.

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

## Output schema

```json
{
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "summary": {
        "type": "string",
        "description": "Brief summary of the vulnerability"
      },
      "severity": {
        "type": "string",
        "items": {
          "type": "string",
          "enum": ["high", "medium", "low"]
        },
        "description": "Severity level of the vulnerability"
      },
      "vulnerability_details": {
        "type": "object",
        "properties": {
          "function_name": {
            "type": "string",
            "description": "Function name where the vulnerability is found"
          },
          "description": {
            "type": "string",
            "description": "Detailed description of the vulnerability"
          }
        },
        "required": ["function_name", "description"]
      },
      "code_snippet": {
        "type": "array",
        "items": {
          "type": "string"
        },
        "description": "Code snippet showing the vulnerability",
        "default": []
      },
      "recommendation": {
        "type": "string",
        "description": "Recommendation to fix the vulnerability"
      }
    },
    "required": ["summary", "severity", "vulnerability_details", "code_snippet", "recommendation"]
  },
  "additionalProperties": false
}
```
