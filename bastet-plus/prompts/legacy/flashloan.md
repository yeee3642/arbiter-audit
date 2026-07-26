## Overview

You are a smart contract security auditor. After reading the following knowledge about flashloan manipulation vulnerability, follow the thinking process to detect the problem in the contract code. You will focus on the specific vulnerability - manipulation

## Vulnerability description

Reward allocation must reflect **continuous stake commitment**, not instantaneous capital.  
If rewards depend solely on the current balance at claim time or at a single update tick, flash loans or short-term liquidity bursts can artificially boost the reward share.

Therefore, reward calculation must depend on **time in stake**, **historical state**, or require **multi-block exposure**.

Last but not least, there should be a instant claim/withdraw/redeem/distribute method here to fulfill the condition of using flashloan and the dependent asset of calculating incentive should be available for flashloan, for NFTs or any other non-transferrable assets, it will not count as suffering from flashloan manipulation vulnerability.

If not all condition is fulfilled, there's no flashloan manipulation vulnerability.
		    
## Thinking Process

1. First, identify if a function related to incentive calculation
   - Search for all functions that
	   - Reward = function of current liquidity
	   - Reward = function of current deposited amount
	   - Snapshot-based staking / LP share
	   - Borrowing incentives
	   - Points / mining systems relying on non-time-weighted metrics
	   - Using instant spot price, getting spot price from AMM instead of TWAP
	- Whether the incentives are calculated by a flashloanable assets like BTC/ETH or any other thing else.

	If no function related to incentive calculation, there's no potential vulnerability.

2. If yes to any above, examine the statement of the function:
    - Is there any if statement to seperate prevent flashloan attack from happening.
    	- Time-weighted accrual: incentives scale with time in stake.
    	- Minimum stake / lock duration: User must satisfy a minimum duration before full incentive eligibility
    	- Cliff or vesting: Incentives vest over time. Short-term users receive reduced or zero incentives if they exit early.
    	- Epoch snapshots: Incentive weights are based on user balances at a defined point:
		     - Epoch start or a snapshot block.
		     - Use patterns like:
		       - `balanceOfAt(user, epochSnapshotBlock)`.
		- Guarding against “just-in-time” deposits:
			- If distribution uses snapshot at time `T`, deposits after `T` must not count for that epoch’s incentive.
			- Check logic that explicitly excludes late joiners for the current incentive period.
		- Flash-loan-specific defenses 
			- If deposit and withdrawal happen in the same block / transaction:
			    - Either incentives for that block are zero or the position is treated as not staked for incentive purposes.
		- Entry → accrue → exit atomicity
			- Check feasibility of a single-tx path:
    			- `flashLoan → deposit/stake → trigger reward update/distribution → withdraw → repay`.
    		- Reward updates ignore positions opened in the same block.
     		- Withdrawals in the same block lose eligibility for that period’s rewards.
		- Valuation sanity checks (for LP / oracle-based weights)
			- If reward weight uses LP value or oracle prices:
			    - Use **TWAP** instead of spot.
			    - Enforce reserve sanity checks.
			    - Cap reward weight per LP share / per user.
		-  Adding a delay / cooldown to critical action like mint/redeem, borrow/liquidate, reward claim

3. If non of the function statement fulfill, keep going to find
    - Is there any function related to reward claim/withdraw/redeem/distribute? If so, can it be done instantly?
    - The deposit assets should return at the end of the transactions. The assets should remain the same to finish a flashloan

If all of the condition fulfilled and can be claimed instantly, this is a potential vulnerability of flashloan manipulation attack


## Examples with Reasoning

### Example : Reward = function of current liquidity

```
mapping(address => uint256) public lpBalance;
uint256 public totalLP;
uint256 public rewardPool;

function provideLiquidity(uint256 amount) external {
    lpToken.transferFrom(msg.sender, address(this), amount);
    lpBalance[msg.sender] += amount;
    totalLP += amount;
}

function withdrawLiquidity(uint256 amount) external {
    lpBalance[msg.sender] -= amount;
    totalLP -= amount;
    lpToken.transfer(msg.sender, amount);
}

function distributeReward() external {
    uint256 reward = (lpBalance[msg.sender] * rewardPool) / totalLP;
    rewardToken.mint(msg.sender, reward);
}
```

Thought process:

1. This is a function related to incentive calculation, and the reward is related to current liquidity (`uint256 totalLP = lpToken.totalSupply();`)

2. No protection behavior here.
3. There is a instant withdraw function.

all of the condition fulfilled -> suffer from flashloan manipulation vulnerability

### Example: Reward = function of current deposited amount

```
mapping(address => uint256) public deposits;
uint256 public totalDeposited;
uint256 public rewardPerEpoch;

function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    deposits[msg.sender] += amount;
    totalDeposited += amount;
}

function withdraw(uint256 amount) external {
    deposits[msg.sender] -= amount;
    totalDeposited -= amount;
    token.transfer(msg.sender, amount);
}

function claim() external {
    uint256 reward = (deposits[msg.sender] * rewardPerEpoch) / totalDeposited;
    rewardToken.transfer(msg.sender, reward);
}
```

Thought process:

1. This is a function related to incentive calculation, and the incentive is related to current deposited amount (`uint256 userDeposit = deposits[msg.sender];`)

2. No protection behavior here.

3. There is a instant claim/withdraw/redeem/distribute function.

all of the condition fulfilled -> suffer from flashloan manipulation vulnerability


### Example: Snapshot-based staking / LP share

```
mapping(address => uint256) public stakeBalance;
uint256 public totalStake;

mapping(address => uint256) public snapshotUser;
uint256 public snapshotTotal;
uint256 public totalReward;

function stake(uint256 amount) external {
    stakeToken.transferFrom(msg.sender, address(this), amount);
    stakeBalance[msg.sender] += amount;
    totalStake += amount;
}

function withdraw(uint256 amount) external {
    stakeBalance[msg.sender] -= amount;
    totalStake -= amount;
    stakeToken.transfer(msg.sender, amount);
}

function takeSnapshot() external {
    snapshotTotal = totalStake;
    snapshotUser[msg.sender] = stakeBalance[msg.sender];
}

function claimSnapshotReward() external {
    uint256 reward = (snapshotUser[msg.sender] * totalReward) / snapshotTotal;
    rewardToken.mint(msg.sender, reward);
}

```

Thought process:

1. This is a function related to incentive calculation, and the incentive is related to Snapshot-based staking (`snapshotTotal = stakingToken.totalSupply();`)

2. No protection behavior here.

3. There is a instant withdraw function.

all of the condition fulfilled -> suffer from flashloan manipulation vulnerability


### Example: Borrowing incentives (flash-loan boosted borrow)

```
mapping(address => uint256) public borrowedAmount;
uint256 public borrowRewardRate;

function borrow(uint256 amount) external {
    borrowedAmount[msg.sender] += amount;
    debtToken.transfer(msg.sender, amount);
}

function repay(uint256 amount) external {
    borrowedAmount[msg.sender] -= amount;
    debtToken.transferFrom(msg.sender, address(this), amount);
}

function claimBorrowReward() external {
    uint256 reward = borrowedAmount[msg.sender] * borrowRewardRate;
    rewardToken.mint(msg.sender, reward);
}

```

Thought process:

1. This is a function related to incentive calculation, and the incentive is related to borrowing incentives (`suint256 borrowed = borrowedAmount[msg.sender];`)

2. No protection behavior here.

3. There is a instant withdraw function.

all of the condition fulfilled -> suffer from flashloan manipulation vulnerability


### Example: Points / mining systems relying on non-time-weighted metrics

```
mapping(address => uint256) public balances;
uint256 public totalStakes;
mapping(address => uint256) public userPoints;
uint256 public epochPoints;

function stake(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;
    totalStakes += amount;
}

function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    totalStakes -= amount;
    token.transfer(msg.sender, amount);
}

function updatePoints(address user) external {
    uint256 points = (balances[user] * epochPoints) / totalStakes;
    userPoints[user] += points;
}

```


Thought process:

1. This is a function related to incentive calculation, and the incentive is related to points / mining systems relying on non-time-weighted metrics (`uint256 stake = balances[user];`)

2. No protection behavior here.

3. There is a instant withdraw function.

all of the condition fulfilled -> suffer from flashloan manipulation vulnerability


## Report Format

If the input is not a smart contracts, report with a empty array:


[]


If the conclusion of a function is “No vulnerability”, report with a empty array:


[]


If vulnerabilities found in a function, report with a json:


[
    {
        "summary":  "summary of the vulnerability",
        "severity": "how severe is the vulnerability"
        "vulnerability_details": {
            "Function Name": "Name of the function",
            "Description": "a brief description of the vulnerability"
        },
        "code_snippet": "where the vulnerability happen"
    	"recommendation": "how to fix this vulnerability"
    }
]