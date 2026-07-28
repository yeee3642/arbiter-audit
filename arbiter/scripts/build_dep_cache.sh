#!/usr/bin/env bash
# Vendor the external Solidity libraries that real audit repositories actually import.
#
# Chosen from measurement, not guesswork: scripts/scan_imports.py counted every import
# across the 17 repositories OneSavie's own evaluation drew from. OpenZeppelin accounts
# for 355 of them, and the long tail is short -- forge-std, solmate, uniswap, chainlink.
# Everything else in that scan is repo-internal and resolves from the repo's own tree.
#
# Three OpenZeppelin majors are kept because the corpus spans 0.6 to 0.8.20+, and a
# contract pinned to ^0.6.12 cannot compile against OZ v5. The resolver picks by pragma.
set -u

CACHE="${1:-$HOME/soldeps}"
mkdir -p "$CACHE"
cd "$CACHE" || exit 1

clone() {  # clone <dir> <url> <tag>
  local dir="$1" url="$2" tag="$3"
  if [ -d "$dir/.git" ]; then
    echo "  have  $dir"
    return 0
  fi
  rm -rf "$dir"
  if git clone --quiet --depth 1 --branch "$tag" "$url" "$dir" 2>/dev/null; then
    echo "  ok    $dir @ $tag"
  else
    echo "  FAIL  $dir @ $tag"
    return 1
  fi
}

echo "vendoring solidity dependencies into $CACHE"

clone openzeppelin-v5   https://github.com/OpenZeppelin/openzeppelin-contracts.git             v5.0.2
clone openzeppelin-v4   https://github.com/OpenZeppelin/openzeppelin-contracts.git             v4.9.6
clone openzeppelin-v3   https://github.com/OpenZeppelin/openzeppelin-contracts.git             v3.4.2
clone openzeppelin-up-v5 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git v5.0.2
clone openzeppelin-up-v4 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git v4.9.6
clone openzeppelin-up-v3 https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git v3.4.2
clone forge-std         https://github.com/foundry-rs/forge-std.git                            v1.9.4
clone solmate           https://github.com/transmissions11/solmate.git                         v7
clone uniswap-v2-core   https://github.com/Uniswap/v2-core.git                                 v1.0.1
clone uniswap-v2-periphery https://github.com/Uniswap/v2-periphery.git                         master
clone uniswap-v3-core   https://github.com/Uniswap/v3-core.git                                 v1.0.0
clone uniswap-v3-periphery https://github.com/Uniswap/v3-periphery.git                         v1.3.0
clone chainlink         https://github.com/smartcontractkit/chainlink-brownie-contracts.git    v0.8.0

# hardhat/console.sol is a debug shim with no package worth cloning; contracts import it
# and it must exist or the closure fails to resolve. Writing it is exact, not a stub:
# console.log is a no-op staticcall to a fixed address on every EVM.
mkdir -p hardhat-shim/hardhat
cat > hardhat-shim/hardhat/console.sol <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity >=0.4.22 <0.9.0;

/// Minimal hardhat/console.sol. The real one dispatches to address(0x000...636F4473)
/// which is a no-op outside the Hardhat EVM, so an empty body is behaviourally identical
/// under forge and keeps the import closure resolvable.
library console {
    function log() internal pure {}
    function log(string memory) internal pure {}
    function log(string memory, uint256) internal pure {}
    function log(string memory, string memory) internal pure {}
    function log(string memory, address) internal pure {}
    function log(string memory, bool) internal pure {}
    function log(uint256) internal pure {}
    function log(address) internal pure {}
    function log(bool) internal pure {}
    function logUint(uint256) internal pure {}
    function logString(string memory) internal pure {}
    function logAddress(address) internal pure {}
}
SOL
echo "  ok    hardhat-shim"

echo
du -sh "$CACHE" 2>/dev/null
ls "$CACHE"
