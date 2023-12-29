// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/Create2.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./Walli.sol";

/**
 * Factory contract for Walli
 * A UserOperations "initCode" holds the address of the factory, and a method call (to createAccount, in this factory contract).
 * The factory's createAccount returns the target account address even if it is already installed.
 * This way, the entryPoint.getSenderAddress() can be called either before or after the account is created.
 */

contract WalliFactory {
    Walli immutable walli;

    constructor(
        address _entryPoint,
        address _walliShield,
        address _connext
    ) {
        walli = new Walli(
            _entryPoint,
            _walliShield,
            _connext
        );
    }

    /**
     * Calculate the counterfactual address of this account as it would be returned by createAccount()
     */
    function getComputeAddress(
        address _owner,
        uint256 _salt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                bytes32(_salt),
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            address(walli),
                            abi.encodeCall(Walli.initialize, (_owner))
                        )
                    )
                )
            );
    }

    /**
     * Create an account, and return its address.
     * Returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
     */
    function createAccount(
        address _owner,
        uint256 _salt
    ) public returns (Walli ret) {
        address addr = getComputeAddress(_owner, _salt);
        uint codeSize = addr.code.length;
        if (codeSize > 0) {
            return Walli(payable(addr));
        }
        ret = Walli(
            payable(
                new ERC1967Proxy{salt: bytes32(_salt)}(
                    address(walli),
                    abi.encodeCall(Walli.initialize, (_owner))
                )
            )
        );
    }
}
