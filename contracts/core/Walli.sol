// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.20;

import {IConnext} from "@connext/interfaces/core/IConnext.sol";
import {IXReceiver} from "@connext/interfaces/core/IXReceiver.sol";

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import "../interfaces/IAccount.sol";
import "./BaseAccount.sol";
import "hardhat/console.sol";

// contract WalliLayout {// }

contract Walli is
    BaseAccount,
    Initializable,
    UUPSUpgradeable,
    IXReceiver,
    ReentrancyGuard
{
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;

    address public owner;
    bytes32 public ownerName;
    IConnext public immutable connext;

    uint256 private nativeLimit;
    address private immutable walliShield;
    bytes32 private hashedEmail;
    uint256 private lockRelease;
    uint256 private nonce;
    address private immutable entryPoint;
    uint private constant maxGuardian = 5;
    uint256 private constant lockPeriod = 7 * 24 * 60 * 60;
    uint256 private constant recoveryPeriod = 5 * 24 * 60 * 60;
    uint256 private constant guardianSecurityPeriod = 24 * 60 * 60;

    bytes32 private immutable selectorRecovery =
        keccak256(abi.encodePacked("initiateRecovery"));
    bytes32 internal immutable selector2FA =
        keccak256(abi.encodePacked("initiate2FARemoval"));
    bytes32 internal immutable selectorGuardianAddition =
        keccak256(abi.encodePacked("initiateGuardianAddition"));
    bytes32 internal immutable selectorGuardianRemoval =
        keccak256(abi.encodePacked("initiateGuardianRemoval"));

    struct Profile {
        address addr;
        bytes32 name;
    }

    struct RequestConfig {
        Profile profile;
        uint256 finaliseAfter;
        bytes32 selector;
    }

    EnumerableSet.AddressSet private authorisedGuardians;
    EnumerableSet.AddressSet private trustedContacts;
    EnumerableSet.Bytes32Set private sessions;
    EnumerableSet.AddressSet private confirmedRecovery;
    EnumerableSet.AddressSet private cancelledRecovery;
    EnumerableSet.AddressSet private confirmed2FARemoval;
    EnumerableSet.AddressSet private cancelled2FARemoval;
    EnumerableSet.Bytes32Set private pendingGuardianAdditions;
    EnumerableSet.Bytes32Set private pendingGuardianRemovals;

    mapping(bytes32 => RequestConfig) private pendingRequests;
    mapping(address => uint256) private tokenLimits;
    mapping(address => bytes32) private guardianNames;
    mapping(address => bytes32) private trustedContactNames;
    mapping(bytes32 => uint256) private sessionExpiry;

    // *************** Events ************************ //

    event DepositAdded(address indexed _wallet, uint _amount);
    event DepositWithdrawed(address indexed _wallet, uint _amount);
    event Received(address indexed _wallet, address _sender, uint _amount);
    event Transfer(
        address indexed _wallet,
        string _selector,
        address _receiver,
        uint amount,
        address _token,
        string _type
    );
    event Execute(
        address indexed _wallet,
        string _selector,
        address _receiver,
        uint amount,
        bytes _callData
    );
    event XReceived(
        address indexed _wallet,
        bytes32 _transferId,
        uint256 _amount,
        address _asset,
        address _originSender,
        uint32 _originDomain,
        bytes _callData
    );

    // *************** Modifiers ************************ //

    modifier onlyOwner() {
        require(msg.sender == owner, "Walli: Must be Owner");
        _;
    }

    /**
     * @notice Throws if the caller is not a guardian for the wallet or the module itself.
     */
    modifier onlyGuardian() {
        require(isGuardian(msg.sender), "Walli: Must be Guardian");
        _;
    }

    modifier onlyGuardianOrOwner() {
        require(
            msg.sender == owner || isGuardian(msg.sender),
            "Walli: Must be Guardian or Owner"
        );
        _;
    }

    modifier onlyEntryPointOrOwner() {
        require(
            msg.sender == address(getEntryPoint()) || msg.sender == owner,
            "Walli: Not Owner or EntryPoint"
        );
        _;
    }

    modifier onlyWalli() {
        require(msg.sender == walliShield, "Walli: Not walli shield");
        _;
    }

    modifier onlyOwnerOrGuardianOrEntryPoint() {
        require(
            msg.sender == owner ||
                msg.sender == address(getEntryPoint()) ||
                isGuardian(msg.sender),
            "Walli: Only Owner or Entry Point or Guardian"
        );
        _;
    }

    modifier onlyEntryPointOrOwnerOrWalli() {
        require(
            msg.sender == address(getEntryPoint()) ||
                msg.sender == owner ||
                msg.sender == walliShield,
            "Walli: Not Owner or EntryPoint"
        );
        _;
    }

    /// @notice Throws if the wallet is not locked.
    modifier onlyWhenLocked() {
        require(_isLocked(), "Walli: Wallet must be locked");
        _;
    }

    /**
     * @notice Throws if the wallet is locked.
     */
    modifier onlyWhenUnlocked() {
        require(!_isLocked(), "Walli: Wallet is locked");
        _;
    }

    modifier validSession(bytes32 _key) {
        require(
            hashedEmail == bytes32(0) || isValidSession(_key),
            "Walli: Invalid session"
        );
        _;
    }

    modifier onlyWhenPendingRecovery() {
        require(
            pendingRequests[selectorRecovery].finaliseAfter > 0,
            "Walli: No recovery pending request"
        );
        _;
    }

    modifier notWhenPendingRecovery() {
        require(
            pendingRequests[selectorRecovery].finaliseAfter == 0 ||
                pendingRequests[selectorRecovery].finaliseAfter <
                block.timestamp,
            "Walli: Recovery request still pending"
        );
        _;
    }

    modifier onlyWhenPending2FARemoval() {
        require(
            pendingRequests[selector2FA].finaliseAfter > 0,
            "Walli: No 2FA removal pending request"
        );
        _;
    }

    modifier notWhenPending2FARemoval() {
        require(
            pendingRequests[selector2FA].finaliseAfter == 0 ||
                pendingRequests[selector2FA].finaliseAfter < block.timestamp,
            "Walli: 2FA removal request still pending"
        );
        _;
    }

    receive() external payable {
        if (msg.value > 0) emit Received(address(this), msg.sender, msg.value);
    }

    constructor(address _entryPoint, address _walliShield, address _connext) {
        require(
            _entryPoint != address(0) && _walliShield != address(0),
            "Walli: Non zero address check"
        );
        entryPoint = _entryPoint;
        walliShield = _walliShield;
        connext = IConnext(_connext);
        _setOwner(address(0));
        _disableInitializers();
    }

    // *************** Internal functions ************************ //

    function _initialize(address _owner) internal {
        owner = _owner;
    }

    function _setOwner(address _newOwner) internal {
        owner = _newOwner;
    }

    function _call(
        address _target,
        uint256 _value,
        bytes memory _data
    ) internal nonReentrant returns (bytes memory) {
        (bool _success, bytes memory _result) = _target.call{value: _value}(
            _data
        );
        if (!_success) {
            assembly {
                revert(add(_result, 32), mload(_result))
            }
        }
        return _result;
    }

    /// @inheritdoc BaseAccount
    function _validateAndUpdateNonce(
        UserOperation calldata _userOp
    ) internal override {
        require(nonce++ == _userOp.nonce, "Walli: Invalid nonce");
    }

    function _validateUserOpWithHash(
        bytes32 _hash,
        bytes calldata _signatures
    ) internal view returns (uint256 _validationData) {
        uint8 _v;
        bytes32 _r;
        bytes32 _s;
        uint _count = _signatures.length / 65;
        require(_count == 2, "Walli: Invalid signatures");

        uint _valid = 0;
        address _lastSigner = address(0);
        for (uint _i = 0; _i < _count; _i++) {
            (_v, _r, _s) = _splitSignature(_signatures, _i);
            address _recovered = _hash.recover(_v, _r, _s);
            require(
                _recovered != _lastSigner,
                "Walli: Duplicate signees"
            ); // make sure signers are different
            _lastSigner = _recovered;
            if (_recovered == owner || _recovered == walliShield) _valid += 1;
        }

        if (_valid != _count) return SIG_VALIDATION_FAILED;

        return 0;
    }

    /// @inheritdoc BaseAccount
    function _validateSignature(
        UserOperation calldata _userOp,
        bytes32 _userOpHash
    ) internal view override returns (uint256 _validationData) {
        bytes32 _hash = _userOpHash.toEthSignedMessageHash();
        if (_userOp.signature.length == 65) {
            if (owner != _hash.recover(_userOp.signature))
                return SIG_VALIDATION_FAILED;
            return 0;
        } else return _validateUserOpWithHash(_hash, _userOp.signature);
    }

    function _splitSignature(
        bytes memory _signatures,
        uint256 _index
    ) internal pure returns (uint8 _v, bytes32 _r, bytes32 _s) {
        // we jump 32 (0x20) as the first slot of bytes contains the length
        // we jump 65 (0x41) per signature
        // for v we load 32 bytes ending with v (the first 31 come from s) tehn apply a mask
        assembly {
            _r := mload(add(_signatures, add(0x20, mul(0x41, _index))))
            _s := mload(add(_signatures, add(0x40, mul(0x41, _index))))
            _v := and(
                mload(add(_signatures, add(0x41, mul(0x41, _index)))),
                0xff
            )
        }
        require(_v == 27 || _v == 28, "Walli: Invalid v");
    }

    function validate2FASignatures(
        string memory _selector,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    ) internal view {
        require(
            _messageHash ==
                keccak256(
                    abi.encodePacked(_selector, entryPoint, _chainId, nonce)
                ),
            "Walli: Invalid message hash"
        );
        require(
            _signatures.length == 2 * 65,
            "Walli: Invalid signature length"
        );

        uint256 _valid = _validateUserOpWithHash(
            _messageHash.toEthSignedMessageHash(),
            _signatures
        );
        if (_valid == SIG_VALIDATION_FAILED)
            revert("Walli: Signature verification failed");
    }

    function _validateNewOwner(address _newOwner) internal view {
        require(
            _newOwner != owner && _newOwner != address(0) && _newOwner != address(this),
            "Walli: New owner cannot be existing owner or null or Walli"
        );
        require(!isGuardian(_newOwner), "Walli: New owner cannot be guardian");
    }

    /// @notice Helper method to check if a wallet is locked.
    function _isLocked() internal view returns (bool) {
        return lockRelease > block.timestamp;
    }

    function _setLock(uint256 _lockRelease) internal {
        lockRelease = _lockRelease;
    }

    function _deleteRecoveryRequest() internal {
        delete pendingRequests[selectorRecovery];
        while (EnumerableSet.length(confirmedRecovery) > 0) {
            EnumerableSet.remove(
                confirmedRecovery,
                EnumerableSet.at(confirmedRecovery, 0)
            );
        }
        while (EnumerableSet.length(cancelledRecovery) > 0) {
            EnumerableSet.remove(
                cancelledRecovery,
                EnumerableSet.at(cancelledRecovery, 0)
            );
        }
        _setLock(0);
        clearAllSessions(); // @TODO
    }

    function _delete2FARemovalRequest() internal {
        delete pendingRequests[selector2FA];
        while (EnumerableSet.length(confirmed2FARemoval) > 0) {
            EnumerableSet.remove(
                confirmed2FARemoval,
                EnumerableSet.at(confirmed2FARemoval, 0)
            );
        }
        while (EnumerableSet.length(cancelled2FARemoval) > 0) {
            EnumerableSet.remove(
                cancelled2FARemoval,
                EnumerableSet.at(cancelled2FARemoval, 0)
            );
        }
        _setLock(0);
        clearAllSessions(); // @TODO
    }

    function _removeOldSession() internal {
        bytes32 _key = EnumerableSet.at(sessions, 0);
        EnumerableSet.remove(sessions, _key);
        delete sessionExpiry[_key];
    }

    function _authorizeUpgrade(address) internal view override onlyOwner {}

    // *************** Public & External functions ************************ //

    // *************** Initialise and Entry Point Interaction ************************ //

    /// @inheritdoc BaseAccount
    function getNonce() public view override returns (uint256) {
        return nonce;
    }

    /// @inheritdoc BaseAccount
    function getEntryPoint() public view override returns (address) {
        return entryPoint;
    }

    function initialize(address _owner) public initializer {
        _initialize(_owner);
    }

    function setOnwerName(
        bytes32 _ownerName
    ) external onlyOwner onlyWhenUnlocked {
        ownerName = _ownerName;
    }

    /**
     * Check current account deposit in the entryPoint
     */
    function getDeposit() public onlyOwner returns (bytes memory) {
        return
            _call(
                entryPoint,
                0,
                abi.encodePacked("balanceOf(address)", address(this))
            );
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        _call(
            entryPoint,
            msg.value,
            abi.encodePacked("depositTo(address)", address(this))
        );
        emit DepositAdded(address(this), msg.value);
    }

    /**
     * withdraw value from the account's deposit
     * @param _withdrawAddress target to send to
     * @param _amount to withdraw
     */
    function withdrawDepositTo(
        address payable _withdrawAddress,
        uint256 _amount
    ) public onlyOwner {
        _call(
            entryPoint,
            0,
            abi.encodePacked(
                "withdrawTo(address, uint256)",
                _withdrawAddress,
                _amount
            )
        );
        emit DepositWithdrawed(address(this), _amount);
    }

    // *************** Execute functions ************************ //

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(
        address _dest,
        uint256 _value,
        bytes calldata _func,
        bytes32 _key,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    ) external onlyEntryPointOrOwner onlyWhenUnlocked validSession(_key) {
        if (is2FAEnabled())
            validate2FASignatures(
                "execute",
                _chainId,
                _messageHash,
                _signatures
            );
        _call(_dest, _value, _func);
        emit Execute(address(this), "execute", _dest, _value, _func);
    }

    /**
     * Execute a sequence of transactions (called directly from owner, or by entryPoint)
     */
    function executeBatch(
        address[] calldata _dest,
        bytes[] calldata _func,
        bytes32 _key,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    ) external onlyEntryPointOrOwner onlyWhenUnlocked validSession(_key) {
        require(_dest.length == _func.length, "Walli: Wrong array lengths");
        if (is2FAEnabled())
            validate2FASignatures(
                "executeBatch",
                _chainId,
                _messageHash,
                _signatures
            );
        for (uint256 _i = 0; _i < _dest.length; _i++) {
            _call(_dest[_i], 0, _func[_i]);
            emit Execute(
                address(this),
                "executeBatch",
                _dest[_i],
                0,
                _func[_i]
            );
        }
    }

    function sendNative(
        address _to,
        uint _amount,
        bytes32 _key,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    )
        external
        onlyEntryPointOrOwner
        onlyWhenUnlocked
        validSession(_key)
        nonReentrant
    {
        require(_to != address(0), "Walli: Invalid recepient");
        require(
            address(this).balance >= _amount,
            "Walli: Insufficent chain's native token balance. Please deposit native token of chain into smart wallet first"
        );
        require(
            EnumerableSet.contains(trustedContacts, _to) ||
                _amount <= nativeLimit,
            "Walli: Amount exceeds native token transfer limit"
        );
        if (is2FAEnabled())
            validate2FASignatures(
                "sendNative",
                _chainId,
                _messageHash,
                _signatures
            );

        payable(_to).transfer(_amount);
        emit Transfer(
            address(this),
            "sendNative",
            _to,
            _amount,
            address(0),
            "native"
        );
    }

    function sendToken(
        address _token,
        address _to,
        uint _amount,
        bytes32 _key,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    )
        external
        onlyEntryPointOrOwner
        onlyWhenUnlocked
        validSession(_key)
        nonReentrant
    {
        require(_to != address(0), "Walli: Invalid recepient");
        require(
            IERC20(_token).balanceOf(address(this)) >= _amount,
            "Walli: Insufficent token balance. Please deposit token into smart wallet first"
        );
        require(
            EnumerableSet.contains(trustedContacts, _to) ||
                _amount <= tokenLimits[_token],
            "Walli: Amount exceeds token transfer limit"
        );
        if (is2FAEnabled())
            validate2FASignatures(
                "sendToken",
                _chainId,
                _messageHash,
                _signatures
            );

        IERC20(_token).transfer(_to, _amount);
        emit Transfer(
            address(this),
            "sendToken",
            _to,
            _amount,
            _token,
            "erc20"
        );
    }

    /**
     * @notice Transfers non-native assets from one chain to another.
     * @dev User should approve a spending allowance before calling this.
     * @param _tokenAddress Address of the token on this domain.
     * @param _amount The amount to transfer.
     * @param _recipient The destination address (e.g. a wallet).
     * @param _destinationDomain The destination domain ID.
     * @param _slippage The maximum amount of slippage the user will accept in BPS.
     * @param _relayerFee The fee offered to relayers.
     */
    function xTransfer(
        address _tokenAddress,
        uint256 _amount,
        address _recipient,
        uint32 _destinationDomain,
        uint256 _slippage,
        uint256 _relayerFee,
        bytes32 _key,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    )
        external
        payable
        onlyEntryPointOrOwner
        onlyWhenUnlocked
        validSession(_key)
        nonReentrant
    {
        if (is2FAEnabled())
            validate2FASignatures(
                "xTransfer",
                _chainId,
                _messageHash,
                _signatures
            );

        // require(msg.value >= _relayerFee, "Walli: Invalid call data value");
        require(
            EnumerableSet.contains(trustedContacts, _recipient) ||
                _amount <= tokenLimits[_tokenAddress],
            "Walli: Amount exceeds token transfer limit"
        );

        IERC20 _token = IERC20(_tokenAddress);
        require(
            _token.balanceOf(address(this)) >= _amount,
            "Walli: Insufficient token balance. First deposit sufficent given token into Walli."
        );

        // This contract approves transfer to Connext
        _token.approve(address(connext), _amount);

        try
            connext.xcall{value: _relayerFee}(
                _destinationDomain, // _destination: Domain ID of the destination chain
                _recipient, // _to: address receiving the funds on the destination
                _tokenAddress, // _asset: address of the token contract
                msg.sender, // _delegate: address that can revert or forceLocal on destination
                _amount, // _amount: amount of tokens to transfer
                _slippage, // _slippage: the maximum amount of slippage the user will accept in BPS (e.g. 30 = 0.3%)
                bytes("") // _callData: empty bytes because we're only sending funds
            )
        {} catch Error(string memory reason) {
            revert(reason);
        } catch {
            revert(
                "No error data generated"
            );
        }
        emit Transfer(
            address(this),
            "xTransfer",
            _recipient,
            _amount,
            _tokenAddress,
            "erc20"
        );
    }

    /// @notice for receving tokens cross chain
    function xReceive(
        bytes32 _transferId,
        uint256 _amount,
        address _asset,
        address _originSender,
        uint32 _originDomain,
        bytes memory _callData
    ) external returns (bytes memory) {
        emit XReceived(
            address(this),
            _transferId,
            _amount,
            _asset,
            _originSender,
            _originDomain,
            _callData
        );
        return "success";
    }

    // *************** Recovery functions ************************ //

    /**
     * @notice Lets the guardians initiate the recovery procedure.
     * Once triggered the recovery is finaliseAfter for the recovery period before it can be finalised.
     * Must be confirmed by N guardians, where N = ceil(Nb Guardians / 2).
     * @param _recoveryOwner The address to which ownership should be transferred.
     */
    function initiateRecovery(
        address _recoveryOwner
    ) external onlyGuardian notWhenPendingRecovery {
        _deleteRecoveryRequest();
        _validateNewOwner(_recoveryOwner);
        pendingRequests[selectorRecovery].selector = selectorRecovery;
        pendingRequests[selectorRecovery].profile = Profile(
            _recoveryOwner,
            bytes32(0)
        );
        pendingRequests[selectorRecovery].finaliseAfter =
            block.timestamp +
            recoveryPeriod;
        _setLock(block.timestamp + lockPeriod);
    }

    function confirmRecovery() external onlyGuardian onlyWhenPendingRecovery {
        require(
            !EnumerableSet.contains(confirmedRecovery, msg.sender),
            "Walli: Recovery already confirmed"
        );
        EnumerableSet.add(confirmedRecovery, msg.sender);
        EnumerableSet.remove(cancelledRecovery, msg.sender);
    }

    /**
     * @notice Lets the owner cancel an ongoing recovery procedure.
     * Must be confirmed by N guardians, where N = ceil(Nb Guardian at initiateRecovery + 1) / 2) - 1.
     */
    function cancelRecovery() external onlyGuardian onlyWhenPendingRecovery {
        require(
            !EnumerableSet.contains(cancelledRecovery, msg.sender),
            "Walli: Recovery already cancelled"
        );
        EnumerableSet.add(cancelledRecovery, msg.sender);
        EnumerableSet.remove(confirmedRecovery, msg.sender);
        if (
            EnumerableSet.length(cancelledRecovery) >=
            Math.ceilDiv(EnumerableSet.length(authorisedGuardians), 2)
        ) _deleteRecoveryRequest();
    }

    /// @notice Finalizes an ongoing recovery procedure if the recovery period is over and current time is before security window as finalising a recovery can not be for infinity.
    function finaliseRecovery() external onlyGuardian onlyWhenPendingRecovery {
        require(
            block.timestamp > pendingRequests[selectorRecovery].finaliseAfter,
            "Walli: Ongoing recovery period"
        );
        require(
            EnumerableSet.length(confirmedRecovery) >=
                Math.ceilDiv(EnumerableSet.length(authorisedGuardians), 2),
            "Walli: Recovery confirmation still pending from guardians"
        );
        _setOwner(pendingRequests[selectorRecovery].profile.addr);
        _deleteRecoveryRequest();
    }

    /// @notice Gets the details of the ongoing recovery procedure if any.
    function getRecovery()
        external
        view
        onlyGuardianOrOwner
        onlyWhenPendingRecovery
        returns (
            address _recoveryOwner,
            uint256 _finaliseAfter,
            uint256 _guardianCount,
            uint256 _confirmedCount,
            uint256 _cancelledCount
        )
    {
        return (
            pendingRequests[selectorRecovery].profile.addr,
            pendingRequests[selectorRecovery].finaliseAfter,
            EnumerableSet.length(authorisedGuardians),
            EnumerableSet.length(confirmedRecovery),
            EnumerableSet.length(cancelledRecovery)
        );
    }

    // *************** Lock functions ************************ //

    /// @notice Lets a guardian or owner lock a wallet.
    function lock() external onlyGuardianOrOwner onlyWhenUnlocked {
        _setLock(block.timestamp + lockPeriod);
    }

    /// @notice Lets a guardian or owner unlock a locked wallet.
    function unlock()
        external
        onlyGuardianOrOwner
        onlyWhenLocked
        notWhenPendingRecovery
        notWhenPending2FARemoval
    {
        _setLock(0);
    }

    /**
     * @notice Returns the release time of a wallet lock or 0 if the wallet is unlocked.
     * @return _lockRelease The epoch time at which the lock will release (in seconds).
     */
    function getLock()
        external
        view
        onlyGuardianOrOwner
        returns (uint256 _lockRelease)
    {
        return _isLocked() ? lockRelease : 0;
    }

    // *************** Guardian functions ************************ //

    /**
     * @notice Lets the owner add a guardian to its wallet.
     * @param _guardian The guardian to add.
     */
    function initiateGuardianAddition(
        address _guardian,
        bytes32 _name
    ) external onlyOwner onlyWhenUnlocked {
        require(
            _guardian != owner &&
                _guardian != address(0) &&
                _guardian != address(this),
            "Walli: Guardian cannot be owner or null or Walli"
        );
        require(!isGuardian(_guardian), "Walli: Duplicate guardian");
        require(
            EnumerableSet.length(authorisedGuardians) < maxGuardian,
            "Walli: Max 5 guardians allowed"
        );

        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianAddition", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter == 0,
            "Walli: Guardian addition already initiated"
        );
        pendingRequests[_id].selector = selectorGuardianAddition;
        pendingRequests[_id].profile = Profile(_guardian, _name);
        pendingRequests[_id].finaliseAfter =
            block.timestamp +
            guardianSecurityPeriod;
        EnumerableSet.add(pendingGuardianAdditions, _id);
    }

    function getPendingGuardianAdditions()
        external
        view
        onlyOwner
        returns (RequestConfig[] memory _pending, uint _currentCount)
    {
        _pending = new RequestConfig[](maxGuardian);
        _currentCount = EnumerableSet.length(pendingGuardianAdditions);
        for (
            uint _i = 0;
            _i < EnumerableSet.length(pendingGuardianAdditions);
            _i++
        ) {
            bytes32 _id = EnumerableSet.at(pendingGuardianAdditions, _i);
            _pending[_i] = pendingRequests[_id];
        }
    }

    function cancelGuardianAddition(
        address _guardian
    ) external onlyOwner onlyWhenUnlocked {
        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianAddition", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter > 0,
            "Walli: No guardian addition initiated"
        );
        delete pendingRequests[_id];
        EnumerableSet.remove(pendingGuardianAdditions, _id);
    }

    function finaliseGuardianAddition(
        address _guardian
    ) external onlyOwner onlyWhenUnlocked {
        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianAddition", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter > 0,
            "Walli: No guardian addition initiated"
        );
        require(
            block.timestamp > pendingRequests[_id].finaliseAfter,
            "Walli: Ongoing security period"
        );

        EnumerableSet.add(authorisedGuardians, _guardian);
        guardianNames[_guardian] = pendingRequests[_id].profile.name;
        delete pendingRequests[_id];
        EnumerableSet.remove(pendingGuardianAdditions, _id);
    }

    /**
     * @notice Lets the owner revoke a guardian from its wallet.
     * @param _guardian The guardian to revoke.
     */
    function initiateGuardianRemoval(
        address _guardian,
        bytes32 _name
    ) external onlyOwner onlyWhenUnlocked {
        require(isGuardian(_guardian), "Walli: Guardian does not exist");
        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianRemoval", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter == 0,
            "Walli: Guardian removal already initiated"
        );
        pendingRequests[_id].selector = selectorGuardianRemoval;
        pendingRequests[_id].profile = Profile(_guardian, _name);
        pendingRequests[_id].finaliseAfter =
            block.timestamp +
            guardianSecurityPeriod;
        EnumerableSet.add(pendingGuardianRemovals, _id);
    }

    function cancelGuardianRemoval(
        address _guardian
    ) external onlyOwner onlyWhenUnlocked {
        require(isGuardian(_guardian), "Walli: Guardian does not exist");
        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianRemoval", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter > 0,
            "Walli: No guardian removal initiated"
        );
        delete pendingRequests[_id];
        EnumerableSet.remove(pendingGuardianRemovals, _id);
    }

    function getPendingGuardianRemovals()
        external
        view
        onlyOwner
        returns (RequestConfig[] memory _pending, uint _currentCount)
    {
        _pending = new RequestConfig[](maxGuardian);
        _currentCount = EnumerableSet.length(pendingGuardianRemovals);
        for (
            uint _i = 0;
            _i < EnumerableSet.length(pendingGuardianRemovals);
            _i++
        ) {
            bytes32 _id = EnumerableSet.at(pendingGuardianRemovals, _i);
            _pending[_i] = pendingRequests[_id];
        }
    }

    function finaliseGuardianRemoval(
        address _guardian
    ) external onlyOwner onlyWhenUnlocked {
        bytes32 _id = keccak256(
            abi.encodePacked("initiateGuardianRemoval", _guardian)
        );
        require(
            pendingRequests[_id].finaliseAfter > 0,
            "Walli: No guardian removal initiated"
        );
        require(
            block.timestamp > pendingRequests[_id].finaliseAfter,
            "Walli: Ongoing security period"
        );

        EnumerableSet.remove(authorisedGuardians, _guardian);
        delete guardianNames[_guardian];
        delete pendingRequests[_id];
        EnumerableSet.remove(pendingGuardianRemovals, _id);
    }

    /**
     * @notice Checks if an address is a guardian for a wallet.
     * @param _guardian The address to check.
     * @return _isGuardian `true` if the address is a guardian for the wallet otherwise `false`.
     */
    function isGuardian(
        address _guardian
    ) public view returns (bool _isGuardian) {
        require(
            msg.sender == owner ||
                EnumerableSet.contains(authorisedGuardians, msg.sender),
            "Walli: Only Guardian or owner"
        );
        return EnumerableSet.contains(authorisedGuardians, _guardian);
    }

    /**
     * @notice Get the active guardians for a wallet.
     * @return _authorisedGuardians the active guardians for a wallet.
     */
    function getGuardians()
        external
        view
        onlyGuardianOrOwner
        returns (Profile[] memory _authorisedGuardians, uint _currentCount)
    {
        _authorisedGuardians = new Profile[](maxGuardian);
        _currentCount = EnumerableSet.length(authorisedGuardians);
        for (
            uint _i = 0;
            _i < EnumerableSet.length(authorisedGuardians);
            _i++
        ) {
            address _addr = EnumerableSet.at(authorisedGuardians, _i);
            _authorisedGuardians[_i] = (Profile(_addr, guardianNames[_addr]));
        }
    }

    // *************** Trusted contacts functions ************************ //

    function addTrustedContact(
        address _contact,
        bytes32 _name
    ) external onlyOwner onlyWhenUnlocked {
        require(
            _contact != address(0) && _contact != address(this),
            "Walli: Contact cannot be null or Walli"
        );
        require(!isTrustedContact(_contact), "Walli: Duplicate contact");
        EnumerableSet.add(trustedContacts, _contact);
        trustedContactNames[_contact] = _name;
    }

    function removeTrustedContact(
        address _contact
    ) external onlyOwner onlyWhenUnlocked {
        require(
            isTrustedContact(_contact),
            "Walli: Must be existing trusted contact"
        );
        EnumerableSet.remove(trustedContacts, _contact);
        delete trustedContactNames[_contact];
    }

    /**
     * @notice Checks if an address is a trusted contact for a wallet.
     * @param _contact The address to check.
     * @return _isTrustedContact `true` if the address is a trusted contact for the wallet otherwise `false`.
     */
    function isTrustedContact(
        address _contact
    ) public view onlyEntryPointOrOwner returns (bool _isTrustedContact) {
        return EnumerableSet.contains(trustedContacts, _contact);
    }

    /**
     * @notice Get the active trusted contacts for a wallet.
     * @return _trustedContacts the active trusted contacts for a wallet.
     */
    function getTrustedContacts(
        uint256 start
    )
        external
        view
        onlyOwner
        returns (Profile[] memory _trustedContacts, uint _currentCount)
    {
        _trustedContacts = new Profile[](start + 5);
        _currentCount = EnumerableSet.length(trustedContacts);
        for (
            uint _i = start;
            _i < start + 5 && _i < EnumerableSet.length(trustedContacts);
            _i++
        ) {
            address _addr = EnumerableSet.at(trustedContacts, _i);
            _trustedContacts[_i - start] = (
                Profile(_addr, trustedContactNames[_addr])
            );
        }
    }

    // *************** Session functions ************************ //

    function is2FAEnabled()
        public
        view
        onlyOwnerOrGuardianOrEntryPoint
        returns (bool _is2FAEnabled)
    {
        return hashedEmail != bytes32(0);
    }

    function addSession(
        bytes32 _hashedEmail,
        bytes32 _key,
        uint256 _expiry,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures
    ) external onlyOwner {
        require(is2FAEnabled(), "Walli: 2FA is not enabled");
        require(_hashedEmail == hashedEmail, "Walli: Invalid email");
        require(!isValidSession(_key), "Walli: Duplicate session");
        validate2FASignatures(
            "addSession",
            _chainId,
            _messageHash,
            _signatures
        );

        if (EnumerableSet.length(sessions) >= 2) _removeOldSession();
        EnumerableSet.add(sessions, _key);
        sessionExpiry[_key] = _expiry;
    }

    function enable2FA(
        bytes32 _hashedEmail,
        uint256 _chainId,
        bytes32 _messageHash,
        bytes calldata _signatures,
        bytes32 _key, 
        uint256 _expiry
    ) external onlyOwner {
        require(hashedEmail == bytes32(0), "Walli: 2FA is already enabled");
        require(!isValidSession(_key), "Walli: Duplicate session");
        validate2FASignatures("enable2FA", _chainId, _messageHash, _signatures);
        
        hashedEmail = _hashedEmail;
        if (EnumerableSet.length(sessions) >= 2) _removeOldSession();
        EnumerableSet.add(sessions, _key);
        sessionExpiry[_key] = _expiry;
    }

    function clearAllSessions() public onlyGuardianOrOwner {
        while (EnumerableSet.length(sessions) > 0) {
            bytes32 _key = EnumerableSet.at(sessions, 0);
            EnumerableSet.remove(sessions, _key);
            delete sessionExpiry[_key];
        }
    }

    function initiate2FARemoval()
        external
        onlyGuardian
        notWhenPending2FARemoval
    {
        require(is2FAEnabled(), "Walli: 2FA is not enabled");
        _delete2FARemovalRequest();
        pendingRequests[selector2FA].selector = selector2FA;
        pendingRequests[selector2FA].finaliseAfter =
            block.timestamp +
            recoveryPeriod;
        _setLock(block.timestamp + lockPeriod);
    }

    function confirm2FARemoval()
        external
        onlyGuardian
        onlyWhenPending2FARemoval
    {
        require(
            !EnumerableSet.contains(confirmed2FARemoval, msg.sender),
            "Walli: 2FA removal already confirmed"
        );
        EnumerableSet.add(confirmed2FARemoval, msg.sender);
        EnumerableSet.remove(cancelled2FARemoval, msg.sender);
    }

    function cancel2FARemoval()
        external
        onlyGuardian
        onlyWhenPending2FARemoval
    {
        require(
            !EnumerableSet.contains(cancelled2FARemoval, msg.sender),
            "Walli: 2FA removal already cancelled"
        );
        EnumerableSet.add(cancelled2FARemoval, msg.sender);
        EnumerableSet.remove(confirmed2FARemoval, msg.sender);
        if (
            EnumerableSet.length(cancelled2FARemoval) >=
            Math.ceilDiv(EnumerableSet.length(authorisedGuardians), 2)
        ) _delete2FARemovalRequest();
    }

    function finalise2FARemoval()
        external
        onlyGuardian
        onlyWhenPending2FARemoval
    {
        require(
            pendingRequests[selector2FA].finaliseAfter > 0,
            "Walli: No 2FA removal initiated"
        );
        require(
            block.timestamp > pendingRequests[selector2FA].finaliseAfter,
            "Walli: Ongoing security period"
        );
        require(
            EnumerableSet.length(confirmed2FARemoval) >=
                Math.ceilDiv(EnumerableSet.length(authorisedGuardians), 2),
            "Walli: 2FA removal confirmation still pending from guardians"
        );
        hashedEmail = bytes32(0);
        _delete2FARemovalRequest();
    }

    /// @notice Gets the details of the ongoing recovery procedure if any.
    function get2FARemoval()
        external
        view
        onlyGuardianOrOwner
        onlyWhenPending2FARemoval
        returns (
            uint256 _finaliseAfter,
            uint256 _guardianCount,
            uint256 _confirmedCount,
            uint256 _cancelledCount
        )
    {
        return (
            pendingRequests[selector2FA].finaliseAfter,
            EnumerableSet.length(authorisedGuardians),
            EnumerableSet.length(confirmed2FARemoval),
            EnumerableSet.length(cancelled2FARemoval)
        );
    }

    /**
     * @notice Checks if a session is a valid session.
     * @param _key The _key to check.
     * @return _isValidSession `true` if the session is a valid session otherwise `false`.
     */
    function isValidSession(
        bytes32 _key
    ) public view onlyEntryPointOrOwner returns (bool _isValidSession) {
        return
            EnumerableSet.contains(sessions, _key) &&
            sessionExpiry[_key] > block.timestamp;
    }

    // *************** Transfer Limit functions of tokens and native ************************ //

    function setNativeLimit(
        uint256 _limit
    ) external onlyOwner onlyWhenUnlocked {
        nativeLimit = _limit;
    }

    function setTokenLimit(
        address _token,
        uint256 _limit
    ) external onlyOwner onlyWhenUnlocked {
        tokenLimits[_token] = _limit;
    }

    function getNativeLimit() external view returns (uint) {
        return nativeLimit;
    }

    function getTokenLimit(address _token) external view returns (uint) {
        return tokenLimits[_token];
    }
}
