// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import { MerkleProof } from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

/**
 * @title  TreasuryVerifier
 * @author Pharmacy Fiduciary Commons
 * @notice Stateless cryptographic verification helper bound immutably to a single
 *         PBMRebateTreasury instance. Evaluates EIP-712 typed-data digests (malleable-safe
 *         ECDSA and ERC-1271 smart-account signatures) and double-hashed Merkle proofs so
 *         PBMRebateTreasury remains comfortably within the EIP-170 24,576-byte runtime limit.
 */
contract TreasuryVerifier {
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant EIP712_NAME_HASH    = keccak256("PBMRebateTreasury");
    bytes32 private constant EIP712_VERSION_HASH = keccak256("1");
    bytes32 public constant CLAIM_AUTH_TYPEHASH = keccak256(
        "ClaimAuthorization(uint256 epoch,address claimant,address recipient,uint256 amount,uint256 eligibleCap,uint256 nonce,uint256 deadline,bool allowPartial)"
    );
    bytes32 public constant EXCLUSION_CREDENTIAL_TYPEHASH = keccak256(
        "ExclusionDisputeCredential(uint256 epoch,address pharmacy,uint256 nonce,bytes32 evidenceHash,uint256 deadline)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    address public immutable treasury;
    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedTreasuryDomainSeparator;

    constructor(address _treasury) {
        treasury = _treasury;
        _cachedChainId = block.chainid;
        _cachedTreasuryDomainSeparator = _buildDomainSeparator(_treasury);
    }

    function _buildDomainSeparator(address verifyingContract) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                EIP712_NAME_HASH,
                EIP712_VERSION_HASH,
                block.chainid,
                verifyingContract
            )
        );
    }

    function treasuryDomainSeparator() public view returns (bytes32) {
        return block.chainid == _cachedChainId
            ? _cachedTreasuryDomainSeparator
            : _buildDomainSeparator(treasury);
    }

    function verifyMerkleLeaf(
        bytes32 root,
        address claimant,
        uint256 amount,
        uint256 eligibleCap,
        bytes32[] calldata proof
    ) external pure returns (bool) {
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encodePacked(claimant, amount, eligibleCap)))
        );
        return MerkleProof.verifyCalldata(proof, root, leaf);
    }

    function verifyClaimAuthorization(
        uint256 epoch,
        address claimant,
        address recipient,
        uint256 amount,
        uint256 eligibleCap,
        uint256 nonce,
        uint256 deadline,
        bool allowPartial,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                CLAIM_AUTH_TYPEHASH,
                epoch,
                claimant,
                recipient,
                amount,
                eligibleCap,
                nonce,
                deadline,
                allowPartial
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", treasuryDomainSeparator(), structHash)
        );
        return _isValidSignature(claimant, digest, signature);
    }

    function verifyExclusionCredential(
        address issuer,
        uint256 epoch,
        address pharmacy,
        uint256 nonce,
        bytes32 evidenceHash,
        uint256 deadline,
        bytes calldata signature
    ) external view returns (bool) {
        bytes32 structHash = keccak256(
            abi.encode(
                EXCLUSION_CREDENTIAL_TYPEHASH,
                epoch,
                pharmacy,
                nonce,
                evidenceHash,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", treasuryDomainSeparator(), structHash)
        );
        return _isValidSignature(issuer, digest, signature);
    }

    function _isValidSignature(
        address signer,
        bytes32 digest,
        bytes calldata sig
    ) private view returns (bool) {
        if (signer == address(0)) return false;
        if (signer.code.length > 0) {
            (bool ok, bytes memory ret) = signer.staticcall(
                abi.encodeWithSelector(0x1626ba7e, digest, sig)
            );
            return ok && ret.length >= 32 && abi.decode(ret, (bytes4)) == bytes4(0x1626ba7e);
        }
        if (sig.length != 65) return false;
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER) return false;
        if (v != 27 && v != 28) return false;
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == signer;
    }
}
