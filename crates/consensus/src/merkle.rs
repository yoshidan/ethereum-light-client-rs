use crate::{beacon::Root, errors::MerkleError, internal_prelude::*, types::H256};
use sha2::{Digest, Sha256};

/// MerkleTree is a merkle tree implementation using sha256 as a hashing algorithm.
#[cfg(any(feature = "prover", test))]
pub type MerkleTree = rs_merkle::MerkleTree<rs_merkle::algorithms::Sha256>;

/// https://github.com/ethereum/consensus-specs/blob/master/specs/altair/light-client/sync-protocol.md#is_valid_normalized_merkle_branch
///
/// The branch may be longer than `floorlog2(gindex)` when a proof generated
/// under an older fork is carried in a newer fork's container whose branch
/// vector is deeper (e.g. pre-Gloas light client data upgraded into a Gloas
/// container). Such branches are prepended with zero hashes, which carry no
/// information and are stripped before verification.
pub fn is_valid_normalized_merkle_branch(
    leaf: H256,
    branch: &[H256],
    gindex: u32,
    root: Root,
) -> Result<(), MerkleError> {
    if gindex == 0 {
        return Err(MerkleError::InvalidGeneralIndex(gindex as i64));
    }
    let depth = get_depth(gindex);
    let subtree_index = get_subtree_index(gindex);
    if branch.len() as u32 > depth {
        let num_extra = branch.len() - depth as usize;
        if branch[..num_extra].iter().any(|b| *b != H256::default()) {
            return Err(MerkleError::NonZeroMerkleBranchPadding(
                depth,
                leaf,
                branch.to_vec(),
                subtree_index,
                root,
            ));
        }
        return is_valid_merkle_branch(leaf, &branch[num_extra..], depth, subtree_index, root);
    }
    is_valid_merkle_branch(leaf, branch, depth, subtree_index, root)
}

/// https://github.com/ethereum/consensus-specs/blob/master/ssz/merkle-proofs.md#concat_generalized_indices
pub const fn concat_generalized_indices(a: u32, b: u32) -> u32 {
    (a << get_depth(b)) | (b - (1 << get_depth(b)))
}

/// Check if ``leaf`` at ``index`` verifies against the Merkle ``root`` and ``branch``.
/// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#is_valid_merkle_branch
pub fn is_valid_merkle_branch(
    leaf: H256,
    branch: &[H256],
    depth: u32,
    subtree_index: u32,
    root: Root,
) -> Result<(), MerkleError> {
    if depth != branch.len() as u32 {
        return Err(MerkleError::InvalidMerkleBranchLength(
            depth,
            leaf,
            branch.to_vec(),
            subtree_index,
            root,
        ));
    }
    let mut value = leaf;
    for (i, b) in branch.iter().enumerate() {
        if let Some(v) = 2u32.checked_pow(i as u32) {
            if subtree_index / v % 2 == 1 {
                value = hash([b.as_bytes(), value.as_bytes()].concat());
            } else {
                value = hash([value.as_bytes(), b.as_bytes()].concat());
            }
        } else {
            return Err(MerkleError::TooLongMerkleBranchLength(
                depth,
                leaf,
                branch.to_vec(),
                subtree_index,
                root,
            ));
        }
    }
    if value == root {
        Ok(())
    } else {
        Err(MerkleError::InvalidMerkleBranch(
            leaf,
            branch.to_vec(),
            subtree_index,
            root,
            value,
        ))
    }
}

pub const fn get_depth(gindex: u32) -> u32 {
    gindex.ilog2()
}

pub const fn get_subtree_index(gindex: u32) -> u32 {
    gindex % 2u32.pow(get_depth(gindex))
}

fn hash(bz: Vec<u8>) -> H256 {
    let mut output = H256::default();
    output.0.copy_from_slice(Sha256::digest(bz).as_ref());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h256(b: u8) -> H256 {
        let mut v = H256::default();
        v.0.copy_from_slice(&[b; 32]);
        v
    }

    #[test]
    fn test_concat_generalized_indices() {
        // EXECUTION_BLOCK_HASH_GINDEX_DENEB = concat(EXECUTION_PAYLOAD_GINDEX=25, block_hash in deneb payload=44)
        assert_eq!(concat_generalized_indices(25, 44), 812);
        // EXECUTION_BLOCK_HASH_GINDEX (capella) = concat(25, block_hash in capella payload=28)
        assert_eq!(concat_generalized_indices(25, 28), 412);
        // concat with the root index is the identity
        assert_eq!(concat_generalized_indices(1, 25), 25);
    }

    #[test]
    fn test_normalized_merkle_branch_padding() {
        // depth-1 tree: gindex=2, subtree_index=0 => root = hash(leaf || sibling)
        let leaf = h256(1);
        let sibling = h256(2);
        let root = hash([leaf.as_bytes(), sibling.as_bytes()].concat());

        // exact-length branch
        is_valid_normalized_merkle_branch(leaf, core::slice::from_ref(&sibling), 2, root).unwrap();

        // zero-padded branch (normalized)
        is_valid_normalized_merkle_branch(leaf, &[H256::default(), sibling], 2, root).unwrap();

        // non-zero padding must be rejected
        let res = is_valid_normalized_merkle_branch(leaf, &[h256(3), sibling], 2, root);
        assert!(matches!(
            res,
            Err(MerkleError::NonZeroMerkleBranchPadding(..))
        ));

        // too-short branch is still rejected
        let res = is_valid_normalized_merkle_branch(leaf, &[], 2, root);
        assert!(matches!(
            res,
            Err(MerkleError::InvalidMerkleBranchLength(..))
        ));
    }
}
