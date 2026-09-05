use alloc::vec::Vec;
use core::fmt;
use crate::errors::SLHDSAError;

use umineko_hash_sha::{SHA2_256, SHA2_512, SHAKE256};
use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

/// The part of a hash tree that one address points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SLHDSAPart {
    WOTSHash,
    WOTSKey,
    Tree,
    FORSTree,
    FORSRoots,
    WOTSSecret,
    FORSSecret,
}

impl SLHDSAPart {
    pub fn value(&self) -> u32 {
        match self {
            Self::WOTSHash => 0,
            Self::WOTSKey => 1,
            Self::Tree => 2,
            Self::FORSTree => 3,
            Self::FORSRoots => 4,
            Self::WOTSSecret => 5,
            Self::FORSSecret => 6,
        }
    }
}

/// The thirty two byte address that names one call of a tweakable hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SLHDSAAddress {
    pub words: [u8; 32],
}

impl SLHDSAAddress {
    pub fn new() -> Self {
        Self { words: [0; 32] }
    }

    pub fn layer(&mut self, layer: u32) -> &mut Self {
        self.words[..4].copy_from_slice(&layer.to_be_bytes());
        self
    }

    pub fn tree(&mut self, tree: u64) -> &mut Self {
        self.words[4..8].fill(0);
        self.words[8..16].copy_from_slice(&tree.to_be_bytes());
        self
    }

    /// The kind of the call, which also clears the three words that follow it.
    pub fn part(&mut self, part: SLHDSAPart) -> &mut Self {
        self.words[16..20].copy_from_slice(&part.value().to_be_bytes());
        self.words[20..].fill(0);
        self
    }

    pub fn pair(&mut self, pair: u32) -> &mut Self {
        self.words[20..24].copy_from_slice(&pair.to_be_bytes());
        self
    }

    pub fn chain(&mut self, chain: u32) -> &mut Self {
        self.words[24..28].copy_from_slice(&chain.to_be_bytes());
        self
    }

    pub fn height(&mut self, height: u32) -> &mut Self {
        self.words[24..28].copy_from_slice(&height.to_be_bytes());
        self
    }

    pub fn step(&mut self, step: u32) -> &mut Self {
        self.words[28..].copy_from_slice(&step.to_be_bytes());
        self
    }

    pub fn index(&mut self, index: u32) -> &mut Self {
        self.words[28..].copy_from_slice(&index.to_be_bytes());
        self
    }

    pub fn pair_of(&self) -> u32 {
        u32::from_be_bytes(self.words[20..24].try_into().unwrap_or([0; 4]))
    }

    pub fn index_of(&self) -> u32 {
        u32::from_be_bytes(self.words[28..].try_into().unwrap_or([0; 4]))
    }

    /// The twenty two byte form that the variants over SHA-2 use.
    pub fn compressed(&self) -> [u8; 22] {
        let mut compressed = [0; 22];
        compressed[0] = self.words[3];
        compressed[1..9].copy_from_slice(&self.words[8..16]);
        compressed[9] = self.words[19];
        compressed[10..].copy_from_slice(&self.words[20..]);
        compressed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SLHDSA {
    SHA2_128S,
    SHA2_128F,
    SHA2_192S,
    SHA2_192F,
    SHA2_256S,
    SHA2_256F,
    SHAKE_128S,
    SHAKE_128F,
    SHAKE_192S,
    SHAKE_192F,
    SHAKE_256S,
    SHAKE_256F,
}

impl SLHDSA {
    pub const ALL: [Self; 12] = [
        Self::SHA2_128S, Self::SHA2_128F, Self::SHA2_192S, Self::SHA2_192F, Self::SHA2_256S, Self::SHA2_256F,
        Self::SHAKE_128S, Self::SHAKE_128F, Self::SHAKE_192S, Self::SHAKE_192F, Self::SHAKE_256S, Self::SHAKE_256F,
    ];
    /// The bits of one step of a chain, which is four in every variant.
    pub const WINDOW: usize = 4;
    pub const STEPS: usize = 15;
    pub const MAXIMUM_CONTEXT_SIZE: usize = 255;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA2_128S => "SLH-DSA-SHA2-128s",
            Self::SHA2_128F => "SLH-DSA-SHA2-128f",
            Self::SHA2_192S => "SLH-DSA-SHA2-192s",
            Self::SHA2_192F => "SLH-DSA-SHA2-192f",
            Self::SHA2_256S => "SLH-DSA-SHA2-256s",
            Self::SHA2_256F => "SLH-DSA-SHA2-256f",
            Self::SHAKE_128S => "SLH-DSA-SHAKE-128s",
            Self::SHAKE_128F => "SLH-DSA-SHAKE-128f",
            Self::SHAKE_192S => "SLH-DSA-SHAKE-192s",
            Self::SHAKE_192F => "SLH-DSA-SHAKE-192f",
            Self::SHAKE_256S => "SLH-DSA-SHAKE-256s",
            Self::SHAKE_256F => "SLH-DSA-SHAKE-256f",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|variant| variant.as_str() == name)
    }

    pub fn shake(&self) -> bool {
        matches!(self, Self::SHAKE_128S | Self::SHAKE_128F | Self::SHAKE_192S | Self::SHAKE_192F | Self::SHAKE_256S | Self::SHAKE_256F)
    }

    pub fn fast(&self) -> bool {
        matches!(self, Self::SHA2_128F | Self::SHA2_192F | Self::SHA2_256F | Self::SHAKE_128F | Self::SHAKE_192F | Self::SHAKE_256F)
    }

    /// The length of one hash, which sets the strength of the variant.
    pub fn size(&self) -> usize {
        match self {
            Self::SHA2_128S | Self::SHA2_128F | Self::SHAKE_128S | Self::SHAKE_128F => 16,
            Self::SHA2_192S | Self::SHA2_192F | Self::SHAKE_192S | Self::SHAKE_192F => 24,
            _ => 32,
        }
    }

    /// The total height of the hypertree.
    pub fn height(&self) -> usize {
        match (self.size(), self.fast()) {
            (16, false) | (24, false) => 63,
            (16, true) | (24, true) => 66,
            (_, false) => 64,
            (_, true) => 68,
        }
    }

    pub fn layers(&self) -> usize {
        match (self.size(), self.fast()) {
            (16, false) | (24, false) => 7,
            (16, true) | (24, true) => 22,
            (_, false) => 8,
            (_, true) => 17,
        }
    }

    pub fn subtree(&self) -> usize {
        self.height() / self.layers()
    }

    /// The height of one tree of the forest.
    pub fn depth(&self) -> usize {
        match (self.size(), self.fast()) {
            (16, false) => 12,
            (16, true) => 6,
            (24, false) => 14,
            (24, true) => 8,
            (_, false) => 14,
            (_, true) => 9,
        }
    }

    /// The number of trees in the forest.
    pub fn trees(&self) -> usize {
        match (self.size(), self.fast()) {
            (16, false) => 14,
            (16, true) => 33,
            (24, false) => 17,
            (24, true) => 33,
            (_, false) => 22,
            (_, true) => 35,
        }
    }

    pub fn chains(&self) -> usize {
        2 * self.size() + 3
    }

    pub fn digest_size(&self) -> usize {
        (self.trees() * self.depth()).div_ceil(8) + (self.height() - self.subtree()).div_ceil(8) + self.subtree().div_ceil(8)
    }

    pub fn public_key_size(&self) -> usize {
        2 * self.size()
    }

    pub fn private_key_size(&self) -> usize {
        4 * self.size()
    }

    pub fn signature_size(&self) -> usize {
        (1 + self.trees() * (self.depth() + 1) + self.height() + self.layers() * self.chains()) * self.size()
    }

    pub fn seed_size(&self) -> usize {
        3 * self.size()
    }

    /// The values of `width` bits each that a byte string holds, taken from the top.
    pub fn digits(data: &[u8], width: usize, count: usize) -> Vec<u32> {
        let mut digits = Vec::with_capacity(count);
        let (mut position, mut bits, mut total) = (0, 0, 0u64);
        for _ in 0..count {
            while bits < width {
                total = (total << 8) | *data.get(position).unwrap_or(&0) as u64;
                position += 1;
                bits += 8;
            }
            bits -= width;
            digits.push(((total >> bits) & ((1 << width) - 1)) as u32);
        }
        digits
    }
}

impl SLHDSA {
    /// Whether the wide digest stands behind the tree hashes, which only the larger sizes use.
    pub fn wide(&self) -> bool {
        !self.shake() && self.size() > 16
    }

    pub fn extend(parts: &[&[u8]], output: &mut [u8]) {
        let mut hash = SHAKE256::builtin();
        for part in parts {
            hash.update(part);
        }
        hash.finalize(output);
    }

    pub fn narrow(parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = SHA2_256::builtin();
        for part in parts {
            hash.update(part);
        }
        hash.finalize()
    }

    pub fn broad(parts: &[&[u8]]) -> [u8; 64] {
        let mut hash = SHA2_512::builtin();
        for part in parts {
            hash.update(part);
        }
        hash.finalize()
    }

    /// The keyed digest of RFC 2104 over one of the two digests of the SHA-2 family.
    pub fn keyed(&self, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let (block, size) = match self.wide() {
            true => (128, 64),
            false => (64, 32),
        };
        let pad = |value: u8| {
            let mut padded = alloc::vec![value; block];
            let key = match key.len() > block {
                true => match self.wide() {
                    true => Self::broad(&[key]).to_vec(),
                    false => Self::narrow(&[key]).to_vec(),
                },
                false => key.to_vec(),
            };
            for (byte, source) in padded.iter_mut().zip(&key) {
                *byte ^= source;
            }
            padded
        };
        let mut inner = alloc::vec![pad(0x36)];
        inner.extend(parts.iter().map(|part| part.to_vec()));
        let inner: Vec<&[u8]> = inner.iter().map(|part| part.as_slice()).collect();
        let digest = match self.wide() {
            true => Self::broad(&inner).to_vec(),
            false => Self::narrow(&inner).to_vec(),
        };
        let outer = pad(0x5C);
        let mut result = match self.wide() {
            true => Self::broad(&[&outer, &digest]).to_vec(),
            false => Self::narrow(&[&outer, &digest]).to_vec(),
        };
        result.truncate(size);
        result
    }

    /// The mask generating function of PKCS #1 over one of the two digests of the SHA-2 family.
    pub fn mask(&self, seed: &[u8], length: usize) -> Vec<u8> {
        let mut mask = Vec::with_capacity(length + 64);
        let mut counter = 0u32;
        while mask.len() < length {
            match self.wide() {
                true => mask.extend_from_slice(&Self::broad(&[seed, &counter.to_be_bytes()])),
                false => mask.extend_from_slice(&Self::narrow(&[seed, &counter.to_be_bytes()])),
            }
            counter += 1;
        }
        mask.truncate(length);
        mask
    }

    /// The tweakable hash of one or more blocks, which every tree of the scheme is built from.
    pub fn tweak(&self, public: &[u8], address: &SLHDSAAddress, message: &[u8], wide: bool) -> Vec<u8> {
        let size = self.size();
        if self.shake() {
            let mut output = alloc::vec![0; size];
            Self::extend(&[public, &address.words, message], &mut output);
            return output;
        }
        let padding = match wide {
            true => 128 - size,
            false => 64 - size,
        };
        let zeroes = alloc::vec![0; padding];
        let compressed = address.compressed();
        let mut digest = match wide {
            true => Self::broad(&[public, &zeroes, &compressed, message]).to_vec(),
            false => Self::narrow(&[public, &zeroes, &compressed, message]).to_vec(),
        };
        digest.truncate(size);
        digest
    }

    /// The tweakable hash of one block, which every chain steps through.
    pub fn chain_hash(&self, public: &[u8], address: &SLHDSAAddress, message: &[u8]) -> Vec<u8> {
        self.tweak(public, address, message, false)
    }

    /// The tweakable hash of several blocks, which joins the nodes of every tree.
    pub fn node_hash(&self, public: &[u8], address: &SLHDSAAddress, message: &[u8]) -> Vec<u8> {
        self.tweak(public, address, message, self.wide())
    }

    pub fn secret(&self, public: &[u8], secret: &[u8], address: &SLHDSAAddress) -> Vec<u8> {
        match self.shake() {
            true => {
                let mut output = alloc::vec![0; self.size()];
                Self::extend(&[public, &address.words, secret], &mut output);
                output
            }
            false => {
                let zeroes = alloc::vec![0; 64 - self.size()];
                let mut digest = Self::narrow(&[public, &zeroes, &address.compressed(), secret]).to_vec();
                digest.truncate(self.size());
                digest
            }
        }
    }

    /// The randomizer of one signature, which the key and the message alone decide.
    pub fn randomizer(&self, key: &[u8], extra: &[u8], message: &[u8]) -> Vec<u8> {
        match self.shake() {
            true => {
                let mut output = alloc::vec![0; self.size()];
                Self::extend(&[key, extra, message], &mut output);
                output
            }
            false => {
                let mut digest = self.keyed(key, &[extra, message]);
                digest.truncate(self.size());
                digest
            }
        }
    }

    /// The digest that a signature covers, which names the leaf and the trees of the forest.
    pub fn message(&self, randomizer: &[u8], public: &[u8], root: &[u8], message: &[u8]) -> Vec<u8> {
        match self.shake() {
            true => {
                let mut output = alloc::vec![0; self.digest_size()];
                Self::extend(&[randomizer, public, root, message], &mut output);
                output
            }
            false => {
                let inner = match self.wide() {
                    true => Self::broad(&[randomizer, public, root, message]).to_vec(),
                    false => Self::narrow(&[randomizer, public, root, message]).to_vec(),
                };
                let mut seed = randomizer.to_vec();
                seed.extend_from_slice(public);
                seed.extend_from_slice(&inner);
                self.mask(&seed, self.digest_size())
            }
        }
    }
}

impl SLHDSA {
    /// One value stepped through the chain, from `start` for `count` steps.
    pub fn chain(&self, public: &[u8], address: &mut SLHDSAAddress, value: &[u8], start: u32, count: u32) -> Vec<u8> {
        let mut value = value.to_vec();
        for step in start..start + count {
            address.step(step);
            value = self.chain_hash(public, address, &value);
        }
        value
    }

    /// The message digits of one chain signature, together with the digits of their checksum.
    pub fn digits_of(&self, message: &[u8]) -> Vec<u32> {
        let first = 2 * self.size();
        let mut digits = Self::digits(message, Self::WINDOW, first);
        let total: u32 = digits.iter().map(|digit| Self::STEPS as u32 - digit).sum();
        let shifted = total << ((8 - (3 * Self::WINDOW) % 8) % 8);
        digits.extend(Self::digits(&(shifted as u16).to_be_bytes(), Self::WINDOW, 3));
        digits
    }

    /// The public key of one chain signature, which is the hash of every chain end.
    pub fn chain_key(&self, secret: &[u8], public: &[u8], address: &mut SLHDSAAddress) -> Vec<u8> {
        let pair = address.pair_of();
        let mut secrets = SLHDSAAddress::new();
        secrets.words[..16].copy_from_slice(&address.words[..16]);
        secrets.part(SLHDSAPart::WOTSSecret).pair(pair);
        let mut ends = Vec::with_capacity(self.chains() * self.size());
        for chain in 0..self.chains() {
            secrets.chain(chain as u32);
            let value = self.secret(public, secret, &secrets);
            address.part(SLHDSAPart::WOTSHash).pair(pair).chain(chain as u32);
            ends.extend_from_slice(&self.chain(public, address, &value, 0, Self::STEPS as u32));
        }
        let mut key = SLHDSAAddress::new();
        key.words[..16].copy_from_slice(&address.words[..16]);
        key.part(SLHDSAPart::WOTSKey).pair(pair);
        self.node_hash(public, &key, &ends)
    }

    pub fn chain_sign(&self, message: &[u8], secret: &[u8], public: &[u8], address: &mut SLHDSAAddress) -> Vec<u8> {
        let pair = address.pair_of();
        let mut secrets = SLHDSAAddress::new();
        secrets.words[..16].copy_from_slice(&address.words[..16]);
        secrets.part(SLHDSAPart::WOTSSecret).pair(pair);
        let mut signature = Vec::with_capacity(self.chains() * self.size());
        for (chain, digit) in self.digits_of(message).into_iter().enumerate() {
            secrets.chain(chain as u32);
            let value = self.secret(public, secret, &secrets);
            address.part(SLHDSAPart::WOTSHash).pair(pair).chain(chain as u32);
            signature.extend_from_slice(&self.chain(public, address, &value, 0, digit));
        }
        signature
    }

    pub fn chain_recover(&self, signature: &[u8], message: &[u8], public: &[u8], address: &mut SLHDSAAddress) -> Vec<u8> {
        let pair = address.pair_of();
        let mut ends = Vec::with_capacity(self.chains() * self.size());
        for (chain, digit) in self.digits_of(message).into_iter().enumerate() {
            address.part(SLHDSAPart::WOTSHash).pair(pair).chain(chain as u32);
            let part = &signature[chain * self.size()..(chain + 1) * self.size()];
            ends.extend_from_slice(&self.chain(public, address, part, digit, Self::STEPS as u32 - digit));
        }
        let mut key = SLHDSAAddress::new();
        key.words[..16].copy_from_slice(&address.words[..16]);
        key.part(SLHDSAPart::WOTSKey).pair(pair);
        self.node_hash(public, &key, &ends)
    }

    /// One node of a hash tree of chain keys, built from the leaves below it.
    pub fn node(&self, secret: &[u8], public: &[u8], address: &mut SLHDSAAddress, index: u32, level: usize) -> Vec<u8> {
        if level == 0 {
            address.part(SLHDSAPart::WOTSHash).pair(index);
            return self.chain_key(secret, public, address);
        }
        let left = self.node(secret, public, address, index * 2, level - 1);
        let right = self.node(secret, public, address, index * 2 + 1, level - 1);
        let mut joined = left;
        joined.extend_from_slice(&right);
        address.part(SLHDSAPart::Tree).height(level as u32).index(index);
        self.node_hash(public, address, &joined)
    }

    /// One signature of a tree, which is a chain signature and the path beside it.
    pub fn tree_sign(&self, message: &[u8], secret: &[u8], public: &[u8], address: &mut SLHDSAAddress, leaf: u32) -> Vec<u8> {
        let mut path = Vec::with_capacity(self.subtree() * self.size());
        for level in 0..self.subtree() {
            path.extend_from_slice(&self.node(secret, public, address, (leaf >> level) ^ 1, level));
        }
        address.part(SLHDSAPart::WOTSHash).pair(leaf);
        let mut signature = self.chain_sign(message, secret, public, address);
        signature.extend_from_slice(&path);
        signature
    }

    pub fn tree_recover(&self, signature: &[u8], message: &[u8], public: &[u8], address: &mut SLHDSAAddress, leaf: u32) -> Vec<u8> {
        let (chains, path) = signature.split_at(self.chains() * self.size());
        address.part(SLHDSAPart::WOTSHash).pair(leaf);
        let mut node = self.chain_recover(chains, message, public, address);
        address.part(SLHDSAPart::Tree).index(leaf);
        for (level, sibling) in path.chunks_exact(self.size()).enumerate() {
            address.height(level as u32 + 1);
            let index = address.index_of();
            let mut joined = Vec::with_capacity(self.size() * 2);
            match (leaf >> level) & 1 == 0 {
                true => {
                    address.index(index / 2);
                    joined.extend_from_slice(&node);
                    joined.extend_from_slice(sibling);
                }
                false => {
                    address.index((index - 1) / 2);
                    joined.extend_from_slice(sibling);
                    joined.extend_from_slice(&node);
                }
            }
            node = self.node_hash(public, address, &joined);
        }
        node
    }

    /// The signature of the hypertree, one tree for each layer up to the root.
    pub fn forest_sign(&self, message: &[u8], secret: &[u8], public: &[u8], tree: u64, leaf: u32) -> Vec<u8> {
        let mut address = SLHDSAAddress::new();
        let (mut tree, mut leaf) = (tree, leaf);
        address.layer(0).tree(tree);
        let mut signature = self.tree_sign(message, secret, public, &mut address, leaf);
        let mut root = self.tree_recover(&signature, message, public, &mut address.clone(), leaf);
        for layer in 1..self.layers() {
            leaf = (tree & ((1 << self.subtree()) - 1)) as u32;
            tree >>= self.subtree();
            address = SLHDSAAddress::new();
            address.layer(layer as u32).tree(tree);
            let part = self.tree_sign(&root, secret, public, &mut address, leaf);
            root = self.tree_recover(&part, &root, public, &mut address.clone(), leaf);
            signature.extend_from_slice(&part);
        }
        signature
    }

    pub fn forest_recover(&self, signature: &[u8], message: &[u8], public: &[u8], tree: u64, leaf: u32) -> Vec<u8> {
        let length = (self.chains() + self.subtree()) * self.size();
        let (mut tree, mut leaf) = (tree, leaf);
        let mut address = SLHDSAAddress::new();
        address.layer(0).tree(tree);
        let mut root = self.tree_recover(&signature[..length], message, public, &mut address, leaf);
        for layer in 1..self.layers() {
            leaf = (tree & ((1 << self.subtree()) - 1)) as u32;
            tree >>= self.subtree();
            address = SLHDSAAddress::new();
            address.layer(layer as u32).tree(tree);
            root = self.tree_recover(&signature[layer * length..(layer + 1) * length], &root, public, &mut address, leaf);
        }
        root
    }

    /// One node of a tree of the forest, built from the secret values below it.
    pub fn forest_node(&self, secret: &[u8], public: &[u8], address: &mut SLHDSAAddress, index: u32, level: usize) -> Vec<u8> {
        if level == 0 {
            let mut secrets = *address;
            secrets.part(SLHDSAPart::FORSSecret).pair(address.pair_of()).index(index);
            let value = self.secret(public, secret, &secrets);
            address.part(SLHDSAPart::FORSTree).pair(secrets.pair_of()).height(0).index(index);
            return self.chain_hash(public, address, &value);
        }
        let pair = address.pair_of();
        let left = self.forest_node(secret, public, address, index * 2, level - 1);
        let right = self.forest_node(secret, public, address, index * 2 + 1, level - 1);
        let mut joined = left;
        joined.extend_from_slice(&right);
        address.part(SLHDSAPart::FORSTree).pair(pair).height(level as u32).index(index);
        self.node_hash(public, address, &joined)
    }

    /// The signature of the forest, one secret value and one path for each tree.
    pub fn fors_sign(&self, digest: &[u8], secret: &[u8], public: &[u8], address: &mut SLHDSAAddress) -> Vec<u8> {
        let indices = Self::digits(digest, self.depth(), self.trees());
        let pair = address.pair_of();
        let mut signature = Vec::with_capacity(self.trees() * (self.depth() + 1) * self.size());
        for (tree, index) in indices.into_iter().enumerate() {
            let position = (tree << self.depth()) as u32 + index;
            let mut secrets = *address;
            secrets.part(SLHDSAPart::FORSSecret).pair(pair).index(position);
            signature.extend_from_slice(&self.secret(public, secret, &secrets));
            for level in 0..self.depth() {
                let sibling = ((tree << (self.depth() - level)) as u32) + ((index >> level) ^ 1);
                address.part(SLHDSAPart::FORSTree).pair(pair);
                signature.extend_from_slice(&self.forest_node(secret, public, address, sibling, level));
            }
        }
        signature
    }

    pub fn fors_recover(&self, signature: &[u8], digest: &[u8], public: &[u8], address: &mut SLHDSAAddress) -> Vec<u8> {
        let indices = Self::digits(digest, self.depth(), self.trees());
        let pair = address.pair_of();
        let length = (self.depth() + 1) * self.size();
        let mut roots = Vec::with_capacity(self.trees() * self.size());
        for (tree, index) in indices.into_iter().enumerate() {
            let part = &signature[tree * length..(tree + 1) * length];
            let (value, path) = part.split_at(self.size());
            address.part(SLHDSAPart::FORSTree).pair(pair).height(0).index((tree << self.depth()) as u32 + index);
            let mut node = self.chain_hash(public, address, value);
            for (level, sibling) in path.chunks_exact(self.size()).enumerate() {
                address.height(level as u32 + 1);
                let position = address.index_of();
                let mut joined = Vec::with_capacity(self.size() * 2);
                match (index >> level) & 1 == 0 {
                    true => {
                        address.index(position / 2);
                        joined.extend_from_slice(&node);
                        joined.extend_from_slice(sibling);
                    }
                    false => {
                        address.index((position - 1) / 2);
                        joined.extend_from_slice(sibling);
                        joined.extend_from_slice(&node);
                    }
                }
                node = self.node_hash(public, address, &joined);
            }
            roots.extend_from_slice(&node);
        }
        let mut key = *address;
        key.part(SLHDSAPart::FORSRoots).pair(pair);
        self.node_hash(public, &key, &roots)
    }

    /// The tree and the leaf that one digest points at, together with the part that the forest signs.
    pub fn place(&self, digest: &[u8]) -> (Vec<u8>, u64, u32) {
        let first = (self.trees() * self.depth()).div_ceil(8);
        let second = (self.height() - self.subtree()).div_ceil(8);
        let third = self.subtree().div_ceil(8);
        let mut tree = 0u64;
        for byte in &digest[first..first + second] {
            tree = (tree << 8) | *byte as u64;
        }
        let mut leaf = 0u64;
        for byte in &digest[first + second..first + second + third] {
            leaf = (leaf << 8) | *byte as u64;
        }
        let trees = self.height() - self.subtree();
        let tree = match trees >= 64 {
            true => tree,
            false => tree & ((1 << trees) - 1),
        };
        (digest[..first].to_vec(), tree, (leaf & ((1 << self.subtree()) - 1)) as u32)
    }

    /// The public key of one seed, which is the root of the top tree.
    pub fn keys(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let size = self.size();
        let (secret, rest) = seed.split_at(size);
        let (prefix, public) = rest.split_at(size);
        let public = &public[..size];
        let mut address = SLHDSAAddress::new();
        address.layer(self.layers() as u32 - 1);
        let root = self.node(secret, public, &mut address, 0, self.subtree());
        let mut key = Vec::with_capacity(4 * size);
        key.extend_from_slice(secret);
        key.extend_from_slice(prefix);
        key.extend_from_slice(public);
        key.extend_from_slice(&root);
        let mut verifier = public.to_vec();
        verifier.extend_from_slice(&root);
        (verifier, key)
    }

    pub fn produce(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let size = self.size();
        let (secret, prefix) = (&key[..size], &key[size..size * 2]);
        let (public, root) = (&key[size * 2..size * 3], &key[size * 3..]);
        let randomizer = self.randomizer(prefix, public, message);
        let digest = self.message(&randomizer, public, root, message);
        let (part, tree, leaf) = self.place(&digest);
        let mut address = SLHDSAAddress::new();
        address.tree(tree).part(SLHDSAPart::FORSTree).pair(leaf);
        let forest = self.fors_sign(&part, secret, public, &mut address);
        let mut recovery = SLHDSAAddress::new();
        recovery.tree(tree).part(SLHDSAPart::FORSTree).pair(leaf);
        let inner = self.fors_recover(&forest, &part, public, &mut recovery);
        let mut signature = randomizer;
        signature.extend_from_slice(&forest);
        signature.extend_from_slice(&self.forest_sign(&inner, secret, public, tree, leaf));
        signature
    }

    pub fn confirm(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let size = self.size();
        if signature.len() != self.signature_size() {
            return false;
        }
        let (public, root) = key.split_at(size);
        let (randomizer, rest) = signature.split_at(size);
        let (forest, hypertree) = rest.split_at(self.trees() * (self.depth() + 1) * size);
        let digest = self.message(randomizer, public, root, message);
        let (part, tree, leaf) = self.place(&digest);
        let mut address = SLHDSAAddress::new();
        address.tree(tree).part(SLHDSAPart::FORSTree).pair(leaf);
        let inner = self.fors_recover(forest, &part, public, &mut address);
        self.forest_recover(hypertree, &inner, public, tree, leaf) == root
    }

    /// The message that a signature covers, which names the context it belongs to.
    pub fn bound(context: &[u8], message: &[u8]) -> Vec<u8> {
        let mut bound = alloc::vec![0, context.len() as u8];
        bound.extend_from_slice(context);
        bound.extend_from_slice(message);
        bound
    }
}

impl fmt::Display for SLHDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl SLHDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(SLHDSAPrivateKey, SLHDSAPublicKey), SLHDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((SLHDSAPrivateKey { variant: *self, key: private }, SLHDSAPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(SLHDSAError::Seed);
                }
                let (public, private) = self.keys(seed);
                Ok((SLHDSAPrivateKey { variant: *self, key: private }, SLHDSAPublicKey { variant: *self, key: public }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSAPrivateKey {
    variant: SLHDSA,
    key: Vec<u8>,
}

impl SLHDSAPrivateKey {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        match data.len() == variant.private_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(SLHDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }

    pub fn public_key(&self) -> SLHDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => SLHDSAPublicKey { variant: self.variant, key },
            None => SLHDSAPublicKey { variant: self.variant, key: self.key[self.variant.size() * 2..].to_vec() },
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<SLHDSASignature, SLHDSAError> {
        if context.len() > SLHDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(SLHDSAError::Length);
        }
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(SLHDSASignature { variant: self.variant, signature }),
            None => Ok(SLHDSASignature { variant: self.variant, signature: self.variant.produce(&self.key, &SLHDSA::bound(context, message)) }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSAPublicKey {
    variant: SLHDSA,
    key: Vec<u8>,
}

impl SLHDSAPublicKey {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        match data.len() == variant.public_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(SLHDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &SLHDSASignature, context: &[u8]) -> Result<(), SLHDSAError> {
        if signature.variant != self.variant {
            return Err(SLHDSAError::Variant);
        }
        if context.len() > SLHDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(SLHDSAError::Length);
        }
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => match self.variant.confirm(&self.key, &SLHDSA::bound(context, message), &signature.signature) {
                true => Ok(()),
                false => Err(SLHDSAError::Verification),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SLHDSASignature {
    variant: SLHDSA,
    signature: Vec<u8>,
}

impl SLHDSASignature {
    pub fn decode(variant: SLHDSA, data: &[u8]) -> Result<Self, SLHDSAError> {
        match data.len() == variant.signature_size() {
            true => Ok(Self { variant, signature: data.to_vec() }),
            false => Err(SLHDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> SLHDSA {
        self.variant
    }
}
