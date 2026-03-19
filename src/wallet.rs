use crate::key_pair::KeyPair;
use ring::{digest, pbkdf2};
use sha2::{Digest, Sha256};
use std::fs;

pub struct Wallet {
    pub address: String,
    pub key_pairs: Vec<KeyPair>,
}

impl Wallet {
    pub fn generate_mnemonic_words(entropy_bits: Vec<u8>) -> Vec<String> {
        // BIP-39 Step 1: Pack the individual bits into raw bytes and hash them
        let entropy_bytes: Vec<u8> = entropy_bits
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, &bit| (acc << 1) | bit))
            .collect();

        let mut hasher = Sha256::new();
        hasher.update(&entropy_bytes);
        let hash = hasher.finalize();

        // BIP-39 Step 2: Take first ENT/32 bits of the hash as checksum
        // For 128-bit entropy, checksum is 4 bits (first 4 bits of first hash byte)
        let checksum_bits_needed = entropy_bits.len() / 32;
        let mut checksum_bits: Vec<u8> = Vec::new();
        for i in 0..checksum_bits_needed {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);
            checksum_bits.push((hash[byte_index] >> bit_index) & 1);
        }

        // BIP-39 Step 3: Append checksum to entropy
        let mut full_bits: Vec<u8> = entropy_bits;
        full_bits.extend(checksum_bits);

        // BIP-39 Step 4: Split into 11-bit segments
        let mut sequence_segments: Vec<u16> = Vec::new();
        for chunk in full_bits.chunks(11) {
            let value = chunk.iter().fold(0u16, |acc, &bit| (acc << 1) | bit as u16);
            sequence_segments.push(value);
        }

        // BIP-39 Step 5: Map each 11-bit value to a word
        let wordlist: Vec<String> = fs::read_to_string("files/bip39wordlist.txt")
            .unwrap()
            .lines()
            .map(|x| x.to_string())
            .collect();

        sequence_segments
            .iter()
            .map(|&idx| wordlist[idx as usize].clone())
            .collect()
    }

    pub fn generate_seed(mnemonic_words: Vec<String>, password: &str) -> String {
        // BIP-39: mnemonic sentence is space-separated words
        let mnemonic_sentence = mnemonic_words.join(" ");

        // BIP-39: PBKDF2-HMAC-SHA512, 2048 iterations, 64-byte output
        let mut seed_bytes = [0u8; digest::SHA512_OUTPUT_LEN];
        let salt = format!("mnemonic{}", password);
        let pbkdf2_iterations = std::num::NonZeroU32::new(2048).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA512,
            pbkdf2_iterations,
            salt.as_bytes(),
            mnemonic_sentence.as_bytes(),
            &mut seed_bytes,
        );

        // Zero-padded hex encoding
        seed_bytes.iter().map(|x| format!("{:02x}", x)).collect()
    }

    pub fn new(seed: String) -> Wallet {
        let mut public_key_hasher = Sha256::new();

        let private_key: String = seed[seed.len() / 2..].to_owned();
        public_key_hasher.update(&private_key);

        let public_key = format!("{:X}", public_key_hasher.finalize());
        let chain_code = seed[..seed.len() / 2].to_owned();

        let mut address_hasher = Sha256::new();

        address_hasher.update(&public_key);

        let address = format!("{:X}", address_hasher.finalize());

        let key_pair = KeyPair {
            private_key: private_key.clone(),
            public_key,
            chain_code,
            index: 0,
            path: "m/44'/0'/0'/0/0".to_owned(), // m: master key / 44': BIP44 / 0': coin type (Bitcoin) / 0': account / 0: change / 0: address index
        };

        let second_key_pair = KeyPair::derive_child(&key_pair, key_pair.index + 1);

        let mut key_pairs = Vec::new();
        key_pairs.push(key_pair);
        key_pairs.push(second_key_pair);

        return Wallet { key_pairs, address };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_words_all_zeros() {
        // BIP-39 test vector: 128 bits of all zeros
        // Entropy: 00000000000000000000000000000000
        // Expected mnemonic: abandon abandon abandon abandon abandon abandon
        //                    abandon abandon abandon abandon abandon about
        let input: Vec<u8> = vec![0; 128];

        let expected: Vec<String> = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        assert_eq!(Wallet::generate_mnemonic_words(input), expected);
    }

    #[test]
    fn test_mnemonic_words_all_ones() {
        // BIP-39 test vector: 128 bits of all ones
        // Entropy: ffffffffffffffffffffffffffffffff
        // Expected mnemonic: zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong
        let input: Vec<u8> = vec![1; 128];

        let expected: Vec<String> = vec![
            "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "zoo", "wrong",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        assert_eq!(Wallet::generate_mnemonic_words(input), expected);
    }

    #[test]
    fn test_generate_seed() {
        // BIP-39 test vector: all-zeros mnemonic with password "TREZOR"
        // Mnemonic: abandon abandon abandon ... abandon about
        // Password: TREZOR
        // Expected seed (from official BIP-39 test vectors):
        let mnemonic_words: Vec<String> = vec![
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "about",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let seed = Wallet::generate_seed(mnemonic_words, "TREZOR");

        // BIP-39 official test vector seed for this mnemonic + "TREZOR"
        assert_eq!(
            seed,
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708\
             e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b\
             2f001698e7463b04"
        );
        // Seed should be 128 hex chars (64 bytes)
        assert_eq!(seed.len(), 128);
    }

    #[test]
    fn test_new() {
        // Use a 128-char hex seed (64 bytes, as BIP-39 produces)
        let seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708\
                     e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b\
                     2f001698e7463b04"
            .to_owned();

        let wallet = Wallet::new(seed.clone());

        // Private key = second half of seed
        let expected_private_key = &seed[seed.len() / 2..];
        assert_eq!(wallet.key_pairs[0].private_key, expected_private_key);

        // Chain code = first half of seed
        let expected_chain_code = &seed[..seed.len() / 2];
        assert_eq!(wallet.key_pairs[0].chain_code, expected_chain_code);

        assert_eq!(wallet.key_pairs[0].index, 0);
        assert_eq!(wallet.key_pairs[0].path, "m/44'/0'/0'/0/0");

        // Verify we have master + one child key pair
        assert_eq!(wallet.key_pairs.len(), 2);
    }
}
