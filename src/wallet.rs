use rand::{thread_rng, Rng};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::fs;
use ring::{digest, pbkdf2};

pub struct Wallet {
    pub id: Uuid,
    pub seed: String
}

impl Wallet {
    pub fn generate_mnemonic_words(sequence_in_bits: u32) -> Vec<String> {
        let mut sequence_vec: Vec<char> = Vec::new();
        let mut rng = thread_rng();

        for _ in 0..sequence_in_bits {
            let random_bit: u32 = rng.gen_range(0..2);
            let bit_string: char = char::from_digit(random_bit, 10).unwrap();
            sequence_vec.push(bit_string);
        }

        let mut hasher = Sha256::new();

        let sequence_string: String = sequence_vec
            .iter()
            .map(|x| -> String { x.to_string() })
            .collect();

        hasher.update(sequence_string);

        let checksum_hash: String =  format!("{:X}", hasher.finalize());

        let checksum_in_binary: String = checksum_hash.clone()
            .into_bytes()
            .iter()
            .map(|x| -> String { format!("0{:b}", x) })
            .collect();

        let checksum_in_binary_clone = checksum_in_binary.clone();

        let checksum_4_bit_vec: Vec<char> = checksum_in_binary_clone[0..4].chars().collect();

        let entropy_sequence = [sequence_vec, checksum_4_bit_vec].concat();

        let mut sequence_segments = Vec::new();
        let mut segment_bit = String::new();

        for i in 0..entropy_sequence.len() {
            let sequence_vec_item = entropy_sequence[i].clone();
            segment_bit.push_str(&sequence_vec_item.to_string());

            if i % 11 == 0 {
                let clone_bit = segment_bit.clone();
                sequence_segments.push(clone_bit);
                segment_bit.clear();
            }
        }

        let sequence_segments_ids: Vec<i32> = sequence_segments
            .iter()
            .map(|x| -> i32 { i32::from_str_radix(x, 2).unwrap() })
            .collect();

        let mut wordlist: Vec<String> = fs::read_to_string("files/bip39wordlist.txt").unwrap()
            .split("\n")
            .map(|x| -> String { x.to_string() })
            .collect();

        return sequence_segments_ids
            .iter()
            .map(|&x| -> String { wordlist.remove(x as usize) })
            .collect();

    }

    pub fn generate_seed(mnemonic_words: Vec<String>, password: &'static str) -> String  {
        let mnemonic_words_string: String = mnemonic_words
            .iter()
            .map(|x| -> String { x.to_string() })
            .collect();

        let mut seed_bytes = [0u8; digest::SHA256_OUTPUT_LEN];
        let salt = format!("mnemonic{}", password);

        let pbkdf2_iterations = std::num::NonZeroU32::new(100_000).unwrap();

        static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;

        pbkdf2::derive(
            PBKDF2_ALG,
            pbkdf2_iterations,
            salt.as_bytes(),
            mnemonic_words_string.as_bytes(), 
            &mut seed_bytes
        );

        let seed: String = seed_bytes
            .iter()
            .map(|x| -> String { format!("{:x?}", x) })
            .collect();

        return seed;
    }
}
