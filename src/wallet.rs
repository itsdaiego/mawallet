use rand::{thread_rng, Rng};
use uuid::Uuid;
use sha2::{Sha256, Digest};
use std::fs;

pub struct Wallet {
    pub id: Uuid,
    pub seed: String
}

impl Wallet {
    pub fn generate_mnemonic_words(sequence_in_bits: u32) -> Vec<String> {
        let mut sequence_vec: Vec<char> = Vec::new();
        let mut rng = thread_rng();

        for _ in 1..sequence_in_bits {
            let random_bit: u32 = rng.gen_range(0..2);
            let bit_string: char = char::from_digit(random_bit, 10).unwrap();
            sequence_vec.push(bit_string);
        }

        let mut hasher = Sha256::new();

        let sequence_32_string: String = sequence_vec
            .iter()
            .take(32)
            .map(|x| -> String { x.to_string() })
            .collect();

        hasher.update(sequence_32_string);

        let checksum_hash =  format!("{:X}", hasher.finalize());

        let mut sequence_string: String= sequence_vec
            .iter()
            .collect();

        sequence_string.push_str(&checksum_hash);

        let mut sequence_segments = Vec::new();
        let mut segment_bit = String::new();

        for i in 1..sequence_vec.len() {
            let sequence_vec_item = sequence_vec[i].clone();
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

    pub fn generate_seed(index: &'static str) -> String  {
        let mut rand_number: String = rand::thread_rng().gen_range(0..u32::MAX)
            .to_string();

        rand_number.push_str(index);

        return rand_number;
    }
}
