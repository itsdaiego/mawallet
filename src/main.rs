use mawallet::key_pair::KeyPair;
use mawallet::wallet::Wallet;
use rand::{thread_rng, Rng};

fn main() {
    let mut sequence_vec: Vec<u8> = Vec::new();
    let mut rng = thread_rng();

    for _ in 0..128 {
        let random_bit: u8 = rng.gen_range(0..2);
        sequence_vec.push(random_bit);
    }

    println!("sequence vec {:?}", sequence_vec);
    let mnemonic_words = Wallet::generate_mnemonic_words(sequence_vec);

    let seed = Wallet::generate_seed(mnemonic_words.clone(), "supersupersecretpasswordploft");

    println!("mnemonic_words: {:?}", mnemonic_words);
    println!("seed from mnemonic_words: {:?}", seed);

    let mut wallet: Wallet = Wallet::new(seed);

    let parent_key_pair = wallet.key_pairs.last().unwrap();
    let new_index = parent_key_pair.index + 1;

    let key_pair = KeyPair::derive_child(parent_key_pair, new_index);

    wallet.key_pairs.push(key_pair);

    println!(
        "wallet address {} {}",
        wallet.address,
        wallet.key_pairs.len()
    );

    for key_pair in wallet.key_pairs {
        println!("---------------------");
        println!("wallet pub key {}", key_pair.public_key);
        println!("wallet pub key {}", key_pair.private_key);
        println!("wallet chain code {}", key_pair.chain_code);
        println!("wallet path {}", key_pair.path);
    }
}
