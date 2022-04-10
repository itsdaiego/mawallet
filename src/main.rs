use mawallet::wallet::Wallet;
use rand::{thread_rng, Rng};
use mawallet::key_pair::KeyPair;

fn main() {
    let mut sequence_vec: Vec<char> = Vec::new();
    let mut rng = thread_rng();

    for _ in 0..128 {
        let random_bit: u32 = rng.gen_range(0..2);
        let bit_string: char = char::from_digit(random_bit, 10).unwrap();
        sequence_vec.push(bit_string);
    }

    println!("sequence vec {:?}", sequence_vec);
    let mnemonic_words = Wallet::generate_mnemonic_words(sequence_vec);

    let seed = Wallet::generate_seed(mnemonic_words.clone(), "supersupersecretpasswordploft");

    println!("mnemonic_words: {:?}", mnemonic_words);
    println!("seed from mnemonic_words: {:?}", seed);

    let mut wallet: Wallet = Wallet::new(seed);

    let parent_key_pair = wallet.key_pairs.last().unwrap();
    let new_index = parent_key_pair.index + 1;

    let key_pair = KeyPair::derive_child(parent_key_pair.private_key.clone(), parent_key_pair.chain_code.clone(), new_index);

    wallet.key_pairs.push(key_pair);

    // super safe stuff amiright
    println!("wallet address {}", wallet.address);

    for key_pair in wallet.key_pairs  {
        println!("---------------------");
        println!("wallet pub key {}", key_pair.public_key);
        println!("wallet pub key {}", key_pair.private_key);
        println!("wallet chain code {}", key_pair.chain_code);
    }
}
