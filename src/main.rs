mod wallet;

use wallet::Wallet;

fn main() {
    let mnemonic_words = Wallet::generate_mnemonic_words(128);

    let seed = Wallet::generate_seed(mnemonic_words.clone(), "supersupersecretpasswordploft");

    println!("mnemonic_words: {:?}", mnemonic_words);
    println!("seed from mnemonic_words: {:?}", seed);

    let wallet: Wallet = Wallet::new(seed);

    // super safe stuff amiright
    println!("wallet uuid {}", wallet.id);
    println!("wallet pub key {}", wallet.public_key);
    println!("wallet pub key {}", wallet.private_key);
    println!("wallet chain code {}", wallet.chain_code);
}
