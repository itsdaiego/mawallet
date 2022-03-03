mod wallet;

use wallet::Wallet;

fn main() {
    let mnemonic_words = Wallet::generate_mnemonic_words(128);

    println!("result: {:?}", mnemonic_words);
}
