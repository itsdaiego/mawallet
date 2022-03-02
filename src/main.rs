mod wallet;

use wallet::Wallet;

fn main() {
    let seed = Wallet::create_seed("0");

    println!("Hello, world! {}", seed);
}
