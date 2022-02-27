mod wallet;
mod utils;

use wallet::Wallet;
use utils::create_seed;
use uuid::Uuid;

fn main() {
    let wallet = Wallet { id: Uuid::new_v4(), seed: create_seed() };

    println!("Hello, world! {} {}", wallet.seed, wallet.id);
}
