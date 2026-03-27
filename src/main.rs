use mawallet::wallet::Wallet;
use rand::{thread_rng, Rng};

fn main() {
    let mut sequence_vec: Vec<u8> = Vec::new();
    let mut rng = thread_rng();

    for _ in 0..128 {
        let random_bit: u8 = rng.gen_range(0..2);
        sequence_vec.push(random_bit);
    }

    let mnemonic_words = Wallet::generate_mnemonic_words(sequence_vec);
    println!("Mnemonic: {:?}\n", mnemonic_words);

    let seed_a = Wallet::generate_seed(mnemonic_words.clone(), "wallet_a_password");
    let mut wallet_a = Wallet::new(seed_a);

    let seed_b = Wallet::generate_seed(mnemonic_words.clone(), "wallet_b_password");
    let mut wallet_b = Wallet::new(seed_b);

    println!("Wallet A address: {}", wallet_a.address);
    println!("Wallet B address: {}", wallet_b.address);

    wallet_a.coinbase(100_000_000); // 1.0 BTC = 100_000_000 satoshis

    println!("\n--- Initial State ---");
    println!(
        "Wallet A balance: {} satoshis ({} BTC)",
        wallet_a.balance(),
        wallet_a.balance() as f64 / 100_000_000.0
    );
    println!(
        "Wallet B balance: {} satoshis ({} BTC)",
        wallet_b.balance(),
        wallet_b.balance() as f64 / 100_000_000.0
    );

    let amount = 40_000_000; // 0.4 BTC in satoshis
    let fee = 30_000; // 0.0003 BTC fee

    println!("\n--- Performing Transaction ---");
    println!(
        "Wallet A sends {} satoshis ({} BTC) to Wallet B (fee: {} satoshis)",
        amount,
        amount as f64 / 100_000_000.0,
        fee
    );

    let tx = match wallet_a.send_transaction(&wallet_b.address, amount, fee) {
        Ok(tx) => tx,
        Err(err) => {
            eprintln!("Transaction failed: {}", err);
            return;
        }
    };

    println!("\nTransaction ID: {}", tx.txid);
    println!("Inputs:  {}", tx.inputs.len());
    for (i, input) in tx.inputs.iter().enumerate() {
        println!(
            "  input[{}]: prev_txid={}... output_index={}",
            i,
            &input.prev_txid[..16],
            input.prev_output_index
        );
    }
    println!("Outputs: {}", tx.outputs.len());
    for (i, output) in tx.outputs.iter().enumerate() {
        println!(
            "  output[{}]: {} satoshis -> {}...",
            i,
            output.value,
            &output.address[..16]
        );
    }

    wallet_b.receive(&tx);

    println!("\n--- Final State ---");
    println!(
        "Wallet A balance: {} satoshis ({} BTC)",
        wallet_a.balance(),
        wallet_a.balance() as f64 / 100_000_000.0
    );
    println!(
        "Wallet B balance: {} satoshis ({} BTC)",
        wallet_b.balance(),
        wallet_b.balance() as f64 / 100_000_000.0
    );
    println!("Wallet A UTXOs: {}", wallet_a.utxos.len());
    println!("Wallet B UTXOs: {}", wallet_b.utxos.len());
    println!(
        "Wallet A key pairs: {} (new change key derived)",
        wallet_a.key_pairs.len()
    );
}
