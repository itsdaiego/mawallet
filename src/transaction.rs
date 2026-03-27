use sha2::{Digest, Sha256};

pub struct UTXO {
    pub txid: String,
    pub output_index: u32,
    pub value: u64, // in satoshis (1 BTC = 100_000_000 satoshis)
    pub address: String,
}

pub struct TxInput {
    pub prev_txid: String,
    pub prev_output_index: u32,
    pub signature: String, // simplified: hash(private_key + transaction_data)
}

pub struct TxOutput {
    pub value: u64,
    pub address: String,
}

pub struct Transaction {
    pub txid: String,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

pub struct ComputedUTXO {
    pub txid: String,
    pub output_index: u32,
    pub value: u64,
}

impl Transaction {
    fn calculate_total_input(
        computed_utxos: &[ComputedUTXO],
        transaction_amount: u64,
        selected_utxo_indices: &mut Vec<usize>,
    ) -> u64 {
        let mut total_input = 0;

        for (i, computed_utxo) in computed_utxos.iter().enumerate() {
            selected_utxo_indices.push(i);
            total_input += computed_utxo.value;
            if total_input >= transaction_amount{
                break;
            }
        };

        return total_input;
    }

    pub fn create(
        computed_utxos: &[ComputedUTXO],
        sender_private_key: &str,
        recipient_address: &str,
        change_address: &str,
        amount: u64,
        fee: u64,
    ) -> (Transaction, Vec<usize>) {
        let mut selected_utxo_indices: Vec<usize> = Vec::new();

        let total_input = Self::calculate_total_input(computed_utxos, amount + fee, &mut selected_utxo_indices);

        if total_input < amount + fee {
            panic!(
                "Insufficient funds: have {} satoshis, need {} (amount {} + fee {})",
                total_input,
                amount + fee,
                amount,
                fee
            );
        }

        let mut outputs: Vec<TxOutput> = Vec::new();

        outputs.push(TxOutput {
            value: amount,
            address: recipient_address.to_owned(),
        });

        let change = total_input - amount - fee;
        if change > 0 {
            outputs.push(TxOutput {
                value: change,
                address: change_address.to_owned(),
            });
        }

        let mut tx_data = String::new();
        for &i in &selected_utxo_indices {
            let computed_utxo = &computed_utxos[i];
            tx_data.push_str(&computed_utxo.txid);
            tx_data.push_str(&computed_utxo.output_index.to_string());
        }
        for output in &outputs {
            tx_data.push_str(&output.value.to_string());
            tx_data.push_str(&output.address);
        }

        let mut data_hasher = Sha256::new();
        data_hasher.update(tx_data.as_bytes());
        let tx_data_hash = format!("{:X}", data_hasher.finalize());

        let mut inputs: Vec<TxInput> = Vec::new();
        for &i in &selected_utxo_indices {
            let computed_utxo = &computed_utxos[i];

            let mut sig_hasher = Sha256::new();
            sig_hasher.update(sender_private_key.as_bytes());
            sig_hasher.update(tx_data_hash.as_bytes());
            let signature = format!("{:X}", sig_hasher.finalize());

            inputs.push(TxInput {
                prev_txid: computed_utxo.txid.clone(),
                prev_output_index: computed_utxo.output_index,
                signature,
            });
        }

        // 5. Compute the transaction ID (hash of the full transaction contents)
        let mut txid_hasher = Sha256::new();
        txid_hasher.update(tx_data_hash.as_bytes());
        for input in &inputs {
            txid_hasher.update(input.signature.as_bytes());
        }
        let txid = format!("{:X}", txid_hasher.finalize());

        (
            Transaction {
                txid,
                inputs,
                outputs,
            },
            selected_utxo_indices,
        )
    }
}
