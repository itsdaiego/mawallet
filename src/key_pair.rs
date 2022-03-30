use sha2::{Digest, Sha256};

pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
    pub chain_code: String,
    pub index: u32,
}

impl KeyPair {
    pub fn derive_child(parent_private_key: String, parent_chain_code: String, index: u32) -> KeyPair {
        let mut hasher = Sha256::new();

        hasher.update(&parent_private_key);
        hasher.update(&parent_chain_code);
        hasher.update(&index.to_string());

        let hash: String = format!("{:X}", hasher.finalize());  

        let private_key = hash[hash.len() / 2..].to_owned();

        let mut private_key_hasher = Sha256::new();
        private_key_hasher.update(&private_key);

        let public_key = format!("{:X}", private_key_hasher.finalize());
        let chain_code = hash[..hash.len() / 2].to_owned();

        return KeyPair {
            private_key,
            public_key,
            chain_code,
            index: index + 1
        }
    }
}
