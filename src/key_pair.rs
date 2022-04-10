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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_child() {
        let parent_private_key = "014f3fe7f36f3e768f659ead704a6c".to_owned();
        let parent_chain_code = "ce313b6a66b6f56fbe7a6bb8d7c84".to_owned();
        let index = 0;

        let key_pair = KeyPair::derive_child(parent_private_key, parent_chain_code, index);

        assert_eq!(key_pair.public_key, "F20F33756995A0385616D7A1A7F3B2A173B71DDA0B329A345A4CC8A4C51C2E1A");
        assert_eq!(key_pair.private_key, "C150BE0E9BFACD9014C3C1F0ED230A7D");
        assert_eq!(key_pair.chain_code, "F2332D68100B416B81EDD94E169D8B5E");
        assert_eq!(key_pair.index, 1);
    }
}
