use sha2::{Digest, Sha256};

pub struct KeyPair {
    pub private_key: String,
    pub public_key: String,
    pub chain_code: String,
    pub index: u32,
    pub path: String,
}

impl KeyPair {
    fn insert_new_path(path: String, index: u32) -> String {
        // m/44'/0'/0'/0/0 -> m/44'/0'/0'/0/1
        // m = master
        // 44' = BIP-44
        // 0' = coin (hardened)
        // 0' = account_number
        // 0 = action type (sending/receiving or change) (hardened)
        // 0 = address index
        let last_slash = path.rfind('/').expect("invalid path: no '/' found");
        format!("{}/{}", &path[..last_slash], index)
    }

    pub fn derive_child(parent_key_pair: &KeyPair, index: u32) -> KeyPair {
        let mut hasher = Sha256::new();

        hasher.update(&parent_key_pair.private_key);
        hasher.update(&parent_key_pair.chain_code);
        hasher.update(parent_key_pair.index.to_be_bytes());

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
            index: index + 1,
            path: KeyPair::insert_new_path(parent_key_pair.path.clone(), index + 1),
        };
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

        let parent_key_pair = &KeyPair {
            private_key: parent_private_key,
            public_key: "F20F33756995A0385616D7A1A7F3B2A173B71DDA0B329A345A4CC8A4C51C2E1A"
                .to_owned(),
            chain_code: parent_chain_code,
            path: "m/44'/0'/0'/0/0".to_owned(),
            index,
        };

        let key_pair = KeyPair::derive_child(parent_key_pair, index);

        assert_eq!(
            key_pair.public_key,
            "398B46F42AFB6AB6FDAE6146636CCA085B42DEFD09DF91D98B738476EF4E6582"
        );
        assert_eq!(key_pair.private_key, "329EDA10440E94064EA294060327CC40");
        assert_eq!(key_pair.chain_code, "DFE9D1DDD450CCD768B9C9477361476F");
        assert_eq!(key_pair.path, "m/44'/0'/0'/0/1");
        assert_eq!(key_pair.index, 1);
    }
}
