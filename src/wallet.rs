use uuid::Uuid;

pub struct Wallet {
    pub id: Uuid,
    pub seed: u32
}

impl Key for Wallet { 
    fn create_key() -> String {
        return String::from("some string")
    }
}

trait Key {
    fn  create_key() -> String;
}
