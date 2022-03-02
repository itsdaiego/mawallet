use rand::Rng;
use uuid::Uuid;

pub struct Wallet {
    pub id: Uuid,
    pub seed: String
}

impl Wallet {
    pub fn create_seed(index: &'static str) -> String  {
        let mut rand_number: String = rand::thread_rng().gen_range(0..u32::MAX)
            .to_string();

        rand_number.push_str(index);

        return rand_number;
    }
}

trait Seed {
    fn  create_seed(index: &'static str) -> String;
}
