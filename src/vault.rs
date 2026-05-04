use std::collections::HashMap;

use crypto::{
    aes::{cbc_decryptor, cbc_encryptor},
    blockmodes::{self, PkcsPadding},
    buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer},
    symmetriccipher::{Decryptor, Encryptor},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

pub struct Vault {
    groups: HashMap<String, HashMap<String, Vec<String>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SealedVault {
    encrypted_key: Vec<u8>,
    encrypted_vault: Vec<u8>,
    key_iv: [u8; 16],
    vault_iv: [u8; 16],
    salt: [u8; 16],
    pass_key_hash: [u8; 24],
}

fn decrypt_slice<T: Decryptor + 'static + ?Sized>(
    encrypted_data: &[u8],
    decryptor: &mut Box<T>,
) -> Vec<u8> {
    let mut reader = RefReadBuffer::new(encrypted_data);

    let mut buff = [0; 4096];
    let mut writer = RefWriteBuffer::new(&mut buff);

    let mut decrypted_data = Vec::new();

    loop {
        let result = decryptor.decrypt(&mut reader, &mut writer, true).unwrap();

        decrypted_data.extend(
            writer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    decrypted_data
}

fn encrypt_slice<T: Encryptor + 'static + ?Sized>(
    encrypted_data: &[u8],
    encryptor: &mut Box<T>,
) -> Vec<u8> {
    let mut reader = RefReadBuffer::new(encrypted_data);

    let mut buff = [0; 4096];
    let mut writer = RefWriteBuffer::new(&mut buff);

    let mut encrypted_data = Vec::new();

    loop {
        let result = encryptor.encrypt(&mut reader, &mut writer, true).unwrap();

        encrypted_data.extend(
            writer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    encrypted_data
}

impl SealedVault {
    pub fn unseal(self, password: &str) -> Result<Vault, Box<dyn std::error::Error>> {
        let pass_key = bcrypt::bcrypt(bcrypt::DEFAULT_COST, self.salt, password.as_bytes());
        let pass_key_hash = bcrypt::bcrypt(bcrypt::DEFAULT_COST, self.salt, &pass_key);

        if pass_key_hash != self.pass_key_hash {
            return Err("wrong password".into());
        } else {
            let mut decryptor: Box<dyn Decryptor + 'static> = cbc_decryptor(
                crypto::aes::KeySize::KeySize192,
                &pass_key,
                &self.key_iv,
                PkcsPadding,
            );

            let key = decrypt_slice(&self.encrypted_key, &mut decryptor);

            let mut decryptor = cbc_decryptor(
                crypto::aes::KeySize::KeySize256,
                &key,
                &self.vault_iv,
                PkcsPadding,
            );

            let data = decrypt_slice(&self.encrypted_vault, &mut decryptor);

            let groups = match serde_cbor::from_slice::<HashMap<String, HashMap<String, Vec<String>>>>(&data) {
                Ok(groups) => groups,
                Err(_) => {
                    // Migrate old format where secrets were stored as a plain String rather than Vec<String>.
                    let old = serde_cbor::from_slice::<HashMap<String, HashMap<String, String>>>(&data)
                        .map_err(|_| "vault data is corrupt or in an unrecognized format")?;
                    old.into_iter()
                        .map(|(group, secrets)| {
                            (group, secrets.into_iter().map(|(k, v)| (k, vec![v])).collect())
                        })
                        .collect()
                }
            };

            Ok(Vault { groups })
        }
    }
}

impl Vault {
    pub fn new() -> Self {
        Vault {
            groups: HashMap::new(),
        }
    }

    pub fn add(&mut self, group_name: &str, key: &str, value: &str) {
        if !self.groups.contains_key(group_name) {
            self.groups.insert(group_name.to_string(), HashMap::new());
        }

        let group = self.groups.get_mut(group_name).unwrap();

        if group.contains_key(key) {
            group.get_mut(key).unwrap().push(value.to_string());
        } else {
            group.insert(key.to_string(), vec![value.to_string()]);
        }
    }

    pub fn get(&self, group: &str) -> Option<&HashMap<String, Vec<String>>> {
        self.groups.get(group)
    }

    pub fn keys(&self) -> Vec<&String> {
        self.groups.keys().collect()
    }

    fn rand_arr<const N: usize>() -> [u8; N] {
        let mut r = [0; N];
        OsRng.fill_bytes(&mut r);
        r
    }

    fn serialize(&self) -> Vec<u8> {
        let result = serde_cbor::to_vec(&self.groups);
        result.unwrap()
    }

    // consumes vault and returns a sealed copy
    pub fn seal(self, password: &str) -> Result<SealedVault, String> {
        // generate a random key & iv for encrypting vault
        let iv = Vault::rand_arr::<16>();
        let key = Vault::rand_arr::<32>();

        // create encryptor for vault data
        let mut encryptor = cbc_encryptor(
            crypto::aes::KeySize::KeySize256,
            &key,
            &iv,
            blockmodes::PkcsPadding,
        );
        let encrypted_vault = encrypt_slice(&self.serialize(), &mut encryptor);

        let salt = Vault::rand_arr::<16>();
        let pass_key = bcrypt::bcrypt(bcrypt::DEFAULT_COST, salt, password.as_bytes());
        let pass_iv = Vault::rand_arr::<16>();

        // hash the key generated from the password
        let pass_key_hash = bcrypt::bcrypt(bcrypt::DEFAULT_COST, salt, &pass_key);

        // create encryptor for vault key
        let mut encryptor = cbc_encryptor(
            crypto::aes::KeySize::KeySize192,
            &pass_key,
            &pass_iv,
            blockmodes::PkcsPadding,
        );

        let encrypted_key = encrypt_slice(&key, &mut encryptor);

        Ok(SealedVault {
            encrypted_key,
            encrypted_vault,
            key_iv: pass_iv,
            vault_iv: iv,
            salt,
            pass_key_hash,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{SealedVault, Vault};

    #[test]
    fn vault_new() {
        let _v = Vault::new();
    }

    #[test]
    fn vault_set_get() {
        let mut v = Vault::new();
        assert!(!v.groups.contains_key("group"));
        v.add("group", "key", "value");
        assert!(v.groups.contains_key("group"));
        assert_eq!(
            v.groups
                .get("group")
                .unwrap()
                .get("key")
                .unwrap()
                .first()
                .unwrap(),
            "value"
        );
    }

    #[test]
    fn vault_lock_unlock() {
        let mut v = Vault::new();

        v.add("foo", "bar", "baz");

        let sealed = v.seal("mypassword").unwrap();

        let sealed_bytes = serde_cbor::to_vec(&sealed).unwrap();
        let sealed = serde_cbor::from_slice::<SealedVault>(&sealed_bytes).unwrap();

        let v = sealed.unseal("mypassword").unwrap();
        assert_eq!(
            v.get("foo").unwrap().get("bar").unwrap().first(),
            Some("baz".to_string()).as_ref()
        );
    }
}
