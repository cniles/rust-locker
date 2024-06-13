use std::{
    collections::HashMap,
    env,
    fs::{read, File},
    path::{Path, PathBuf},
};

use clap::{arg, command, value_parser, Command};
use prompt::Prompt;
use vault::{SealedVault, Vault};

mod prompt;
mod vault;

fn cli() -> clap::ArgMatches {
    command!()
        .arg(arg!(-p --password <STRING> "Optional password. Prefer to use environment variable or prompt"))
        .arg(
            arg!(-f --file <FILE> "Optional vault file name")
                .required(false)
                .default_value(".rustyvault")
                .value_parser(value_parser!(PathBuf)),
        )
        .subcommand_required(true)
        .subcommand(Command::new("list-groups").about("list available secrets"))
        .subcommand(
            Command::new("set")
                .about("set a secret")
                .arg(arg!([group] "group to add secret to").required(true))
                .arg(arg!([key] "name of secret to set").required(true))
                .arg(arg!([value] "Value to set").required(false)),
        )
        .subcommand(Command::new("list-secrets").about("list available secrets").arg(arg!([group] "group to list").required(true)))
        .subcommand(
            Command::new("get")
                .about("get a secret")
                .arg(arg!([group] "group of secret to get").required(true))
                .arg(arg!([key] "key of the secret to get").required(true))
        )
        .subcommand(
            Command::new("create")
            .about("create a new vault file")
        )
        .subcommand(
            Command::new("password").about("change the vault password").arg(arg!([password]).required(false))
        )
        .get_matches()
}

fn try_read_vault(path: &Path) -> Result<Option<SealedVault>, Box<dyn std::error::Error>> {
    if let Ok(exists) = path.try_exists() {
        if exists {
            let bytes = read(path)?;
            Ok(Some(serde_cbor::from_slice::<SealedVault>(
                bytes.as_slice(),
            )?))
        } else {
            println!(
                "A vault does not exist at {}.  Run create command to create a new vault.",
                path.display()
            );

            Ok(None)
        }
    } else {
        panic!("Failed to check for vault file.");
    }
}

fn get_backup_path(vault_path_buf: &PathBuf) -> Result<PathBuf, &str> {
    let vault_file_name = vault_path_buf.file_name();
    if let Some(vault_file_name) = vault_file_name {
        let vault_backup_name = vault_file_name;
        if let Some(vault_backup_name) = vault_backup_name.to_str() {
            let mut vault_backup_path = vault_path_buf.clone();
            vault_backup_path.pop();

            let mut vault_backup_name = vault_backup_name.to_string();
            vault_backup_name.push_str(".bak");
            vault_backup_path.push(vault_backup_name);
            Ok(vault_backup_path)
        } else {
            Err("vault file name must be regular unicode")
        }
    } else {
        Err("vault file must be a regular file")
    }
}

fn backup_and_seal(vault_path: &Path, backup_path: &Path, vault: Vault, password: String) {
    std::fs::copy(vault_path, backup_path).expect("backup failed");

    let sealed_vault = vault.seal(&password).expect("password should be correct");

    let vault_file = File::create(&vault_path).expect("should be able to create vault file");

    serde_cbor::to_writer(vault_file, &sealed_vault)
        .expect("should be able to serialize sealed vault to file");
}

fn main() {
    let mut prompt = Prompt::new();
    let matches = cli();

    let vault_path_buf = matches
        .get_one::<PathBuf>("file")
        .expect("default path should be provided");
    let backup_path_buf = get_backup_path(&vault_path_buf);

    let vault_path = vault_path_buf.as_path();
    let backup_path = if let Ok(ref backup_path_buf) = backup_path_buf {
        backup_path_buf.as_path()
    } else {
        println!(
            "Failed to get backup path: {}",
            backup_path_buf.unwrap_err()
        );
        return;
    };

    let (vault, password) = if let Ok(Some(sealed)) = try_read_vault(&vault_path) {
        // get the password
        let vars = env::vars().collect::<HashMap<String, String>>();

        let password = match vars.get("RUSTYVAULT_PASSWORD") {
            Some(password) => password.clone(),
            None => Prompt::new()
                .secret("Enter the vault password: ")
                .expect("couldn't read in password"),
        };

        (
            Some(sealed.unseal(&password).expect("failed to unseal vault")),
            Some(password),
        )
    } else {
        (None, None)
    };

    if let Some(mut vault) = vault {
        // handle commands if the vault exists
        if let Some(_) = matches.subcommand_matches("create") {
            println!("Vault already exists.");
        } else if let Some(_) = matches.subcommand_matches("list-groups") {
            let groups = vault.keys();
            for group in groups {
                println!("{}", group);
            }
        } else if let Some(matches) = matches.subcommand_matches("set") {
            let group = matches
                .get_one::<String>("group")
                .expect("group must be supplied");
            let key = matches
                .get_one::<String>("key")
                .expect("key arg must be supplied");

            let value = matches.get_one::<String>("value");

            let value = if let Some(value) = value {
                value.clone()
            } else {
                prompt
                    .secret("Enter a new secret value: ")
                    .expect("failed to read secret")
            };

            if vault.get(key).is_some() {
                if prompt
                    .value("Secret exists, replace? [Y/n]: ")
                    .expect("failed to read y/n")
                    .to_uppercase()
                    != "Y"
                {
                    return;
                }
            }

            vault.add(group, key, &value);

            backup_and_seal(
                vault_path,
                backup_path,
                vault,
                password.expect("password should have been entered"),
            );

            return;
        } else if let Some(matches) = matches.subcommand_matches("list-secrets") {
            let group_name = matches
                .get_one::<String>("group")
                .expect("group arg must be supplied");
            if let Some(group) = vault.get(&group_name) {
                for (key, _value) in group {
                    println!("{}", key);
                }
            }
        } else if let Some(matches) = matches.subcommand_matches("password") {
            let new_password = if let Some(password) = matches.get_one::<String>("password") {
                password.clone()
            } else {
                prompt
                    .secret("Enter a new password: ")
                    .expect("password must be read in")
            };

            backup_and_seal(vault_path, backup_path, vault, new_password);
        } else if let Some(matches) = matches.subcommand_matches("get") {
            let group = matches
                .get_one::<String>("group")
                .expect("group arg must be supplied");
            let key = matches
                .get_one::<String>("key")
                .expect("key arg must be supplied");
            if let Some(group) = vault.get(&group) {
                if let Some(key) = group.get(key) {
                    println!("{}", key);
                }
            } else {
                println!("group does not exist");
            }
        }
    } else {
        if let Some(_) = matches.subcommand_matches("create") {
            let v = Vault::new();
            let password = prompt
                .secret("Enter a password to seal the vault: ")
                .expect("couldn't read in password");

            let sealed_vault: SealedVault =
                v.seal(&password).expect("couldn't serialize sealed vault");

            let f = File::create_new(vault_path).expect("couldn't create file");

            serde_cbor::to_writer(f, &sealed_vault).expect("couldn't create new vault");
        } else {
            println!(
                "Command {} requires a vault",
                matches.subcommand_name().unwrap()
            );
        }
    }
}
