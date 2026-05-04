use std::{
    collections::HashMap,
    env,
    fs::{create_dir_all, read, File},
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::{arg, command, value_parser, Arg, Command};
use prompt::Prompt;
use vault::{SealedVault, Vault};

mod prompt;
mod vault;

fn cli() -> clap::ArgMatches {
    let mut default_vault_path = env::home_dir()
        .or_else(|| Some(PathBuf::from_str(".").unwrap()))
        .unwrap();

    default_vault_path.push(".rust-locker");
    default_vault_path.push("vault");

    let default_vault_file_name = default_vault_path.into_os_string();

    command!()
        .arg(arg!(-p --password <STRING> "Optional password. Prefer to use environment variable or prompt"))
        .arg(
            arg!(-f --file <FILE> "Optional vault file name")
                .required(false)
                .default_value(default_vault_file_name)
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
                .arg(arg!([version] "version of the secret to get").value_parser(value_parser!(i32)).required(false))
        )
        .subcommand(
            Command::new("create")
            .about("create a new vault file")
        )
        .subcommand(
            Command::new("password").about("change the vault password").arg(arg!([password]).required(false))
        )
        .subcommand(
            Command::new("generate")
                .about("generate a secret and print it to stdout")
                .arg(
                    Arg::new("length")
                        .short('L')
                        .value_name("N")
                        .help("Length of secret (default: 12)")
                        .num_args(1)
                        .default_value("12")
                        .value_parser(value_parser!(usize)),
                )
                .arg(
                    Arg::new("uppercase")
                        .short('u')
                        .value_name("MIN")
                        .help("Include uppercase letters with optional minimum count")
                        .num_args(0..=1)
                        .default_missing_value("1")
                        .value_parser(value_parser!(usize)),
                )
                .arg(
                    Arg::new("lowercase")
                        .short('l')
                        .value_name("MIN")
                        .help("Include lowercase letters with optional minimum count")
                        .num_args(0..=1)
                        .default_missing_value("1")
                        .value_parser(value_parser!(usize)),
                )
                .arg(
                    Arg::new("digits")
                        .short('d')
                        .value_name("MIN")
                        .help("Include digits with optional minimum count")
                        .num_args(0..=1)
                        .default_missing_value("1")
                        .value_parser(value_parser!(usize)),
                )
                .arg(
                    Arg::new("special")
                        .short('s')
                        .value_name("SPEC")
                        .help("Include special chars; SPEC is optional charset then optional min (e.g. !@#2)")
                        .num_args(0..=1)
                        .default_missing_value(""),
                ),
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

fn parse_special_spec(spec: &str) -> (String, usize) {
    let trimmed = spec.trim_end_matches(|c: char| c.is_ascii_digit());
    let digits = &spec[trimmed.len()..];
    let min = if digits.is_empty() { 1 } else { digits.parse().unwrap_or(1) };
    let charset = if trimmed.is_empty() {
        "!@#$%^&*()-_=+".to_string()
    } else {
        trimmed.to_string()
    };
    (charset, min)
}

fn generate_secret(
    length: usize,
    uppercase: Option<usize>,
    lowercase: Option<usize>,
    digits: Option<usize>,
    special: Option<(String, usize)>,
) -> String {
    use rand::rngs::OsRng;
    use rand::seq::SliceRandom;

    let upper_chars: Vec<char> = ('A'..='Z').collect();
    let lower_chars: Vec<char> = ('a'..='z').collect();
    let digit_chars: Vec<char> = ('0'..='9').collect();

    let mut rng = OsRng;
    let mut required: Vec<char> = Vec::new();
    let mut pool: Vec<char> = Vec::new();

    if let Some(min) = uppercase {
        for _ in 0..min {
            required.push(*upper_chars.choose(&mut rng).unwrap());
        }
        pool.extend_from_slice(&upper_chars);
    }
    if let Some(min) = lowercase {
        for _ in 0..min {
            required.push(*lower_chars.choose(&mut rng).unwrap());
        }
        pool.extend_from_slice(&lower_chars);
    }
    if let Some(min) = digits {
        for _ in 0..min {
            required.push(*digit_chars.choose(&mut rng).unwrap());
        }
        pool.extend_from_slice(&digit_chars);
    }
    if let Some((ref charset, min)) = special {
        let special_chars: Vec<char> = charset.chars().collect();
        for _ in 0..min {
            required.push(*special_chars.choose(&mut rng).unwrap());
        }
        pool.extend_from_slice(&special_chars);
    }

    let effective_length = length.max(required.len());
    let mut result = required;
    for _ in 0..(effective_length - result.len()) {
        result.push(*pool.choose(&mut rng).unwrap());
    }

    result.shuffle(&mut rng);
    result.into_iter().collect()
}

fn main() {
    let mut prompt = Prompt::new();
    let matches = cli();

    if let Some(gen_matches) = matches.subcommand_matches("generate") {
        let length = *gen_matches.get_one::<usize>("length").unwrap_or(&12);
        let uppercase = gen_matches.get_one::<usize>("uppercase").copied();
        let lowercase = gen_matches.get_one::<usize>("lowercase").copied();
        let digits = gen_matches.get_one::<usize>("digits").copied();
        let special_spec = gen_matches.get_one::<String>("special");

        let (uc, lc, dg, sp) = if uppercase.is_none() && lowercase.is_none() && digits.is_none() && special_spec.is_none() {
            (Some(1usize), Some(1usize), Some(1usize), None)
        } else {
            (uppercase, lowercase, digits, special_spec.map(|s| parse_special_spec(s)))
        };

        println!("{}", generate_secret(length, uc, lc, dg, sp));
        return;
    }

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

            let version = matches.get_one::<i32>("version");

            if let Some(group) = vault.get(&group) {
                if let Some(values) = group.get(key) {
                    if let Some(version) = version {
                        let version = if *version < 0 {
                            (values.len() as i32) + *version - 1
                        } else {
                            *version
                        } as usize;

                        println!("{}", values[version]);
                    } else {
                        println!("{}", values.last().unwrap());
                    }
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

            let prefix = vault_path.parent().unwrap();

            create_dir_all(prefix).expect("could not create parent directory for vault file");

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
