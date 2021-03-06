mod cli;
mod tui;

use async_std::task::block_on;
use roomba::{api, Client};
use serde::{Deserialize, Serialize};
use std::io::Write;
use structopt::StructOpt;

const ROOMBA_CFG: &str = "roomba.toml";

#[derive(Serialize, Deserialize, Default)]
struct Config {
    hostname: Option<String>,
    username: Option<String>,
    password: Option<String>,
    pmap_id: Option<String>,
    user_pmapv_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    rooms: Vec<Room>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Room {
    name: String,
    #[serde(flatten)]
    region: api::Region,
}

impl std::fmt::Display for Room {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

macro_rules! unwrap {
    ($option:expr, $message:expr) => {{
        if $option.is_none() {
            if let Ok(path) = std::env::current_exe() {
                eprintln!($message, exe = path.display());
            } else {
                eprintln!($message, exe = env!("CARGO_PKG_NAME"));
            }

            std::process::exit(1);
        }

        $option.unwrap()
    }};
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Default to "error" log level unless overridden by environment
    env_logger::init_from_env(env_logger::Env::default().filter_or("RUST_LOG", "error"));

    let config_file = dirs::config_dir().unwrap_or_default().join(ROOMBA_CFG);
    let mut config = if config_file.exists() {
        std::fs::read_to_string(&config_file)
            .map_err(|err| err.to_string())
            .and_then(|ref content| toml::from_str(content).map_err(|err| err.to_string()))
            .unwrap_or_else(|err| {
                eprintln!(
                    "Could not read configuration file `{}`: {}",
                    config_file.display(),
                    err
                );
                Config::default()
            })
    } else {
        Config::default()
    };
    let save_config = |config| {
        toml::to_string_pretty(&config)
            .map_err(|err| err.to_string())
            .and_then(|x| std::fs::write(&config_file, x).map_err(|err| err.to_string()))
            .unwrap_or_else(|err| {
                eprintln!(
                    "Could not write configuration file `{}`: {}",
                    config_file.display(),
                    err
                )
            })
    };
    let cli = cli::Cli::from_args();

    match cli.command {
        cli::AnyCommand::Unauthenticated(cli::UnauthenticatedCommand::FindIp { no_save }) => {
            let stdout = std::io::stdout();

            for res in Client::find_ip_address()? {
                let mut fh = stdout.lock();
                if let Ok(info) = res {
                    let _ = writeln!(
                        fh,
                        "found.\nIP address: {}\nBLID/Username/Robot ID: {}",
                        info.ip,
                        info.robot_id()
                            .unwrap_or_else(|err| panic!("{}: {:?}", err, info)),
                    );
                    if !no_save {
                        config.hostname = Some(info.ip.clone());
                        config.username = info.robot_id().ok();
                        save_config(config);
                        break;
                    }
                } else {
                    let _ = fh.write(b".");
                }
                let _ = fh.flush();
            }

            Ok(())
        }
        cli::AnyCommand::Unauthenticated(cli::UnauthenticatedCommand::GetPassword {
            hostname,
            no_save,
        }) => {
            let hostname = match hostname {
                Some(ref x) => x,
                None => unwrap!(
                    config.hostname.as_ref(),
                    "Missing hostname in the configuration. Please run `{exe} find-ip` first"
                ),
            };

            println!(
                "Warning: please hold the Home button for 2 seconds and check that the ring led \
                is blinking blue."
            );

            let password = loop {
                match Client::get_password(hostname) {
                    Err(err) => {
                        println!("{}", err);
                        std::thread::sleep(std::time::Duration::from_secs(3));
                    }
                    Ok(password) => break password,
                }
            };

            println!("Password: {}", password);

            if !no_save {
                config.hostname = Some(hostname.to_string());
                config.password = Some(password);
                save_config(config);
            }

            Ok(())
        }
        cli::AnyCommand::Authenticated(cli) => block_on(async {
            let mut client = Client::new(
                unwrap!(
                    config.hostname.as_ref(),
                    "Missing hostname in the configuration. Please run `{exe} find-ip` first"
                ),
                unwrap!(
                    config.username.as_ref(),
                    "Missing username in the configuration. Please run `{exe} find-ip` first"
                ),
                unwrap!(
                    config.password.as_ref(),
                    "Missing password in the configuration. Please run `{exe} get-password` first"
                ),
                0,
            )
            .await?;

            match cli.command {
                Some(command) => {
                    let pmap_id = unwrap!(
                        config.pmap_id.as_ref(),
                        "Missing pmap_id in the configuration. Please run `{exe} TODO` first"
                    );
                    let user_pmapv_id = unwrap!(
                        config.user_pmapv_id.as_ref(),
                        "Missing user_pmapv_id in the configuration. Please run `{exe} TODO` \
                        first"
                    );

                    let (command, extra) = command.into_command_with_extra(pmap_id, user_pmapv_id);
                    let message = api::Message::new_command(command, extra);

                    client.send_message(&message).await?;
                }
                None => {
                    let map = config
                        .pmap_id
                        .clone()
                        .and_then(|x| config.user_pmapv_id.clone().map(|y| (x, y)));
                    let save = map.is_none();

                    let app = tui::App::new(&mut client, config.rooms.as_slice(), map);
                    let map = app.main_loop().await?;

                    if save {
                        if let Some((pmap_id, user_pmapv_id)) = map {
                            config.pmap_id = Some(pmap_id);
                            config.user_pmapv_id = Some(user_pmapv_id);
                            save_config(config);
                        }
                    }
                }
            }

            Ok(())
        }),
    }
}
