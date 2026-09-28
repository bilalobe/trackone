use postgres::Client;
use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;
use trackone_gateway_svc::postgres_connection::{PostgresTlsMode, connect_postgres};
use trackone_gateway_svc::snapshot::{DisclosureClass, export_snapshot};

fn usage() -> ! {
    eprintln!(
        "usage: trackone-vtl-export --ledger-id ID --segment-number N --class A|B|C [--batch N ...] --output DIR"
    );
    std::process::exit(2);
}

fn take_value(args: &[String], index: &mut usize, name: &str) -> String {
    *index += 1;
    args.get(*index).cloned().unwrap_or_else(|| {
        eprintln!("missing value for {name}");
        usage();
    })
}

fn connect() -> Result<Client, Box<dyn std::error::Error>> {
    let database_url = env::var("TRACKONE_DATABASE_URL")
        .map_err(|_| "required environment variable TRACKONE_DATABASE_URL is missing")?;
    let mode = PostgresTlsMode::parse(
        &env::var("TRACKONE_POSTGRES_TLS_MODE").unwrap_or_else(|_| "verify-full".into()),
    )?;
    let ca_file = env::var("TRACKONE_POSTGRES_CA_FILE")
        .ok()
        .filter(|value| !value.is_empty());
    connect_postgres(&database_url, mode, ca_file.as_deref())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let mut ledger_id = None;
    let mut segment_number = None;
    let mut class = None;
    let mut batches = BTreeSet::new();
    let mut output: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--ledger-id" => ledger_id = Some(take_value(&args, &mut index, "--ledger-id")),
            "--segment-number" => {
                segment_number = Some(
                    take_value(&args, &mut index, "--segment-number")
                        .parse::<u64>()
                        .unwrap_or_else(|_| {
                            eprintln!("invalid --segment-number");
                            usage();
                        }),
                );
            }
            "--class" => {
                class = Some(
                    DisclosureClass::parse(&take_value(&args, &mut index, "--class"))
                        .unwrap_or_else(|error| {
                            eprintln!("{error}");
                            usage();
                        }),
                );
            }
            "--batch" => {
                let batch = take_value(&args, &mut index, "--batch")
                    .parse::<u64>()
                    .unwrap_or_else(|_| {
                        eprintln!("invalid --batch");
                        usage();
                    });
                if !batches.insert(batch) {
                    eprintln!("duplicate --batch {batch}");
                    usage();
                }
            }
            "--output" => output = Some(PathBuf::from(take_value(&args, &mut index, "--output"))),
            _ => usage(),
        }
        index += 1;
    }
    let ledger_id = ledger_id.unwrap_or_else(|| usage());
    let segment_number = segment_number.unwrap_or_else(|| usage());
    let class = class.unwrap_or_else(|| usage());
    let output = output.unwrap_or_else(|| usage());
    let mut client = connect()?;
    export_snapshot(
        &mut client,
        &ledger_id,
        segment_number,
        class,
        &batches,
        &output,
    )?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}
