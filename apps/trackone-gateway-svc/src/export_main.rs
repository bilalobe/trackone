use std::{collections::BTreeSet, path::PathBuf};

use clap::Parser;
use trackone_gateway_svc::config::{DatabaseConfig, parse_ledger_id};
use trackone_gateway_svc::error::{ResultContext, RuntimeError};
use trackone_gateway_svc::postgres_connection::connect_postgres;
use trackone_gateway_svc::snapshot::{DisclosureClass, export_snapshot};

#[derive(Parser)]
#[command(
    name = "trackone-vtl-export",
    version,
    about = "Export an immutable VTL disclosure snapshot"
)]
struct ExportConfig {
    #[command(flatten)]
    database: DatabaseConfig,

    /// Ledger identifier, 32 lowercase hexadecimal characters
    #[arg(long, env = "TRACKONE_LEDGER_ID", value_parser = parse_ledger_id)]
    ledger_id: String,

    /// Segment number to export
    #[arg(long)]
    segment_number: u64,

    /// Disclosure class: A, B or C
    #[arg(long, value_parser = parse_class)]
    class: DisclosureClass,

    /// Selected batch number (repeat for each Class B batch)
    #[arg(long = "batch")]
    batches: Vec<u64>,

    /// Destination directory
    #[arg(long)]
    output: PathBuf,
}

fn parse_class(raw: &str) -> Result<DisclosureClass, String> {
    DisclosureClass::parse(raw).map_err(|error| error.to_string())
}

fn main() -> Result<(), RuntimeError> {
    let config = ExportConfig::parse();
    let batches: BTreeSet<_> = config.batches.iter().copied().collect();
    if batches.len() != config.batches.len() {
        return Err::<(), _>("duplicate --batch selection").context("invalid export configuration");
    }
    let mut client = connect_postgres(
        &config.database.url,
        config.database.postgres_tls_mode,
        config.database.ca_file(),
    )
    .context("cannot connect snapshot exporter to PostgreSQL")?;
    export_snapshot(
        &mut client,
        &config.ledger_id,
        config.segment_number,
        config.class,
        &batches,
        &config.output,
    )
    .context(format!(
        "cannot export segment {} to {}",
        config.segment_number,
        config.output.display()
    ))?;
    Ok(())
}
