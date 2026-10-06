//! Shared PostgreSQL transport configuration for the gateway and exporter.

use native_tls::{Certificate, TlsConnector};
use postgres::config::SslMode;
use postgres::{Client, Config, NoTls};
use postgres_native_tls::MakeTlsConnector;
use std::fs;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresTlsMode {
    VerifyFull,
    Disable,
}

impl PostgresTlsMode {
    pub fn parse(raw: &str) -> Result<Self, Box<dyn std::error::Error>> {
        match raw {
            "verify-full" => Ok(Self::VerifyFull),
            "disable" => Ok(Self::Disable),
            _ => Err(
                "TRACKONE_POSTGRES_TLS_MODE must be verify-full or disable (development only)"
                    .into(),
            ),
        }
    }
}

pub fn connect_postgres(
    database_url: &str,
    mode: PostgresTlsMode,
    ca_file: Option<&str>,
) -> Result<Client, Box<dyn std::error::Error>> {
    let mut config = Config::from_str(database_url)?;
    config.connect_timeout(std::time::Duration::from_secs(5));
    match mode {
        PostgresTlsMode::VerifyFull => {
            config.ssl_mode(SslMode::Require);
            let mut builder = TlsConnector::builder();
            if let Some(path) = ca_file {
                builder.add_root_certificate(Certificate::from_pem(&fs::read(path)?)?);
            }
            Ok(config.connect(MakeTlsConnector::new(builder.build()?))?)
        }
        PostgresTlsMode::Disable => {
            config.ssl_mode(SslMode::Disable);
            Ok(config.connect(NoTls)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PostgresTlsMode;

    #[test]
    fn postgres_tls_mode_accepts_only_explicit_supported_values() {
        assert_eq!(
            PostgresTlsMode::parse("verify-full").unwrap(),
            PostgresTlsMode::VerifyFull
        );
        assert_eq!(
            PostgresTlsMode::parse("disable").unwrap(),
            PostgresTlsMode::Disable
        );
        assert!(PostgresTlsMode::parse("prefer").is_err());
    }
}
