//! Command-line entry point for VTL evidence verification and compaction.

mod cli;

use std::{
    io::{self, Write},
    process::ExitCode,
};

use clap::Parser;
use cli::{Cli, CompactArgs, EvidenceCommand, VerifyArgs, VerifyInput};
use serde_json::Value;
use trackone_evidence::vtl::{
    compact_bundle, verify_archive, verify_bundle_with_policy, verify_remote_bundle,
};
use trackone_evidence::{EvidenceError, Result};

fn run_verify(args: VerifyArgs) -> Result<()> {
    let input = args.input()?;
    let policy = args.policy.into_policy();
    let summary = match input {
        VerifyInput::Directory(root) => verify_bundle_with_policy(&root, &policy)?,
        VerifyInput::Archive(archive) => verify_archive(&archive, &policy)?,
        VerifyInput::Remote(options) => verify_remote_bundle(&options, &policy)?,
    };
    write_summary(&summary, args.json, args.pretty, &mut io::stdout().lock())?;
    if summary["overall"].as_str() != Some("success") {
        return Err(EvidenceError::VerificationFailed(
            "verification did not succeed".into(),
        ));
    }
    Ok(())
}

fn write_summary(summary: &Value, json: bool, pretty: bool, output: &mut impl Write) -> Result<()> {
    if json {
        if pretty {
            serde_json::to_writer_pretty(&mut *output, summary)?;
        } else {
            serde_json::to_writer(&mut *output, summary)?;
        }
        writeln!(output)?;
    } else {
        writeln!(
            output,
            "Disclosure={} Overall={}",
            summary["claimed_disclosure_class"], summary["overall"]
        )?;
    }
    output.flush()?;
    Ok(())
}

fn run_compact(args: CompactArgs) -> Result<()> {
    compact_bundle(
        &args.root,
        &args.output,
        &args.policy.into_policy(),
        args.include_extensions,
    )?;
    Ok(())
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        EvidenceCommand::Verify(args) => run_verify(args),
        EvidenceCommand::Compact(args) => run_compact(args),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn summary_formatting_preserves_json_and_text_output() {
        let summary = json!({"claimed_disclosure_class": "C", "overall": "success"});
        let mut bytes = Vec::new();
        write_summary(&summary, true, false, &mut bytes).unwrap();
        assert_eq!(
            bytes,
            format!("{}\n", serde_json::to_string(&summary).unwrap()).as_bytes()
        );
        bytes.clear();
        write_summary(&summary, true, true, &mut bytes).unwrap();
        assert_eq!(
            bytes,
            format!("{}\n", serde_json::to_string_pretty(&summary).unwrap()).as_bytes()
        );
        bytes.clear();
        write_summary(&summary, false, true, &mut bytes).unwrap();
        assert_eq!(bytes, b"Disclosure=\"C\" Overall=\"success\"\n");
    }

    struct FailedOutput {
        fail_flush: bool,
    }

    impl Write for FailedOutput {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_flush {
                Ok(bytes.len())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "output was closed",
                ))
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "output was closed",
            ))
        }
    }

    #[test]
    fn output_write_and_flush_failures_return_errors() {
        for json in [false, true] {
            for fail_flush in [false, true] {
                let error =
                    write_summary(&json!({}), json, false, &mut FailedOutput { fail_flush })
                        .unwrap_err();
                assert!(error.to_string().contains("output was closed"));
            }
        }
    }
}
