//! honk-tool — CLI toolbox for honk diagnostics.
//!
//! Currently implemented: `sub` (subscription availability check),
//! `bpf` (pinned-map quick reads), `diagnose` (one-shot health check),
//! `geosite` / `geoip` (dat file content search).

mod bpf;
mod diagnose;
mod geo;
mod sub;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "honk-tool", version = honk_core::VERSION, about = "honk CLI toolbox", disable_version_flag = true)]
#[command(arg(clap::Arg::new("version")
    .short('v')
    .long("version")
    .action(clap::ArgAction::Version)
    .help("Print version")))]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a subscription and probe every node: server families, per-family
    /// proxy connectivity, and proxied latency.
    Sub(sub::SubArgs),
    /// Quick reads of the running engine's pinned eBPF maps.
    Bpf(bpf::BpfArgs),
    /// One-shot health check of a running honk engine.
    Diagnose(diagnose::DiagnoseArgs),
    /// Search geosite.dat: list categories, show entries (with @attr),
    /// reverse-lookup a domain.
    Geosite(geo::GeositeArgs),
    /// Search geoip.dat: list codes, show CIDRs, longest-prefix IP lookup.
    Geoip(geo::GeoipArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
    let cli = Cli::parse();
    match cli.command {
        Command::Sub(args) => sub::run(args).await,
        Command::Bpf(args) => bpf::run(args).await,
        Command::Diagnose(args) => diagnose::run(args).await,
        Command::Geosite(args) => geo::run_geosite(args),
        Command::Geoip(args) => geo::run_geoip(args),
    }
}
