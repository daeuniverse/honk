//! `honk-tool geosite` / `honk-tool geoip` — offline content search of
//! geosite.dat / geoip.dat: which categories exist, what a category contains
//! (including `@attr` attributes), which categories contain a domain, and
//! which geoip codes cover an IP. Output is one record per line for piping
//! into grep.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;

use clap::{Args, Subcommand};
use honk_core::routing::{GeoipScan, GeositeEntry, GeositeScan, find_geoip_dat, find_geosite_dat};

#[derive(Args)]
pub struct GeositeArgs {
    #[command(subcommand)]
    action: GeositeAction,
    /// Path to geosite.dat (default: $DAE_LOCATION_ASSET, then
    /// /var/lib/honk/geosite.dat, legacy /var/share/honk/geosite.dat,
    /// ./geosite.dat, honk share directories, then dae asset locations).
    #[arg(long, global = true)]
    pub file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum GeositeAction {
    /// List all categories and their entry counts; FILTER is a
    /// case-insensitive substring match on the category code.
    List { filter: Option<String> },
    /// Show the domain entries of one category.
    Show {
        category: String,
        /// Only show entries carrying this @attr attribute.
        #[arg(long)]
        attr: Option<String>,
    },
    /// Reverse lookup: which categories contain this domain (full, suffix,
    /// keyword, and regex entries all count).
    Find { domain: String },
}

#[derive(Args)]
pub struct GeoipArgs {
    #[command(subcommand)]
    action: GeoipAction,
    /// Path to geoip.dat (default: $DAE_LOCATION_ASSET, then
    /// /var/lib/honk/geoip.dat, legacy /var/share/honk/geoip.dat,
    /// ./geoip.dat, honk share directories, then dae asset locations).
    #[arg(long, global = true)]
    pub file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum GeoipAction {
    /// List all codes and their CIDR counts; FILTER is a case-insensitive
    /// substring match on the code.
    List { filter: Option<String> },
    /// Show the CIDRs of one code.
    Show { code: String },
    /// Longest-prefix lookup: which codes cover this IP.
    Lookup { ip: IpAddr },
}

pub fn run_geosite(args: GeositeArgs) -> anyhow::Result<()> {
    let path = resolve_dat(args.file, "geosite.dat", find_geosite_dat)?;
    let scan = GeositeScan::load(&path)?;
    let out = match &args.action {
        GeositeAction::List { filter } => render_geosite_list(&scan, filter.as_deref()),
        GeositeAction::Show { category, attr } => {
            render_geosite_show(&scan, category, attr.as_deref())?
        }
        GeositeAction::Find { domain } => render_geosite_find(&scan, domain),
    };
    write_out(&out)
}

pub fn run_geoip(args: GeoipArgs) -> anyhow::Result<()> {
    let path = resolve_dat(args.file, "geoip.dat", find_geoip_dat)?;
    let scan = GeoipScan::load(&path)?;
    let out = match &args.action {
        GeoipAction::List { filter } => render_geoip_list(&scan, filter.as_deref()),
        GeoipAction::Show { code } => render_geoip_show(&scan, code)?,
        GeoipAction::Lookup { ip } => render_geoip_lookup(&scan, *ip),
    };
    write_out(&out)
}

/// print!() panics on SIGPIPE; a tool meant for `| grep` must exit quietly
/// when the downstream reader closes the pipe.
fn write_out(out: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(out.as_bytes()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn resolve_dat(
    explicit: Option<PathBuf>,
    name: &str,
    find: fn() -> Option<PathBuf>,
) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.exists() {
            anyhow::bail!("{}: no such file", p.display());
        }
        if !p.is_file() {
            anyhow::bail!("{}: not a file", p.display());
        }
        return Ok(p);
    }
    find().ok_or_else(|| {
        anyhow::anyhow!(
            "{name} not found (tried $DAE_LOCATION_ASSET/{name}, /var/lib/honk/{name}, \
             /var/share/honk/{name}, ./{name}, /usr/local/share/honk/{name}, \
             /usr/share/honk/{name}, /usr/local/share/dae/{name}, \
             /usr/share/dae/{name}, /etc/dae/{name}) — pass --file PATH"
        )
    })
}

fn format_entry(out: &mut String, code: &str, entry: &GeositeEntry) {
    let _ = write!(out, "{code} {} {}", entry.kind.as_str(), entry.value);
    for attr in &entry.attrs {
        let _ = write!(out, " @{attr}");
    }
    out.push('\n');
}

fn render_geosite_list(scan: &GeositeScan, filter: Option<&str>) -> String {
    let filter = filter.map(str::to_lowercase);
    let mut out = String::new();
    for cat in scan.categories() {
        if let Some(f) = &filter
            && !cat.code.to_lowercase().contains(f)
        {
            continue;
        }
        let _ = writeln!(out, "{} {}", cat.code, cat.entries.len());
    }
    out
}

fn render_geosite_show(
    scan: &GeositeScan,
    category: &str,
    attr: Option<&str>,
) -> anyhow::Result<String> {
    let cat = scan
        .category(category)
        .ok_or_else(|| anyhow::anyhow!("category '{category}' not found"))?;
    let mut out = String::new();
    for entry in &cat.entries {
        if let Some(a) = attr
            && !entry.attrs.iter().any(|e| e.eq_ignore_ascii_case(a))
        {
            continue;
        }
        format_entry(&mut out, &cat.code, entry);
    }
    Ok(out)
}

fn render_geosite_find(scan: &GeositeScan, domain: &str) -> String {
    let mut hits = scan.find(domain);
    hits.sort_by(|a, b| a.0.code.cmp(&b.0.code));
    let mut out = String::new();
    for (cat, entry) in hits {
        format_entry(&mut out, &cat.code, entry);
    }
    out
}

fn render_geoip_list(scan: &GeoipScan, filter: Option<&str>) -> String {
    let mut out = String::new();
    for cat in scan.categories() {
        if let Some(f) = filter
            && !cat.code.to_lowercase().contains(&f.to_lowercase())
        {
            continue;
        }
        let _ = writeln!(out, "{} {}", cat.code, cat.cidrs.len());
    }
    out
}

fn render_geoip_show(scan: &GeoipScan, code: &str) -> anyhow::Result<String> {
    let cat = scan
        .category(code)
        .ok_or_else(|| anyhow::anyhow!("geoip code '{code}' not found"))?;
    let mut out = String::new();
    for net in &cat.cidrs {
        let _ = writeln!(out, "{} {}", cat.code, net);
    }
    Ok(out)
}

fn render_geoip_lookup(scan: &GeoipScan, ip: IpAddr) -> String {
    let mut out = String::new();
    for (cat, net) in scan.lookup(ip) {
        let _ = writeln!(out, "{} {}", cat.code, net);
    }
    out
}
