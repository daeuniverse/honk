use super::*;

/// The log file the process opened at startup and the CLI override, which
/// takes precedence over any candidate's `global.log_file`.
#[derive(Clone, Debug, Default)]
pub(crate) struct LogFiles {
    pub(crate) cli_override: Option<PathBuf>,
    pub(crate) effective: Option<PathBuf>,
}

/// A restart-only setting that differs, with a safe message naming it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RestartField {
    pub(crate) path: &'static str,
    pub(crate) message: &'static str,
}

macro_rules! field {
    ($path:literal) => {
        RestartField {
            path: $path,
            message: concat!("Changing ", $path, " requires restarting honk"),
        }
    };
}

/// Restart-only settings that differ between the running configuration and a
/// candidate. Reload rejects such a candidate; the native API refuses it
/// before writing.
pub(crate) fn restart_required_fields(
    current: &Config,
    candidate: &Config,
    log_files: &LogFiles,
) -> Vec<RestartField> {
    let candidate_log_file =
        crate::resolved_log_file_path(candidate, log_files.cli_override.as_deref());
    restart_required_changes(
        current,
        candidate,
        log_files.effective.as_deref(),
        candidate_log_file.as_deref(),
    )
}

/// Fields whose current consumers are process-scoped and therefore cannot be
/// swapped safely by runtime generation publication.
pub(crate) fn restart_required_changes(
    current: &Config,
    candidate: &Config,
    current_log_file: Option<&Path>,
    candidate_log_file: Option<&Path>,
) -> Vec<RestartField> {
    let mut changed = Vec::new();
    let dns_bind_changed = match (current.dns.bind_endpoint(), candidate.dns.bind_endpoint()) {
        (Ok(current), Ok(candidate)) => current != candidate,
        _ => current.dns.bind != candidate.dns.bind,
    };
    if dns_bind_changed {
        changed.push(field!("dns.bind"));
    }
    let old_global = &current.global;
    let new_global = &candidate.global;
    if old_global.check_interval_secs != new_global.check_interval_secs {
        changed.push(field!("global.check_interval"));
    }
    let old_http = http_probe_inputs(old_global);
    let new_http = http_probe_inputs(new_global);
    if old_http.map(|input| input.0) != new_http.map(|input| input.0) {
        changed.push(field!("global.tcp_check_url"));
    }
    if old_http.map(|input| input.1) != new_http.map(|input| input.1) {
        changed.push(field!("global.tcp_check_http_method"));
    }
    if udp_probe_input_changed(&old_global.udp_check_dns, &new_global.udp_check_dns) {
        changed.push(field!("global.udp_check_dns"));
    }
    if old_global.tls_implementation.eq_ignore_ascii_case("utls")
        != new_global.tls_implementation.eq_ignore_ascii_case("utls")
    {
        changed.push(field!("global.tls_implementation"));
    }
    if old_global.tproxy_port != new_global.tproxy_port {
        changed.push(field!("global.tproxy_port"));
    }
    if old_global.tproxy_mark != new_global.tproxy_mark {
        changed.push(field!("global.tproxy_mark"));
    }
    if old_global.tproxy_port_protect != new_global.tproxy_port_protect {
        changed.push(field!("global.tproxy_port_protect"));
    }
    if old_global.pprof_port != new_global.pprof_port {
        changed.push(field!("global.pprof_port"));
    }
    if old_global.so_mark_from_dae != new_global.so_mark_from_dae {
        changed.push(field!("global.so_mark_from_dae"));
    }
    if old_global.log_level != new_global.log_level {
        changed.push(field!("global.log_level"));
    }
    if current_log_file != candidate_log_file {
        changed.push(field!("global.log_file"));
    }
    if old_global.lan_interface != new_global.lan_interface {
        changed.push(field!("global.lan_interface"));
    }
    if old_global.wan_interface != new_global.wan_interface {
        changed.push(field!("global.wan_interface"));
    }
    if old_global.auto_config_kernel_parameter != new_global.auto_config_kernel_parameter {
        changed.push(field!("global.auto_config_kernel_parameter"));
    }
    if old_global.data_dir != new_global.data_dir {
        changed.push(field!("global.data_dir"));
    }
    if old_global.store_subscribe != new_global.store_subscribe {
        changed.push(field!("global.store_subscribe"));
    }
    if old_global.nfqueue_enable != new_global.nfqueue_enable {
        changed.push(field!("global.nfqueue_enable"));
    }

    let old_api = &current.experimental.clash_api;
    let new_api = &candidate.experimental.clash_api;
    if old_api.external_controller != new_api.external_controller {
        changed.push(field!("experimental.clash_api.external_controller"));
    }
    if old_api.external_ui != new_api.external_ui {
        changed.push(field!("experimental.clash_api.external_ui"));
    }
    if old_api.external_ui_download_url != new_api.external_ui_download_url {
        changed.push(field!("experimental.clash_api.external_ui_download_url"));
    }
    if old_api.external_ui_download_detour != new_api.external_ui_download_detour {
        changed.push(field!("experimental.clash_api.external_ui_download_detour"));
    }
    if old_api.secret != new_api.secret {
        changed.push(field!("experimental.clash_api.secret"));
    }
    if old_api.default_mode != new_api.default_mode {
        changed.push(field!("experimental.clash_api.default_mode"));
    }
    if current.experimental.native_api != candidate.experimental.native_api {
        changed.push(field!("experimental.native_api"));
    }
    if serde_json::to_value(&current.experimental.cache_file).ok()
        != serde_json::to_value(&candidate.experimental.cache_file).ok()
    {
        changed.push(field!("experimental.cache_file"));
    }
    changed
}

fn http_probe_inputs(global: &honk_config::config::GlobalConfig) -> Option<(&str, &str)> {
    let url = global.tcp_check_url.first().filter(|url| !url.is_empty())?;
    let method = if global.tcp_check_http_method.is_empty() {
        "HEAD"
    } else {
        &global.tcp_check_http_method
    };
    Some((url, method))
}

fn udp_probe_input_changed(current: &[String], candidate: &[String]) -> bool {
    use honk_config::check::{DnsCheckTarget, select_dns_check_target};

    let target = |values| {
        select_dns_check_target(values)
            .ok()
            .flatten()
            .unwrap_or(DnsCheckTarget::Literal(DEFAULT_UDP_CHECK_DNS))
    };
    match (target(current), target(candidate)) {
        (
            DnsCheckTarget::Domain { host: a, port: p },
            DnsCheckTarget::Domain { host: b, port: q },
        ) => {
            p != q
                || !a
                    .strip_suffix('.')
                    .unwrap_or(a)
                    .eq_ignore_ascii_case(b.strip_suffix('.').unwrap_or(b))
        }
        (a, b) => a != b,
    }
}
