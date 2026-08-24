use super::*;

/// Fields whose current consumers are process-scoped and therefore cannot be
/// swapped safely by runtime generation publication.
pub(crate) fn restart_required_changes(
    current: &Config,
    candidate: &Config,
    current_log_file: Option<&Path>,
    candidate_log_file: Option<&Path>,
) -> Vec<&'static str> {
    let mut changed = Vec::new();
    let dns_bind_changed = match (current.dns.bind_endpoint(), candidate.dns.bind_endpoint()) {
        (Ok(current), Ok(candidate)) => current != candidate,
        _ => current.dns.bind != candidate.dns.bind,
    };
    if dns_bind_changed {
        changed.push("dns.bind");
    }
    let old_global = &current.global;
    let new_global = &candidate.global;
    if old_global.tproxy_port != new_global.tproxy_port {
        changed.push("global.tproxy_port");
    }
    if old_global.tproxy_mark != new_global.tproxy_mark {
        changed.push("global.tproxy_mark");
    }
    if old_global.tproxy_port_protect != new_global.tproxy_port_protect {
        changed.push("global.tproxy_port_protect");
    }
    if old_global.pprof_port != new_global.pprof_port {
        changed.push("global.pprof_port");
    }
    if old_global.so_mark_from_dae != new_global.so_mark_from_dae {
        changed.push("global.so_mark_from_dae");
    }
    if old_global.log_level != new_global.log_level {
        changed.push("global.log_level");
    }
    if current_log_file != candidate_log_file {
        changed.push("global.log_file");
    }
    if old_global.lan_interface != new_global.lan_interface {
        changed.push("global.lan_interface");
    }
    if old_global.wan_interface != new_global.wan_interface {
        changed.push("global.wan_interface");
    }
    if old_global.auto_config_kernel_parameter != new_global.auto_config_kernel_parameter {
        changed.push("global.auto_config_kernel_parameter");
    }
    if old_global.data_dir != new_global.data_dir {
        changed.push("global.data_dir");
    }
    if old_global.store_subscribe != new_global.store_subscribe {
        changed.push("global.store_subscribe");
    }
    if old_global.nfqueue_enable != new_global.nfqueue_enable {
        changed.push("global.nfqueue_enable");
    }

    let old_api = &current.experimental.clash_api;
    let new_api = &candidate.experimental.clash_api;
    if old_api.external_controller != new_api.external_controller {
        changed.push("experimental.clash_api.external_controller");
    }
    if old_api.external_ui != new_api.external_ui {
        changed.push("experimental.clash_api.external_ui");
    }
    if old_api.secret != new_api.secret {
        changed.push("experimental.clash_api.secret");
    }
    if old_api.default_mode != new_api.default_mode {
        changed.push("experimental.clash_api.default_mode");
    }
    if serde_json::to_value(&current.experimental.cache_file).ok()
        != serde_json::to_value(&candidate.experimental.cache_file).ok()
    {
        changed.push("experimental.cache_file");
    }
    changed
}
