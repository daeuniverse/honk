# 迁移 XDP Gateway Host 配置

删除 `datapath.host` 内的 `xsk_mode`，包括结构化配置中显式设置的 null。若同时使用物理 XDP 捕获，请保留直接写在 `datapath` 下的物理口 `xsk_mode`。

仅启用 Host 时可使用以下配置。运行程序需以 `ebpf` 特性构建。

```dae
global {
    nfqueue_enable: false
}

datapath {
    backend: xdp
    direct: endpoint
    host {
        interface {
            eth0.100
        }
    }
}
```

填写一至四个不同的出口接口名，不能用 `auto` 或 `lo`，也不能与任何物理捕获口或 `l3_lan` 同名。使用 `l3_lan` 或 `workers: 2` 仍需配置物理 XDP 接口。修改 Host 接口列表后需重启。

Host 支持配置网关 DNS 投影。有效旁路 mark 必须非零，且不得设置 `0xc800_0000` 掩码中的任一位。省略 `global.so_mark_from_dae` 或显式设为 `0` 时，使用 `0x100`。

[English](../en/gateway-host.md)
