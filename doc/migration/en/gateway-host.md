# Migrate XDP Gateway Host configuration

Remove `xsk_mode` from inside `datapath.host`, including an explicit null in a structured configuration. If you also use physical XDP capture, keep its `xsk_mode` directly under `datapath`.

A Host-only configuration can use the following block. It requires an `ebpf` build.

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

List one to four distinct egress interface names. `auto` and `lo` are invalid. Choose names separate from every physical or `l3_lan` capture interface. An `l3_lan` still requires a physical XDP interface, as does `workers: 2`. Change the Host interface list with a restart.

Host supports configured gateway DNS projection. The effective bypass mark must be nonzero and must leave all bits in `0xc800_0000` clear. Omitting `global.so_mark_from_dae` or setting it to `0` selects `0x100`.

[简体中文](../zh/gateway-host.md)
