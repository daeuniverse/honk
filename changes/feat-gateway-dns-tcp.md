Changed

- Eligible TCP connections on physical XDP Endpoint LANs can use native kernel routing based on DNS answers learned on that LAN. UDP remains shadow-only; observing `notrack` disables DNS-derived forwarding for the rest of the capture.
