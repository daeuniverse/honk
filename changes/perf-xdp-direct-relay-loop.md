Changed

- Eligible single-worker i40e XDP Endpoint connections can relay established plain Direct TCP sockets on the capture runtime. Other outbounds and capture modes keep their existing runtime.
- Keep an optional relay task from resetting a packet TCP connection by taking the memory needed for its retirement callback.
