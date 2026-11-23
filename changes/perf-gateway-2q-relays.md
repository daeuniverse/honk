Changed

- On a single physical member, two-worker XDP Endpoint keeps new TCP flows on the receiving queue and routes later packets to the retained owner if the queue changes. Both output windows can grow within the existing capture budget.
- On supported single-member i40e Endpoint gateways, each worker can relay its own established Direct TCP sockets. Shutdown waits for those relay tasks without releasing uncompleted device output.
- Native datapath diagnostics and Clash `/stats` report how many packet envelopes were handed to another XDP worker during the current capture.
