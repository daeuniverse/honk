Fixed

- TCP writers resume when send credit returns, and short output frames allow smaller packets to proceed. Fragment reassembly and retransmission queues can grow within tighter memory budgets. Global ICMP refusals leave per-target eviction order unchanged.
