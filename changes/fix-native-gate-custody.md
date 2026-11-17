Fixed

- Keep the Native ingress gate attached after its creating process exits, including failures before attachment readback completes. The documented cold-recovery procedure identifies the owned gate program and detaches it exactly before removing its pin.
