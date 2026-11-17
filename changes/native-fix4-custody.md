Fixed

- Native XDP installs its guard with netdev-held driver-mode custody, so creator FD loss after successful installation does not release the attachment; stale installations require explicit cleanup with sources stopped and prior owners joined.
