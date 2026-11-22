Changed

- Health checks pause for every idle group, not only URLTest groups, after `idle_timeout` (default 1800 seconds) without traffic. A Selector's selected node, a manually pinned node and a node `final` keep being probed, and members resume probing on the group's next use.
