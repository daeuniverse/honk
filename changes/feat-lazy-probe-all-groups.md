Changed

- Health checks pause for every idle group policy after `idle_timeout` (default 1800 seconds) without traffic. Automatic groups resume probing their direct members on the next selection while keeping unselected Selector branches suspended; a Selector's current TCP and UDP picks, manually pinned automatic-group members (including custom `check_url`), and non-builtin `final` nodes keep being probed and wake immediately on change, and idle automatic groups still recover when all members fail TCP, data UDP, or a custom `check_url`.
