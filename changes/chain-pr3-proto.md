Added

- Groups accept `exit`: TCP dials the selected leaf, then each nested exit from the innermost group out, up to four physical hops. A failed path to a shared exit does not mark other paths to that exit down. Recovery uses an existing configured HTTP check through the affected path. A group exit does not forward UDP; an explicit `block` remains terminal.
