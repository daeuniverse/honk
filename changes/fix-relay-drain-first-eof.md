Fixed

- After a userspace TCP relay reads EOF, its idle timeout also covers the final flush and write-side shutdown. On timeout, the returned byte totals count only bytes accepted by the destination.
