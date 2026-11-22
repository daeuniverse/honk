Fixed

- After a userspace TCP relay reads EOF, its 30-second idle timeout covers the final flush and write-side shutdown. Delayed polling no longer extends an idle drain. On timeout, the returned byte totals count only bytes accepted by the destination.
