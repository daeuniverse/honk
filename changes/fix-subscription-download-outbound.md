Fixed

- Subscription connection and HTTP status failures name the selected node and group in the log. Classified fetch failures report their stage and available outbound attribution in native API provider `last_error.details`, including completed failures retained during shutdown; unusable subscription content reports `parse_failed`.
