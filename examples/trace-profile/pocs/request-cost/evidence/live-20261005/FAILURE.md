# Preserved pilot failure

The first run stopped during OBI-only trace retrieval because Tempo's trace search
returned a hexadecimal trace ID with a leading zero omitted. The original parser
required an even, full-width hexadecimal string and then incorrectly attempted
to decode that shortened ID as base64.

The run produced no valid comparison or CPU attribution. The trace search,
partially retrieved traces, image metadata, traffic measurements, and application
continuity check are retained here. Its own Compose project was cleaned up after
the failure. Application container identity, PID, and start time stayed unchanged
through this incomplete run.

The corrected parser restores omitted leading zeros only for valid hexadecimal
IDs within the expected width. Unit tests cover that case and reject zero IDs and
invalid widths. A fresh investigation uses a new output directory and new windows.
