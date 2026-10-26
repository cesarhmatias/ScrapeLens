One real evidence record per protocol, captured by ./run-demo.sh (synthetic,
local). They exist to document the JSONL shape for consumers (matrix, core
importers, tests); regenerate with ./run-demo.sh <base-port> <run-id>.
Fields: headers is an ordered array of [name, value] pairs (duplicates kept),
pseudoheaders is the ordered subset of ':' fields (h2/h3), raw_head_b64 is the
exact HTTP/1.1 request head, header_block_b64 is the raw HPACK block (h2).
