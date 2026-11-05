# Live bodies — Google Chrome 156.0.8078.73

| case | ok | state(s) | detail |
|---|---|---|---|
| form | ✓ | request:captured, response:captured | |
| json | ✓ | request:captured, response:captured | |
| binary | ✓ | request:captured, response:captured | |
| echo_binary | ✓ | request:captured, response:captured | |
| big_post | ✓ | request:truncated | |
| big_binary_post | ✓ | request:truncated | |
| big_get | ✓ | response:truncated | |
| gzip | ✓ | response:captured | |
| binary_get | ✓ | response:captured | |
| json_get | ✓ | response:captured | |
| r302 | ✓ | attempt0:unavailable, attempt1:captured | |
| r307 | ✓ | request0:captured, request1:captured, response0:unavailable, response1:captured | |
| empty204 | ✓ | response:empty | |
| zero | ✓ | response:empty | |
| latin1 | ✓ | response:captured | |
| refused | ✓ | response:unavailable | |
| invariants | ✓ |  | |
| session_bodies | ✓ |  | |
| session_label | ✓ |  | |
| session_search | ✓ |  | |
