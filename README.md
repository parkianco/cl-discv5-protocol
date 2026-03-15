# Discv5 Protocol

Experimental Common Lisp implementation of parts of the Ethereum Discovery v5 protocol.

## Features

- Native node ID, routing-table, session-cache, message, and RLP code paths
- Local test coverage for core data structures and serialization
- Pure Common Lisp with explicit crypto stubs where work is still incomplete

## Installation

```lisp
(asdf:load-system :cl-discv5-protocol)
```

## Usage

```lisp
(let* ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
       (node-id (discv5:make-node-id-from-bytes bytes))
       (table (discv5:make-routing-table-for-node node-id)))
  (discv5:routing-table-node-count table))
```

## Testing

```lisp
(asdf:test-system :cl-discv5-protocol)
```

## API

- `make-node-id-from-bytes` creates node IDs from raw 32-byte values.
- `make-routing-table-for-node` builds a routing table for a local node.
- `rlp-encode` and `rlp-decode` provide untyped RLP serialization helpers.
- `rlp-decode-integer` converts decoded byte strings to integers at typed call sites.

## License

Apache-2.0 License - See LICENSE file for details.

---
Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
SPDX-License-Identifier: Apache-2.0
