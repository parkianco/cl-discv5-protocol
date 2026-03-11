# cl-discv5-protocol

Ethereum Discovery v5 UDP Protocol implementation with **zero external dependencies**.

## Features

- **ENR (EIP-778)**: Ethereum Node Records
- **WHOAREYOU**: Handshake protocol for session establishment
- **Kademlia DHT**: Distributed hash table for node discovery
- **Topic advertisement**: Service discovery via topics
- **Session management**: Encrypted communication sessions
- **Pure Common Lisp**: No CFFI, no external libraries

## Installation

```lisp
(asdf:load-system :cl-discv5-protocol)
```

## Quick Start

```lisp
(use-package :cl-discv5-protocol)

;; Create discovery service
(let ((discovery (make-discovery-service
                  :privkey (generate-random-bytes 32)
                  :udp-port 30303
                  :bootnodes '("enr:-..."))))
  ;; Start service
  (discovery-start discovery)
  ;; Find nodes
  (start-lookup discovery target-id
                :callback (lambda (nodes)
                            (format t "Found ~a nodes~%" (length nodes)))))
```

## API Reference

### Discovery Service

- `(make-discovery-service &key privkey udp-port bootnodes)` - Create service
- `(discovery-start discovery)` - Start UDP listener
- `(discovery-stop discovery)` - Stop service
- `(discovery-ping discovery node)` - Ping a node

### Node Lookup

- `(start-lookup discovery target-id &key callback)` - Find nodes near target
- `(advertise-topic discovery topic-name)` - Advertise a topic
- `(query-topic discovery topic-name callback)` - Find topic providers

### ENR Operations

- `(make-enr-with-keys privkey &key ip tcp udp)` - Create ENR
- `(enr-encode enr privkey)` - Sign and encode ENR
- `(enr-decode bytes)` - Decode ENR from bytes
- `(enr-verify enr)` - Verify ENR signature

## Testing

```lisp
(asdf:test-system :cl-discv5-protocol)
```

## License

BSD-3-Clause

Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
