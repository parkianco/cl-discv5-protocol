;;;; -*- Mode: Lisp; Syntax: Common-Lisp -*-
;;;; cl-discv5-protocol.asd - Ethereum Discovery v5 Protocol
;;;;
;;;; Standalone Common Lisp implementation of the Ethereum Discovery v5 protocol.
;;;; Zero external dependencies - pure Common Lisp with SBCL extensions.

(defsystem #:cl-discv5-protocol
  :name "cl-discv5-protocol"
  :version "1.0.0"
  :author "CLPIC Project"
  :license "MIT"
  :description "Ethereum Discovery v5 UDP Protocol - Standalone Implementation"
  :long-description "Pure Common Lisp implementation of the Ethereum Discovery v5 protocol
for secure, encrypted peer discovery in P2P networks. Features include:
- ENR (Ethereum Node Records) per EIP-778
- WHOAREYOU challenge-response handshake
- AES-GCM session encryption
- Kademlia DHT routing table (256 k-buckets)
- Topic-based service discovery
- NAT traversal support"

  :depends-on ()  ; No external dependencies

  :serial t
  :components
  ((:file "package")
   (:module "src"
    :serial t
    :components
    ((:file "util")         ; Utilities, byte operations, hex encoding
     (:file "crypto")       ; Keccak-256, secp256k1, AES-GCM, HKDF
     (:file "rlp")          ; RLP encoding/decoding
     (:file "node-id")      ; Node ID and distance calculations
     (:file "enr")          ; Ethereum Node Records
     (:file "types")        ; Protocol types and conditions
     (:file "packet")       ; Packet encoding/decoding
     (:file "session")      ; Session management and encryption
     (:file "handshake")    ; WHOAREYOU handshake
     (:file "routing")      ; Kademlia routing table
     (:file "messages")     ; Protocol messages
     (:file "findnode")     ; FINDNODE/NODES handling
     (:file "topics")       ; Topic advertisement
     (:file "discovery")))  ; Main discovery service
   (:module "test"
    :components
    ((:file "test-discv5"))))

  :in-order-to ((test-op (test-op #:cl-discv5-protocol/test))))

(defsystem #:cl-discv5-protocol/test
  :depends-on (#:cl-discv5-protocol)
  :components
  ((:module "test"
    :components
    ((:file "test-discv5"))))
  :perform (test-op (o c)
             (uiop:symbol-call :discv5.test :run-tests)))
