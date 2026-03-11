;;;; -*- Mode: Lisp; Syntax: Common-Lisp -*-
;;;; package.lisp - Package definition for cl-discv5-protocol
;;;;
;;;; Ethereum Discovery v5 Protocol - Standalone Implementation
;;;; Pure Common Lisp with SBCL threading primitives.

(defpackage #:discv5
  (:use #:cl)
  (:nicknames #:cl-discv5-protocol #:discv5-protocol)
  (:documentation "Ethereum Discovery v5 Protocol - Secure P2P Node Discovery

This package implements the Ethereum Discovery v5 protocol, providing:

1. NODE IDENTITY:
   - 256-bit node IDs derived from secp256k1 public keys
   - Kademlia XOR-metric distance calculations
   - Cryptographically signed node records (ENR)

2. ROUTING TABLE:
   - 256 k-buckets organized by XOR distance
   - Replacement cache for resilience
   - Periodic liveness checking and bucket refresh

3. PROTOCOL MESSAGES:
   - PING/PONG: Node liveness verification
   - FINDNODE/NODES: Kademlia-style node lookup
   - TALKREQ/TALKRESP: Application-layer messaging
   - REGTOPIC/TICKET/REGCONFIRMATION: Topic advertisement
   - TOPICQUERY: Topic-based peer discovery

4. SESSION MANAGEMENT:
   - WHOAREYOU challenge-response handshake
   - AES-128-GCM encrypted message transport
   - Session caching for performance

5. NAT TRAVERSAL:
   - IP/port detection via external observation
   - UDP hole punching coordination

References:
- EIP-778: Ethereum Node Records
- https://github.com/ethereum/devp2p/blob/master/discv5/discv5.md")

  ;; ============================================================================
  ;; CONSTANTS AND CONFIGURATION
  ;; ============================================================================
  (:export
   ;; Protocol constants
   #:+discv5-version+
   #:+protocol-id+
   #:+max-packet-size+
   #:+max-enr-size+
   #:+node-id-bits+
   #:+node-id-bytes+

   ;; Kademlia parameters
   #:+k-bucket-size+
   #:+alpha+
   #:+num-buckets+
   #:+replacement-cache-size+

   ;; Timing constants
   #:+request-timeout+
   #:+request-retries+
   #:+session-timeout+
   #:+bucket-refresh-interval+
   #:+liveness-check-interval+
   #:+topic-registration-ttl+

   ;; Limits
   #:+max-nodes-response+
   #:+max-talk-request-size+
   #:+max-topic-name-size+
   #:+max-pending-requests+
   #:+max-sessions+

   ;; Configuration
   #:*discv5-config*
   #:make-discv5-config
   #:discv5-config
   #:config-listen-address
   #:config-listen-port
   #:config-boot-nodes
   #:config-bucket-size
   #:config-request-timeout
   #:config-log-level)

  ;; ============================================================================
  ;; NODE IDENTITY
  ;; ============================================================================
  (:export
   ;; Node ID type
   #:node-id
   #:node-id-p
   #:make-node-id
   #:make-node-id-from-bytes   ; For creating node IDs from byte arrays
   #:node-id-bytes
   #:node-id-hex

   ;; Node ID generation
   #:generate-node-id
   #:node-id-from-public-key
   #:node-id-from-enr
   #:random-node-id

   ;; Distance calculations
   #:node-distance
   #:log-distance
   #:common-prefix-length
   #:distance-compare
   #:closer-to-p

   ;; Comparison and equality
   #:node-id=
   #:node-id<
   #:node-id-hash

   ;; Serialization
   #:serialize-node-id
   #:deserialize-node-id
   #:node-id-to-string
   #:string-to-node-id

   ;; Validation
   #:valid-node-id-p
   #:node-id-zero-p)

  ;; ============================================================================
  ;; ENR - ETHEREUM NODE RECORDS
  ;; ============================================================================
  (:export
   ;; ENR structure
   #:enr
   #:enr-p
   #:make-enr
   #:copy-enr

   ;; Required fields
   #:enr-signature
   #:enr-sequence
   #:enr-id
   #:enr-secp256k1

   ;; Network fields
   #:enr-ip
   #:enr-ip6
   #:enr-tcp
   #:enr-tcp6
   #:enr-udp
   #:enr-udp6

   ;; Key-value operations
   #:enr-get
   #:enr-set
   #:enr-delete
   #:enr-keys
   #:enr-pairs

   ;; ENR creation and updates
   #:create-enr
   #:update-enr
   #:sign-enr
   #:increment-sequence

   ;; Derivation
   #:enr-node-id
   #:enr-public-key
   #:enr-socket-address

   ;; Serialization (RLP encoding)
   #:serialize-enr
   #:deserialize-enr
   #:enr-to-base64
   #:base64-to-enr
   #:enr-to-text
   #:parse-enr-text

   ;; Validation
   #:verify-enr
   #:valid-enr-p
   #:enr-size
   #:enr-too-large-p

   ;; Standard keys
   #:+enr-key-id+
   #:+enr-key-secp256k1+
   #:+enr-key-ip+
   #:+enr-key-ip6+
   #:+enr-key-tcp+
   #:+enr-key-tcp6+
   #:+enr-key-udp+
   #:+enr-key-udp6+)

  ;; ============================================================================
  ;; TYPES
  ;; ============================================================================
  (:export
   ;; Node information
   #:discv5-node
   #:discv5-node-p
   #:make-discv5-node
   #:discv5-node-id              ; Accessor for node's ID
   #:discv5-node-enr             ; Accessor for node's ENR
   #:discv5-node-address         ; Accessor for node's address
   #:discv5-node-udp-port        ; Accessor for UDP port
   #:node-enr
   #:node-address
   #:node-last-seen
   #:node-last-ping
   #:node-last-pong
   #:node-failed-requests
   #:node-latency
   #:node-added-at

   ;; Socket address
   #:socket-address
   #:socket-address-p
   #:make-socket-address
   #:address-ip
   #:address-port
   #:address-ipv6-p
   #:address-to-string
   #:string-to-address
   #:address=

   ;; Request tracking
   #:pending-request
   #:pending-request-p
   #:make-pending-request
   #:request-id
   #:request-target
   #:request-type
   #:request-sent-at
   #:request-retries
   #:request-callback
   #:request-timeout

   ;; Lookup state
   #:lookup-state
   #:lookup-state-p
   #:make-lookup-state
   #:lookup-target
   #:lookup-closest
   #:lookup-queried
   #:lookup-pending
   #:lookup-started-at
   #:lookup-complete-p
   #:lookup-callback

   ;; Topic registration
   #:topic-registration
   #:topic-registration-p
   #:make-topic-registration
   #:registration-topic
   #:registration-node
   #:registration-ticket
   #:registration-expires

   ;; Ticket
   #:ticket
   #:ticket-p
   #:make-ticket
   #:ticket-topic
   #:ticket-node
   #:ticket-nonce
   #:ticket-wait-time
   #:ticket-issued-at
   #:ticket-expires-at
   #:ticket-valid-p

   ;; Error conditions
   #:discv5-error
   #:enr-error
   #:session-error
   #:protocol-error
   #:timeout-error
   #:validation-error
   #:packet-error
   #:handshake-error
   #:authentication-error
   #:routing-error)

  ;; ============================================================================
  ;; ROUTING TABLE
  ;; ============================================================================
  (:export
   ;; Routing table
   #:routing-table
   #:routing-table-p
   #:make-routing-table
   #:make-routing-table-for-node  ; Convenience constructor
   #:routing-table-local-id
   #:routing-table-local-enr
   #:routing-table-buckets
   #:routing-table-size
   #:routing-table-node-count     ; Alias for routing-table-size

   ;; K-bucket
   #:k-bucket
   #:k-bucket-p
   #:make-k-bucket
   #:bucket-index
   #:bucket-nodes
   #:bucket-replacements
   #:bucket-size
   #:bucket-capacity
   #:bucket-last-refresh

   ;; Core operations
   #:routing-table-add
   #:routing-table-remove
   #:routing-table-update
   #:routing-table-contains-p
   #:routing-table-get
   #:routing-table-get-bucket

   ;; Lookups
   #:routing-table-closest
   #:routing-table-closest-except
   #:routing-table-random-nodes
   #:routing-table-all-nodes
   #:routing-table-nodes-at-distance

   ;; Maintenance
   #:routing-table-refresh
   #:routing-table-refresh-bucket
   #:routing-table-prune
   #:routing-table-needs-refresh-p
   #:routing-table-stale-buckets

   ;; Replacement cache
   #:bucket-add-replacement
   #:bucket-get-replacement
   #:bucket-promote-replacement

   ;; Statistics
   #:routing-table-stats
   #:routing-table-health
   #:routing-table-coverage
   #:bucket-stats

   ;; Persistence
   #:save-routing-table
   #:load-routing-table
   #:export-routing-table
   #:import-routing-table

   ;; Events
   #:*on-node-added*
   #:*on-node-removed*
   #:*on-node-updated*
   #:*on-bucket-refresh*)

  ;; ============================================================================
  ;; PROTOCOL MESSAGES
  ;; ============================================================================
  (:export
   ;; Message types enum
   #:message-type
   #:+msg-ping+
   #:+msg-pong+
   #:+msg-findnode+
   #:+msg-nodes+
   #:+msg-talkreq+
   #:+msg-talkresp+
   #:+msg-regtopic+
   #:+msg-ticket+
   #:+msg-regconfirmation+
   #:+msg-topicquery+

   ;; PING/PONG messages
   #:ping-message
   #:ping-message-p
   #:make-ping-message
   #:ping-request-id
   #:ping-enr-seq

   #:pong-message
   #:pong-message-p
   #:make-pong-message
   #:pong-request-id
   #:pong-enr-seq
   #:pong-recipient-ip
   #:pong-recipient-port

   ;; FINDNODE/NODES messages
   #:findnode-message
   #:findnode-message-p
   #:make-findnode-message
   #:findnode-request-id
   #:findnode-distances

   #:nodes-message
   #:nodes-message-p
   #:make-nodes-message
   #:nodes-request-id
   #:nodes-total
   #:nodes-enrs

   ;; TALKREQ/TALKRESP messages
   #:talkreq-message
   #:talkreq-message-p
   #:make-talkreq-message
   #:talkreq-request-id
   #:talkreq-protocol
   #:talkreq-payload

   #:talkresp-message
   #:talkresp-message-p
   #:make-talkresp-message
   #:talkresp-request-id
   #:talkresp-payload

   ;; Topic messages
   #:regtopic-message
   #:regtopic-message-p
   #:make-regtopic-message
   #:regtopic-request-id
   #:regtopic-topic
   #:regtopic-enr
   #:regtopic-ticket

   #:ticket-message
   #:ticket-message-p
   #:make-ticket-message
   #:ticket-request-id
   #:ticket-wait-time

   #:regconfirmation-message
   #:regconfirmation-message-p
   #:make-regconfirmation-message
   #:regconfirmation-request-id
   #:regconfirmation-topic

   #:topicquery-message
   #:topicquery-message-p
   #:make-topicquery-message
   #:topicquery-request-id
   #:topicquery-topic

   ;; Message serialization
   #:serialize-message
   #:deserialize-message
   #:message-type-code
   #:message-request-id)

  ;; ============================================================================
  ;; PACKET ENCODING
  ;; ============================================================================
  (:export
   ;; Packet types
   #:packet-type
   #:+packet-ordinary+
   #:+packet-whoareyou+
   #:+packet-handshake+

   ;; Packet structures
   #:discv5-packet
   #:discv5-packet-p
   #:packet-src-id
   #:packet-dest-id
   #:packet-nonce
   #:packet-auth-tag

   #:ordinary-packet
   #:ordinary-packet-p
   #:make-ordinary-packet
   #:ordinary-packet-message

   #:whoareyou-packet
   #:whoareyou-packet-p
   #:make-whoareyou-packet
   #:whoareyou-id-nonce
   #:whoareyou-enr-seq

   #:handshake-packet
   #:handshake-packet-p
   #:make-handshake-packet
   #:handshake-id-signature
   #:handshake-ephemeral-key
   #:handshake-enr
   #:handshake-message

   ;; Packet encoding/decoding
   #:encode-packet
   #:decode-packet
   #:packet-header-size
   #:validate-packet

   ;; Masking
   #:mask-src-id
   #:unmask-src-id
   #:compute-masking-key

   ;; Nonce handling
   #:generate-nonce
   #:nonce-counter
   #:increment-nonce)

  ;; ============================================================================
  ;; SESSION MANAGEMENT
  ;; ============================================================================
  (:export
   ;; Session structure
   #:session
   #:session-p
   #:make-session
   #:discv5-session            ; Actual struct name in implementation
   #:discv5-session-p
   #:make-discv5-session
   #:discv5-session-node-id
   #:session-node-id
   #:session-address
   #:session-initiator-key
   #:session-recipient-key
   #:session-created-at
   #:session-last-used
   #:session-nonce-counter
   #:session-seen-nonces

   ;; Session cache
   #:session-cache
   #:session-cache-p
   #:make-session-cache
   #:make-session-cache-default  ; Convenience constructor
   #:session-cache-get
   #:session-cache-put
   #:session-cache-remove
   #:session-cache-clear
   #:session-cache-size
   #:session-cache-prune

   ;; Session operations
   #:create-session
   #:session-encrypt
   #:session-decrypt
   #:session-expired-p
   #:session-valid-p

   ;; Key derivation
   #:derive-session-keys
   #:compute-shared-secret
   #:kdf-info

   ;; Replay protection
   #:check-nonce-replay
   #:record-nonce
   #:prune-old-nonces

   ;; Events
   #:*on-session-established*
   #:*on-session-expired*
   #:*on-session-error*)

  ;; ============================================================================
  ;; WHOAREYOU HANDSHAKE
  ;; ============================================================================
  (:export
   ;; Handshake state
   #:handshake-state
   #:handshake-state-p
   #:make-handshake-state
   #:handshake-challenge
   #:handshake-nonce
   #:handshake-enr-seq
   #:handshake-started-at
   #:handshake-request

   ;; Handshake cache
   #:handshake-cache
   #:handshake-cache-p
   #:make-handshake-cache
   #:handshake-cache-get
   #:handshake-cache-put
   #:handshake-cache-remove
   #:handshake-cache-prune

   ;; Challenge generation
   #:generate-whoareyou
   #:create-id-nonce
   #:sign-id-nonce
   #:verify-id-nonce-signature

   ;; Handshake processing
   #:handle-whoareyou
   #:create-handshake-response
   #:process-handshake
   #:complete-handshake

   ;; Ephemeral keys
   #:generate-ephemeral-keypair
   #:compute-ephemeral-secret

   ;; ID scheme operations
   #:id-sign
   #:id-verify
   #:id-nonce-signing-text

   ;; Events
   #:*on-handshake-started*
   #:*on-handshake-complete*
   #:*on-handshake-failed*)

  ;; ============================================================================
  ;; FINDNODE HANDLING
  ;; ============================================================================
  (:export
   ;; Lookup operations
   #:find-node
   #:iterative-find-node
   #:parallel-find-node
   #:lookup-node
   #:lookup-random

   ;; Request handling
   #:send-findnode
   #:handle-findnode
   #:send-nodes
   #:handle-nodes

   ;; Distance-based queries
   #:query-distances
   #:collect-nodes-at-distances
   #:split-nodes-response

   ;; Lookup state management
   #:create-lookup
   #:advance-lookup
   #:finalize-lookup
   #:cancel-lookup
   #:lookup-timed-out-p

   ;; Closest nodes set
   #:closest-nodes-set
   #:closest-nodes-set-p
   #:make-closest-nodes-set
   #:closest-set-add
   #:closest-set-pop
   #:closest-set-peek
   #:closest-set-full-p

   ;; Events
   #:*on-lookup-started*
   #:*on-lookup-progress*
   #:*on-lookup-complete*
   #:*on-nodes-discovered*)

  ;; ============================================================================
  ;; TOPIC ADVERTISEMENT
  ;; ============================================================================
  (:export
   ;; Topic operations
   #:register-topic
   #:unregister-topic
   #:query-topic
   #:advertise-topic
   #:stop-advertising

   ;; Topic hash
   #:topic-hash
   #:topic-hash-p
   #:make-topic-hash
   #:topic-to-hash

   ;; Topic table (actual implementation)
   #:topic-table
   #:topic-table-p
   #:make-topic-table
   #:make-topic-table-default   ; Convenience constructor
   #:topic-table-register
   #:topic-table-lookup
   #:topic-table-remove

   ;; Topic index (ad table)
   #:topic-index
   #:topic-index-p
   #:make-topic-index
   #:topic-index-add
   #:topic-index-remove
   #:topic-index-query
   #:topic-index-prune
   #:topic-index-size

   ;; Ticket management
   #:issue-ticket
   #:validate-ticket
   #:consume-ticket
   #:compute-wait-time

   ;; Topic radius
   #:topic-radius
   #:topic-radius-p
   #:make-topic-radius
   #:radius-for-topic
   #:adjust-radius

   ;; Request handling
   #:send-regtopic
   #:handle-regtopic
   #:send-ticket
   #:handle-ticket
   #:send-regconfirmation
   #:handle-regconfirmation
   #:send-topicquery
   #:handle-topicquery

   ;; Registration state
   #:registration-manager
   #:registration-manager-p
   #:make-registration-manager
   #:registration-manager-add
   #:registration-manager-complete
   #:registration-manager-cancel
   #:registration-manager-refresh

   ;; Events
   #:*on-topic-registered*
   #:*on-topic-expired*
   #:*on-topic-query-result*
   #:*on-registration-denied*)

  ;; ============================================================================
  ;; MAIN DISCOVERY SERVICE
  ;; ============================================================================
  (:export
   ;; Service structure
   #:discv5-service
   #:discv5-service-p
   #:make-discv5-service
   #:service-config
   #:service-local-enr
   #:service-routing-table
   #:service-session-cache
   #:service-socket
   #:service-running-p

   ;; Lifecycle
   #:start-service
   #:stop-service
   #:restart-service
   #:service-status

   ;; Bootstrap
   #:bootstrap
   #:add-boot-node
   #:remove-boot-node
   #:get-boot-nodes

   ;; Node discovery
   #:discover-nodes
   #:find-closest-nodes
   #:refresh-all-buckets
   #:random-node-discovery

   ;; Ping/Pong
   #:ping
   #:handle-ping
   #:handle-pong

   ;; ENR operations
   #:get-local-enr
   #:update-local-enr
   #:request-enr

   ;; Low-level operations
   #:send-packet
   #:receive-packet
   #:process-packet
   #:dispatch-message

   ;; Connection management
   #:node-reachable-p
   #:get-node-address
   #:mark-node-responsive
   #:mark-node-unresponsive

   ;; Events
   #:*on-service-started*
   #:*on-service-stopped*
   #:*on-message-received*
   #:*on-message-sent*
   #:*on-node-discovered*
   #:*on-node-removed*)

  ;; ============================================================================
  ;; CONVENIENCE MACROS AND UTILITIES
  ;; ============================================================================
  (:export
   ;; Convenience macros
   #:with-discv5-service
   #:with-session
   #:with-routing-table-lock

   ;; Utility functions
   #:node-id-from-hex
   #:enr-from-text
   #:format-node-id
   #:format-enr

   ;; RLP encoding/decoding
   #:rlp-encode
   #:rlp-decode

   ;; Debugging
   #:dump-routing-table
   #:dump-sessions
   #:dump-pending-requests
   #:trace-messages
   #:untrace-messages

   ;; Testing helpers
   #:make-test-node
   #:make-test-enr
   #:simulate-network
   #:inject-packet))

;;; Internal package for cryptographic primitives
(defpackage #:discv5.crypto
  (:use #:cl)
  (:documentation "Cryptographic primitives for Discovery v5 protocol.")
  (:export
   ;; Keccak-256
   #:keccak-256
   #:keccak-256-update
   #:keccak-256-finalize
   #:make-keccak-256-state

   ;; secp256k1
   #:secp256k1-sign
   #:secp256k1-verify
   #:secp256k1-recover
   #:secp256k1-multiply
   #:secp256k1-multiply-generator
   #:compress-public-key
   #:decompress-public-key
   #:generate-keypair
   #:derive-public-key

   ;; AES-GCM
   #:aes-gcm-encrypt
   #:aes-gcm-decrypt

   ;; HKDF
   #:hkdf-extract
   #:hkdf-expand
   #:hkdf-derive

   ;; HMAC-SHA256
   #:hmac-sha256

   ;; Random
   #:generate-random-bytes
   #:secure-random-bytes))

;;; Test package
(defpackage #:discv5.test
  (:use #:cl #:discv5)
  (:documentation "Tests for Discovery v5 protocol implementation.")
  (:export #:run-tests))

(in-package #:discv5)

;;; Package initialization
(defvar *discv5-version* "5.1"
  "Version of the discv5 protocol implementation.")

(defvar *discv5-agent* "cl-discv5/1.0"
  "Agent string for node identification.")

(defvar *log-level* :info
  "Logging level for discv5 (:debug :info :warn :error).")
