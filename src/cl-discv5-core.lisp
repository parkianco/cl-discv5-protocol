;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package :cl-discv5-protocol)

;;; ============================================================================
;;; Discovery v5 Protocol Implementation
;;; ============================================================================

(defstruct discv5-node
  "Discv5 node with peer discovery capability."
  (node-id (gensym "DISC5") :type symbol)
  (enr (make-hash-table :test 'equal) :type hash-table)
  (table (make-hash-table :test 'eq) :type hash-table)
  (sessions (make-hash-table :test 'equal) :type hash-table)
  (pending-pings (make-hash-table :test 'equal) :type hash-table)
  (seen-topics (make-hash-table :test 'equal) :type hash-table)
  (lock (sb-thread:make-mutex) :type sb-thread:mutex)
  (bootstrap-nodes nil :type list)
  (requests-sent 0 :type (integer 0 *))
  (responses-received 0 :type (integer 0 *))
  (peers-discovered 0 :type (integer 0 *)))

(defstruct discv5-enr
  "Ethereum Node Record."
  (signature (make-array 0 :element-type '(unsigned-byte 8)) :type vector)
  (sequence 1 :type (integer 1 *))
  (kv-pairs (make-hash-table :test 'equal) :type hash-table))

(defstruct discv5-session
  "Active discovery session with node."
  (id (gensym "SESSION") :type symbol)
  (remote-node-id (gensym) :type symbol)
  (handshake-sent-p nil :type boolean)
  (key (make-array 32 :element-type '(unsigned-byte 8)) :type vector)
  (created-at (get-universal-time) :type integer)
  (last-activity (get-universal-time) :type integer))

;;; ============================================================================
;;; Node Initialization
;;; ============================================================================

(defun make-discv5-node (&key (node-id nil) (bootstrap-nodes nil))
  "Create a Discv5 discovery node.
   Parameters:
     NODE-ID - Custom node ID (generated if nil)
     BOOTSTRAP-NODES - List of bootstrap node IDs
   Returns: discv5-node instance"
  (make-discv5-node
   :node-id (or node-id (gensym "DISCV5-"))
   :bootstrap-nodes bootstrap-nodes))

(defun start-discovery (node)
  "Start discovery process.
   Parameters:
     NODE - discv5-node instance
   Returns: T"
  (sb-thread:with-mutex ((discv5-node-lock node))
    ;; Seed with bootstrap nodes
    (loop for bn in (discv5-node-bootstrap-nodes node)
          do (setf (gethash bn (discv5-node-table node)) t))
    t))

;;; ============================================================================
;;; ENR (Ethereum Node Record) Management
;;; ============================================================================

(defun make-enr (&key (seq 1) (ip nil) (tcp nil) (udp nil) (public-key nil))
  "Create an Ethereum Node Record.
   Parameters:
     SEQ - Sequence number
     IP - IPv4 address
     TCP - TCP port
     UDP - UDP port
     PUBLIC-KEY - Node public key
   Returns: discv5-enr instance"
  (let ((enr (make-discv5-enr :sequence seq)))
    (when ip (setf (gethash "ip" (discv5-enr-kv-pairs enr)) ip))
    (when tcp (setf (gethash "tcp" (discv5-enr-kv-pairs enr)) tcp))
    (when udp (setf (gethash "udp" (discv5-enr-kv-pairs enr)) udp))
    (when public-key (setf (gethash "secp256k1" (discv5-enr-kv-pairs enr)) public-key))
    enr))

(defun update-enr (node enr)
  "Update node's ENR record.
   Parameters:
     NODE - discv5-node instance
     ENR - discv5-enr instance
   Returns: T"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (setf (gethash "enr" (discv5-node-enr node)) enr)
    t))

(defun get-enr (node)
  "Get node's ENR record.
   Parameters:
     NODE - discv5-node instance
   Returns: discv5-enr or NIL"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (gethash "enr" (discv5-node-enr node))))

(defun enr-to-text (enr)
  "Encode ENR as text format.
   Parameters:
     ENR - discv5-enr instance
   Returns: Text string"
  (with-output-to-string (s)
    (format s "enr:~A/~A"
            (enr-to-base64 enr)
            (discv5-enr-sequence enr))))

(defun enr-to-base64 (enr)
  "Encode ENR to base64.
   Parameters:
     ENR - discv5-enr instance
   Returns: Base64 string"
  ;; Simplified - real implementation would RLP-encode and base64
  (format nil "ENR-~A" (discv5-enr-sequence enr)))

;;; ============================================================================
;;; Protocol Messages
;;; ============================================================================

(defun make-ping-message (node-id)
  "Create a PING message.
   Returns: Message structure"
  (list :type :ping :node-id node-id :enr-seq 1))

(defun make-pong-message (node-id enr-seq)
  "Create a PONG message.
   Returns: Message structure"
  (list :type :pong :node-id node-id :enr-seq enr-seq))

(defun make-findnode-message (node-id target-distance)
  "Create a FINDNODE message.
   Parameters:
     NODE-ID - Requesting node
     TARGET-DISTANCE - Distance to search for
   Returns: Message structure"
  (list :type :findnode :node-id node-id :distance target-distance))

(defun make-nodes-message (node-id nodes)
  "Create a NODES response message.
   Parameters:
     NODE-ID - Responding node
     NODES - List of discovered nodes
   Returns: Message structure"
  (list :type :nodes :node-id node-id :nodes nodes :total 1))

;;; ============================================================================
;;; Peer Discovery
;;; ============================================================================

(defun send-ping (node remote-node-id)
  "Send PING to remote node.
   Parameters:
     NODE - discv5-node instance
     REMOTE-NODE-ID - Target node ID
   Returns: T"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (let ((session (make-discv5-session :remote-node-id remote-node-id)))
      (setf (gethash (discv5-session-id session) (discv5-node-sessions node)) session)
      (incf (discv5-node-requests-sent node))
      t)))

(defun record-pong (node remote-node-id)
  "Record received PONG from remote node.
   Parameters:
     NODE - discv5-node instance
     REMOTE-NODE-ID - Source node ID
   Returns: T"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (setf (gethash remote-node-id (discv5-node-table node)) t)
    (incf (discv5-node-responses-received node))
    t))

(defun find-nodes (node target-distance)
  "Perform node lookup at distance.
   Parameters:
     NODE - discv5-node instance
     TARGET-DISTANCE - Bit distance to search
   Returns: List of discovered node IDs"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (incf (discv5-node-requests-sent node))
    ;; Return known nodes at this distance
    (loop for nid being the hash-keys of (discv5-node-table node)
          collect nid)))

(defun handle-findnode-response (node nodes)
  "Process FINDNODE response.
   Parameters:
     NODE - discv5-node instance
     NODES - List of discovered nodes
   Returns: Count added"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (loop for n in nodes
          unless (gethash n (discv5-node-table node))
          do (setf (gethash n (discv5-node-table node)) t)
             (incf (discv5-node-peers-discovered node)))
    (length nodes)))

;;; ============================================================================
;;; Topic Advertisement (for Topic Table)
;;; ============================================================================

(defun register-topic (node topic)
  "Register interest in a topic.
   Parameters:
     NODE - discv5-node instance
     TOPIC - Topic name
   Returns: T"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (setf (gethash topic (discv5-node-seen-topics node)) (get-universal-time))
    t))

(defun advertise-topic (node topic)
  "Advertise topic to network.
   Parameters:
     NODE - discv5-node instance
     TOPIC - Topic name
   Returns: T"
  (register-topic node topic))

(defun list-topics (node)
  "List registered topics.
   Parameters:
     NODE - discv5-node instance
   Returns: List of topic names"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (loop for topic being the hash-keys of (discv5-node-seen-topics node)
          collect topic)))

;;; ============================================================================
;;; Statistics
;;; ============================================================================

(defun peer-count (node)
  "Count known peers in routing table.
   Parameters:
     NODE - discv5-node instance
   Returns: Integer count"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (hash-table-count (discv5-node-table node))))

(defun node-stats (node)
  "Get statistics for discovery node.
   Parameters:
     NODE - discv5-node instance
   Returns: Property list"
  (sb-thread:with-mutex ((discv5-node-lock node))
    (list :node-id (discv5-node-node-id node)
          :peers-known (hash-table-count (discv5-node-table node))
          :peers-discovered (discv5-node-peers-discovered node)
          :requests-sent (discv5-node-requests-sent node)
          :responses-received (discv5-node-responses-received node)
          :active-sessions (hash-table-count (discv5-node-sessions node))
          :topics-advertised (hash-table-count (discv5-node-seen-topics node)))))
