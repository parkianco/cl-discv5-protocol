;;;; discovery.lisp - Main discovery service
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Main Discovery v5 service implementation

(defstruct discovery
  "The main Discovery v5 service."
  (local-enr nil :type (or null enr))
  (local-id nil :type (or null node-id))
  (privkey nil)
  (routing-table nil :type (or null routing-table))
  (session-cache nil :type (or null session-cache))
  (topic-table nil :type (or null topic-table))
  (pending-requests (make-hash-table) :type hash-table)
  (socket nil)
  (running-p nil :type boolean)
  (udp-port 30303 :type fixnum)
  (bootnodes nil :type list))

(defun make-discovery-service (&key privkey udp-port bootnodes ip)
  "Create a new discovery service."
  (let* ((privkey (or privkey (generate-random-bytes 32)))
         (enr (make-enr-with-keys privkey :udp udp-port :ip ip))
         (local-id (enr-node-id enr)))
    (make-discovery
     :local-enr enr
     :local-id local-id
     :privkey privkey
     :routing-table (make-routing-table-for-node local-id)
     :session-cache (make-session-cache-default)
     :topic-table (make-topic-table-default)
     :udp-port (or udp-port 30303)
     :bootnodes (or bootnodes nil))))

(defun discovery-start (discovery)
  "Start the discovery service."
  (setf (discovery-running-p discovery) t)
  ;; Create UDP socket
  (let ((socket (make-udp-socket (discovery-udp-port discovery))))
    (setf (discovery-socket discovery) socket))
  ;; Bootstrap from known nodes
  (dolist (bootnode (discovery-bootnodes discovery))
    (discovery-ping discovery bootnode))
  discovery)

(defun discovery-stop (discovery)
  "Stop the discovery service."
  (setf (discovery-running-p discovery) nil)
  (when (discovery-socket discovery)
    (close-udp-socket (discovery-socket discovery))
    (setf (discovery-socket discovery) nil))
  discovery)

(defun discovery-send (discovery node data)
  "Send data to a node."
  (let* ((session (session-cache-get (discovery-session-cache discovery)
                                     (discv5-node-id node)))
         (nonce (generate-random-bytes +nonce-size+))
         (header (make-packet-header
                  :version +discv5-version+
                  :flag (if session 0 2)  ; ordinary or handshake
                  :nonce nonce))
         (packet (make-packet
                  :header header
                  :src-id (discovery-local-id discovery)
                  :message data))
         (session-key (when session (discv5-session-initiator-key session)))
         (encoded (encode-packet packet (discv5-node-id node) session-key)))
    (udp-send (discovery-socket discovery)
              encoded
              (discv5-node-address node)
              (discv5-node-udp-port node))))

(defun discovery-receive (discovery)
  "Receive and process incoming packets."
  (multiple-value-bind (data addr port)
      (udp-receive (discovery-socket discovery))
    (when data
      (handler-case
          (discovery-handle-packet discovery data addr port)
        (discv5-error (e)
          (format *error-output* "Packet error: ~A~%" e))))))

(defun discovery-handle-packet (discovery data src-addr src-port)
  "Handle an incoming packet."
  ;; Check for WHOAREYOU
  (when (and (>= (length data) 32)
             (equalp (subseq data 0 32)
                     (compute-whoareyou-magic (discovery-local-id discovery))))
    (return-from discovery-handle-packet
      (discovery-handle-whoareyou discovery data src-addr src-port)))
  ;; Regular packet - try to find session
  (let* ((src-id (guess-src-id discovery src-addr src-port))
         (session (when src-id
                    (session-cache-get (discovery-session-cache discovery) src-id))))
    (when session
      (let* ((session-key (discv5-session-recipient-key session))
             (packet (decode-packet data src-id session-key)))
        (when (packet-message packet)
          (discovery-handle-message discovery packet src-addr src-port))))))

(defun discovery-handle-whoareyou (discovery data src-addr src-port)
  "Handle a WHOAREYOU challenge."
  (let* ((whoareyou (decode-whoareyou data (discovery-local-id discovery)))
         (need-enr-p (< (whoareyou-enr-seq whoareyou)
                        (enr-seq (discovery-local-enr discovery))))
         (auth (create-handshake-response (discovery-privkey discovery)
                                          whoareyou
                                          (discovery-local-enr discovery)
                                          need-enr-p)))
    ;; Create and establish session
    ;; Send handshake response
    (declare (ignore auth src-addr src-port))))

(defun discovery-handle-message (discovery packet src-addr src-port)
  "Handle a decrypted message."
  (let* ((msg (decode-message (packet-message packet)))
         (src-node (make-discv5-node
                    :id (packet-src-id packet)
                    :address src-addr
                    :udp-port src-port)))
    (etypecase msg
      (ping-message
       (handle-ping discovery src-node msg))
      (pong-message
       (handle-pong discovery src-node msg))
      (findnode-message
       (handle-findnode discovery src-node msg))
      (nodes-message
       (handle-nodes discovery src-node msg nil))
      (talkreq-message
       (handle-talkreq discovery src-node msg))
      (regtopic-message
       (handle-regtopic discovery src-node msg))
      (topicquery-message
       (handle-topicquery discovery src-node msg)))))

(defun discovery-ping (discovery node)
  "Send a PING to a node."
  (let ((msg (make-ping (enr-seq (discovery-local-enr discovery)))))
    (discovery-send discovery node (encode-message +msg-ping+ msg))))

(defun handle-ping (discovery src-node msg)
  "Handle an incoming PING."
  ;; Update routing table
  (routing-table-add (discovery-routing-table discovery) src-node)
  ;; Send PONG
  (let ((pong (make-pong (ping-message-request-id msg)
                         (enr-seq (discovery-local-enr discovery))
                         (discv5-node-address src-node)
                         (discv5-node-udp-port src-node))))
    (discovery-send discovery src-node (encode-message +msg-pong+ pong))))

(defun handle-pong (discovery src-node msg)
  "Handle an incoming PONG."
  (declare (ignore msg))
  ;; Update routing table
  (setf (discv5-node-last-pong src-node) (get-universal-time))
  (routing-table-add (discovery-routing-table discovery) src-node))

(defun handle-talkreq (discovery src-node msg)
  "Handle an incoming TALKREQ."
  ;; Stub - override for custom protocols
  (declare (ignore discovery src-node msg))
  nil)

(defun guess-src-id (discovery src-addr src-port)
  "Try to guess the source node ID from address."
  ;; This is a simplified implementation - real version would
  ;; look up nodes by address in the routing table
  (declare (ignore discovery src-addr src-port))
  nil)

;;; UDP socket stubs (implementation depends on platform)

(defun make-udp-socket (port)
  "Create a UDP socket bound to PORT."
  (declare (ignore port))
  ;; Stub - would use sb-bsd-sockets in real implementation
  nil)

(defun close-udp-socket (socket)
  "Close a UDP socket."
  (declare (ignore socket))
  nil)

(defun udp-send (socket data addr port)
  "Send data over UDP."
  (declare (ignore socket data addr port))
  nil)

(defun udp-receive (socket)
  "Receive data from UDP socket.
   Returns (values data src-addr src-port) or NIL."
  (declare (ignore socket))
  (values nil nil nil))
