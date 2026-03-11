;;;; enr.lisp - Ethereum Node Records (EIP-778)
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; ENR (Ethereum Node Record) implementation
;;; See https://eips.ethereum.org/EIPS/eip-778

(defstruct enr
  "Ethereum Node Record containing node metadata."
  (seq 0 :type integer)              ; Sequence number (incremented on update)
  (signature nil)                     ; 64-byte signature
  (pairs (make-hash-table :test 'equal) :type hash-table)  ; Key-value pairs
  (raw nil))                          ; Raw RLP-encoded bytes

;;; Standard ENR keys
;;; Note: Using defvar instead of defconstant because SBCL's
;;; DEFCONSTANT-UNEQL check fails for strings on reload.
(defvar +enr-key-id+ "id")        ; Identity scheme (e.g., "v4")
(defvar +enr-key-secp256k1+ "secp256k1")  ; Compressed public key
(defvar +enr-key-ip+ "ip")        ; IPv4 address (4 bytes)
(defvar +enr-key-tcp+ "tcp")      ; TCP port
(defvar +enr-key-udp+ "udp")      ; UDP port
(defvar +enr-key-ip6+ "ip6")      ; IPv6 address (16 bytes)
(defvar +enr-key-tcp6+ "tcp6")    ; IPv6 TCP port
(defvar +enr-key-udp6+ "udp6")    ; IPv6 UDP port

(defun enr-get (enr key)
  "Get a value from an ENR."
  (gethash key (enr-pairs enr)))

(defun enr-set (enr key value)
  "Set a value in an ENR. Increments sequence number."
  (setf (gethash key (enr-pairs enr)) value)
  (incf (enr-seq enr))
  (setf (enr-raw enr) nil)  ; Invalidate cached encoding
  value)

(defun enr-node-id (enr)
  "Get the node ID from an ENR (derived from public key)."
  (let ((pubkey (enr-get enr +enr-key-secp256k1+)))
    (when pubkey
      (node-id-from-pubkey pubkey))))

(defun make-enr-with-keys (privkey &key ip tcp udp)
  "Create a new ENR with the given keys."
  (let ((enr (make-enr)))
    (enr-set enr +enr-key-id+ "v4")
    (let ((pubkey (secp256k1-pubkey-compress
                   (secp256k1-derive-pubkey privkey))))
      (enr-set enr +enr-key-secp256k1+ pubkey))
    (when ip (enr-set enr +enr-key-ip+ ip))
    (when tcp (enr-set enr +enr-key-tcp+ tcp))
    (when udp (enr-set enr +enr-key-udp+ udp))
    enr))

(defun enr-encode (enr privkey)
  "Encode ENR to RLP with signature."
  (let* ((content (enr-encode-content enr))
         (hash (keccak-256 content))
         (sig (secp256k1-sign privkey hash)))
    (setf (enr-signature enr) sig)
    (let ((full (rlp-encode (list sig (enr-seq enr)
                                  (enr-pairs-to-list enr)))))
      (setf (enr-raw enr) full)
      full)))

(defun enr-encode-content (enr)
  "Encode ENR content (without signature) for signing."
  (rlp-encode (list (enr-seq enr) (enr-pairs-to-list enr))))

(defun enr-pairs-to-list (enr)
  "Convert ENR pairs to sorted key-value list."
  (let ((pairs nil))
    (maphash (lambda (k v) (push (list k v) pairs))
             (enr-pairs enr))
    (sort pairs #'string< :key #'first)))

(defun enr-decode (bytes)
  "Decode ENR from RLP bytes."
  (let* ((decoded (rlp-decode bytes))
         (sig (first decoded))
         (seq (second decoded))
         (pairs-list (cddr decoded))
         (enr (make-enr :seq seq :signature sig :raw bytes)))
    (loop for (key value) on pairs-list by #'cddr
          do (setf (gethash key (enr-pairs enr)) value))
    enr))

(defun enr-verify (enr)
  "Verify ENR signature."
  (let* ((pubkey (enr-get enr +enr-key-secp256k1+))
         (content (enr-encode-content enr))
         (hash (keccak-256 content)))
    (when pubkey
      (secp256k1-verify pubkey hash (enr-signature enr)))))

(defun enr-to-url (enr)
  "Convert ENR to enr:// URL format."
  (format nil "enr:~A" (base64-encode (enr-raw enr))))

(defun url-to-enr (url)
  "Parse ENR from enr:// URL format."
  (let ((prefix "enr:"))
    (when (and (>= (length url) (length prefix))
               (string= (subseq url 0 (length prefix)) prefix))
      (enr-decode (base64-decode (subseq url (length prefix)))))))
