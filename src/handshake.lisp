;;;; handshake.lisp - WHOAREYOU challenge-response handshake
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; WHOAREYOU packet structure:
;;; - magic: keccak256(dest-id || "WHOAREYOU")[:32]
;;; - token: 32 bytes (random challenge)
;;; - id-nonce: 16 bytes
;;; - enr-seq: RLP-encoded sequence number

(defstruct whoareyou
  "A WHOAREYOU challenge packet."
  (magic nil)      ; 32-byte authentication tag
  (token nil)      ; 32-byte challenge token
  (id-nonce nil)   ; 16-byte ID nonce
  (enr-seq 0 :type integer)
  (node nil))      ; Optional: node we're challenging

(defun compute-whoareyou-magic (dest-id)
  "Compute the WHOAREYOU magic bytes."
  (let ((preimage (concatenate '(vector (unsigned-byte 8))
                               (node-id-bytes dest-id)
                               ;; "WHOAREYOU" in bytes
                               #(#x57 #x48 #x4f #x41 #x52 #x45 #x59 #x4f #x55))))
    (subseq (keccak-256 preimage) 0 32)))

(defun make-whoareyou-challenge (dest-id enr-seq)
  "Create a new WHOAREYOU challenge."
  (make-whoareyou
   :magic (compute-whoareyou-magic dest-id)
   :token (generate-random-bytes 32)
   :id-nonce (generate-random-bytes 16)
   :enr-seq enr-seq))

(defun encode-whoareyou (whoareyou)
  "Encode WHOAREYOU to bytes."
  (let ((enr-seq-rlp (rlp-encode (whoareyou-enr-seq whoareyou))))
    (concatenate '(vector (unsigned-byte 8))
                 (whoareyou-magic whoareyou)
                 (whoareyou-token whoareyou)
                 (whoareyou-id-nonce whoareyou)
                 enr-seq-rlp)))

(defun decode-whoareyou (bytes dest-id)
  "Decode WHOAREYOU from bytes."
  (let ((expected-magic (compute-whoareyou-magic dest-id)))
    (unless (equalp (subseq bytes 0 32) expected-magic)
      (error 'handshake-error :message "Invalid WHOAREYOU magic"))
    (make-whoareyou
     :magic (subseq bytes 0 32)
     :token (subseq bytes 32 64)
     :id-nonce (subseq bytes 64 80)
     :enr-seq (rlp-decode (subseq bytes 80)))))

;;; Handshake response (auth message)

(defstruct handshake-auth
  "Authentication data for handshake response."
  (version 5 :type fixnum)
  (id-nonce-sig nil)    ; Signature over id-nonce
  (ephemeral-pubkey nil) ; Ephemeral ECDH public key
  (enr nil))            ; Optional ENR if requested

(defun sign-id-nonce (privkey id-nonce challenge-data)
  "Sign the ID nonce for handshake authentication."
  (let* ((message (concatenate '(vector (unsigned-byte 8))
                               ;; "discovery v5 identity proof" prefix
                               #(#x64 #x69 #x73 #x63 #x6f #x76 #x65 #x72 #x79
                                 #x20 #x76 #x35 #x20 #x69 #x64 #x65 #x6e #x74
                                 #x69 #x74 #x79 #x20 #x70 #x72 #x6f #x6f #x66)
                               challenge-data
                               id-nonce))
         (hash (keccak-256 message)))
    (secp256k1-sign privkey hash)))

(defun verify-id-nonce-sig (pubkey sig id-nonce challenge-data)
  "Verify the ID nonce signature."
  (let* ((message (concatenate '(vector (unsigned-byte 8))
                               #(#x64 #x69 #x73 #x63 #x6f #x76 #x65 #x72 #x79
                                 #x20 #x76 #x35 #x20 #x69 #x64 #x65 #x6e #x74
                                 #x69 #x74 #x79 #x20 #x70 #x72 #x6f #x6f #x66)
                               challenge-data
                               id-nonce))
         (hash (keccak-256 message)))
    (secp256k1-verify pubkey hash sig)))

(defun create-handshake-response (privkey whoareyou our-enr include-enr-p)
  "Create a handshake response to a WHOAREYOU challenge."
  (let* ((ephemeral-privkey (generate-random-bytes 32))
         (ephemeral-pubkey (secp256k1-pubkey-compress
                            (secp256k1-derive-pubkey ephemeral-privkey)))
         (id-nonce-sig (sign-id-nonce privkey
                                      (whoareyou-id-nonce whoareyou)
                                      (whoareyou-token whoareyou))))
    (make-handshake-auth
     :version 5
     :id-nonce-sig id-nonce-sig
     :ephemeral-pubkey ephemeral-pubkey
     :enr (when include-enr-p our-enr))))

(defun encode-handshake-auth (auth)
  "Encode handshake auth data."
  (let ((parts (list (handshake-auth-version auth)
                     (handshake-auth-id-nonce-sig auth)
                     (handshake-auth-ephemeral-pubkey auth))))
    (when (handshake-auth-enr auth)
      (push (enr-raw (handshake-auth-enr auth)) (cdr (last parts))))
    (rlp-encode parts)))

(defun decode-handshake-auth (bytes)
  "Decode handshake auth data."
  (let ((decoded (rlp-decode bytes)))
    (make-handshake-auth
     :version (first decoded)
     :id-nonce-sig (second decoded)
     :ephemeral-pubkey (third decoded)
     :enr (when (fourth decoded)
            (enr-decode (fourth decoded))))))
