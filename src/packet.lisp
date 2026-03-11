;;;; packet.lisp - Packet encoding/decoding
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Packet structure:
;;; [masking-iv (16)] [masked-header (variable)] [message (variable)]
;;;
;;; Header structure (after unmasking):
;;; [protocol-id (6)] [version (2)] [flag (1)] [nonce (12)] [authdata-size (2)] [authdata (variable)]

(defvar +protocol-id+ #(#x64 #x69 #x73 #x63 #x76 #x35))  ; "discv5"

(defstruct packet-header
  "Discovery v5 packet header."
  (version +discv5-version+ :type fixnum)
  (flag 0 :type fixnum)  ; 0=ordinary, 1=whoareyou, 2=handshake
  (nonce nil)
  (authdata nil))

(defstruct packet
  "A complete discovery v5 packet."
  (header nil :type (or null packet-header))
  (src-id nil :type (or null node-id))
  (message nil)
  (raw nil))

(defun encode-packet-header (header)
  "Encode packet header to bytes."
  (let* ((authdata (packet-header-authdata header))
         (authdata-size (if authdata (length authdata) 0))
         (result (make-array (+ 6 2 1 +nonce-size+ 2 authdata-size)
                             :element-type '(unsigned-byte 8))))
    ;; Protocol ID
    (replace result +protocol-id+)
    ;; Version (2 bytes, big-endian)
    (setf (aref result 6) 0
          (aref result 7) (packet-header-version header))
    ;; Flag
    (setf (aref result 8) (packet-header-flag header))
    ;; Nonce
    (when (packet-header-nonce header)
      (replace result (packet-header-nonce header) :start1 9))
    ;; Authdata size
    (setf (aref result (+ 9 +nonce-size+)) (ash authdata-size -8)
          (aref result (+ 10 +nonce-size+)) (logand authdata-size #xff))
    ;; Authdata
    (when authdata
      (replace result authdata :start1 (+ 11 +nonce-size+)))
    result))

(defun decode-packet-header (bytes)
  "Decode packet header from bytes."
  (when (< (length bytes) (+ 6 2 1 +nonce-size+ 2))
    (error 'invalid-packet-error :message "Header too short"))
  ;; Verify protocol ID
  (unless (equalp (subseq bytes 0 6) +protocol-id+)
    (error 'invalid-packet-error :message "Invalid protocol ID"))
  (let* ((version (aref bytes 7))
         (flag (aref bytes 8))
         (nonce (subseq bytes 9 (+ 9 +nonce-size+)))
         (authdata-size (logior (ash (aref bytes (+ 9 +nonce-size+)) 8)
                                (aref bytes (+ 10 +nonce-size+))))
         (authdata (when (> authdata-size 0)
                     (subseq bytes (+ 11 +nonce-size+)
                             (+ 11 +nonce-size+ authdata-size)))))
    (make-packet-header :version version
                        :flag flag
                        :nonce nonce
                        :authdata authdata)))

(defun mask-header (header dest-id)
  "Mask header bytes using destination node ID."
  (let* ((encoded (encode-packet-header header))
         (mask-key (subseq (node-id-bytes dest-id) 0 16))
         (masked (make-array (length encoded)
                             :element-type '(unsigned-byte 8))))
    (dotimes (i (length encoded))
      (setf (aref masked i)
            (logxor (aref encoded i) (aref mask-key (mod i 16)))))
    masked))

(defun unmask-header (masked-bytes src-id)
  "Unmask header bytes using source node ID."
  (let* ((mask-key (subseq (node-id-bytes src-id) 0 16))
         (unmasked (make-array (length masked-bytes)
                               :element-type '(unsigned-byte 8))))
    (dotimes (i (length masked-bytes))
      (setf (aref unmasked i)
            (logxor (aref masked-bytes i) (aref mask-key (mod i 16)))))
    unmasked))

(defun encode-packet (packet dest-id session-key)
  "Encode a complete packet with encryption."
  (let* ((header (packet-header packet))
         (masking-iv (generate-random-bytes 16))
         (masked-header (mask-header header dest-id))
         (nonce (packet-header-nonce header))
         (message-bytes (when (packet-message packet)
                          (rlp-encode (packet-message packet))))
         (encrypted (when message-bytes
                      (aes-gcm-encrypt session-key nonce message-bytes
                                       masked-header))))
    (concatenate '(vector (unsigned-byte 8))
                 masking-iv
                 masked-header
                 (or encrypted #()))))

(defun decode-packet (bytes src-id session-key)
  "Decode a complete packet with decryption."
  (when (< (length bytes) 16)
    (error 'invalid-packet-error :message "Packet too short"))
  (let* ((masking-iv (subseq bytes 0 16))
         (rest (subseq bytes 16))
         (unmasked-header-bytes (unmask-header rest src-id))
         (header (decode-packet-header unmasked-header-bytes))
         (header-len (+ 11 +nonce-size+
                        (if (packet-header-authdata header)
                            (length (packet-header-authdata header))
                            0)))
         (encrypted (subseq rest header-len))
         (message (when (and session-key (> (length encrypted) 0))
                    (let ((decrypted (aes-gcm-decrypt
                                      session-key
                                      (packet-header-nonce header)
                                      encrypted
                                      (subseq rest 0 header-len))))
                      (when decrypted
                        (rlp-decode decrypted))))))
    (declare (ignore masking-iv))
    (make-packet :header header
                 :src-id src-id
                 :message message
                 :raw bytes)))
