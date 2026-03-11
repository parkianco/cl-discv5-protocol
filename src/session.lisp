;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; session.lisp - Session management and encryption
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Session state for encrypted communication with a peer

(defstruct discv5-session
  "An encrypted session with a remote node."
  (node-id nil :type (or null node-id))
  (initiator-key nil)   ; Our encryption key (when we initiated)
  (recipient-key nil)   ; Their encryption key (when they initiated)
  (created-at 0 :type integer)
  (last-used 0 :type integer)
  (established-p nil :type boolean))

(defstruct session-cache
  "Cache of active sessions."
  (sessions (make-hash-table :test 'equalp) :type hash-table)
  (max-sessions 1000 :type fixnum)
  (session-timeout 86400 :type fixnum))  ; 24 hours

(defun make-session-cache-default ()
  "Create a default session cache."
  (make-session-cache))

(defun session-cache-get (cache node-id)
  "Get a session for a node ID."
  (gethash (node-id-bytes node-id) (session-cache-sessions cache)))

(defun session-cache-put (cache session)
  "Store a session in the cache."
  (let ((key (node-id-bytes (discv5-session-node-id session))))
    (setf (gethash key (session-cache-sessions cache)) session)
    ;; TODO: Evict old sessions if over limit
    session))

(defun session-cache-remove (cache node-id)
  "Remove a session from the cache."
  (remhash (node-id-bytes node-id) (session-cache-sessions cache)))

(defun session-cache-cleanup (cache current-time)
  "Remove expired sessions."
  (let ((timeout (session-cache-session-timeout cache))
        (to-remove nil))
    (maphash (lambda (key session)
               (when (> (- current-time (discv5-session-last-used session))
                        timeout)
                 (push key to-remove)))
             (session-cache-sessions cache))
    (dolist (key to-remove)
      (remhash key (session-cache-sessions cache)))
    (length to-remove)))

;;; Session key derivation (HKDF)

(defun derive-session-keys (secret initiator-id recipient-id challenge)
  "Derive session keys using HKDF.
   Returns (values initiator-key recipient-key)."
  (let* ((info (concatenate '(vector (unsigned-byte 8))
                            #(#x64 #x69 #x73 #x63 #x76 #x35 #x20  ; \"discv5 \"
                              #x6b #x65 #x79 #x20 #x61 #x67 #x72  ; \"key agr\"
                              #x65 #x65 #x6d #x65 #x6e #x74)      ; \"eement\"
                            (node-id-bytes initiator-id)
                            (node-id-bytes recipient-id)))
         (prk (hkdf-extract challenge secret))
         (okm (hkdf-expand prk info 32)))
    (values (subseq okm 0 16)    ; initiator-key
            (subseq okm 16 32)))) ; recipient-key

(defun create-session (our-id their-id our-privkey their-pubkey challenge initiator-p)
  "Create a new session with derived keys."
  (let* ((shared-secret (ecdh-compute-secret our-privkey their-pubkey))
         (init-id (if initiator-p our-id their-id))
         (recip-id (if initiator-p their-id our-id)))
    (multiple-value-bind (init-key recip-key)
        (derive-session-keys shared-secret init-id recip-id challenge)
      (make-discv5-session
       :node-id their-id
       :initiator-key (if initiator-p init-key recip-key)
       :recipient-key (if initiator-p recip-key init-key)
       :created-at (get-universal-time)
       :last-used (get-universal-time)
       :established-p t))))

(defun session-encrypt (session message our-nonce)
  "Encrypt a message using session keys."
  (let ((key (discv5-session-initiator-key session)))
    (setf (discv5-session-last-used session) (get-universal-time))
    (aes-gcm-encrypt key our-nonce message nil)))

(defun session-decrypt (session ciphertext their-nonce aad)
  "Decrypt a message using session keys."
  (let ((key (discv5-session-recipient-key session)))
    (setf (discv5-session-last-used session) (get-universal-time))
    (aes-gcm-decrypt key their-nonce ciphertext aad)))
