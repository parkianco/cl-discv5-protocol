;;;; types.lisp - Protocol types and conditions
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Protocol constants
(defconstant +discv5-version+ 1)
(defconstant +max-packet-size+ 1280)
(defconstant +nonce-size+ 12)
(defconstant +tag-size+ 32)
(defconstant +auth-tag-size+ 16)

;;; Message types
(defconstant +msg-ping+ #x01)
(defconstant +msg-pong+ #x02)
(defconstant +msg-findnode+ #x03)
(defconstant +msg-nodes+ #x04)
(defconstant +msg-talkreq+ #x05)
(defconstant +msg-talkresp+ #x06)
(defconstant +msg-regtopic+ #x07)
(defconstant +msg-ticket+ #x08)
(defconstant +msg-regconfirm+ #x09)
(defconstant +msg-topicquery+ #x0a)

;;; Conditions
(define-condition discv5-error (error)
  ((message :initarg :message :reader discv5-error-message))
  (:report (lambda (c s)
             (format s "Discovery v5 error: ~A" (discv5-error-message c)))))

(define-condition invalid-packet-error (discv5-error) ()
  (:report (lambda (c s)
             (format s "Invalid packet: ~A" (discv5-error-message c)))))

(define-condition handshake-error (discv5-error) ()
  (:report (lambda (c s)
             (format s "Handshake failed: ~A" (discv5-error-message c)))))

(define-condition decryption-error (discv5-error) ()
  (:report (lambda (c s)
             (format s "Decryption failed: ~A" (discv5-error-message c)))))

;;; Node representation
(defstruct discv5-node
  "A node in the discovery network."
  (id nil :type (or null node-id))
  (enr nil :type (or null enr))
  (address nil)  ; IP address bytes
  (udp-port 0 :type fixnum)
  (tcp-port 0 :type fixnum)
  (last-seen 0 :type integer)
  (last-pong 0 :type integer)
  (failures 0 :type fixnum))

(defun node-from-enr (enr)
  "Create a node from an ENR."
  (make-discv5-node
   :id (enr-node-id enr)
   :enr enr
   :address (enr-get enr +enr-key-ip+)
   :udp-port (or (enr-get enr +enr-key-udp+) 0)
   :tcp-port (or (enr-get enr +enr-key-tcp+) 0)))

;;; Request tracking
(defstruct pending-request
  "A pending outbound request."
  (id 0 :type integer)
  (type nil :type keyword)
  (target nil :type (or null node-id))
  (timestamp 0 :type integer)
  (callback nil :type (or null function))
  (retries 0 :type fixnum))
