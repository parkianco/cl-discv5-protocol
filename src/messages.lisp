;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; messages.lisp - Protocol messages
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Message encoding/decoding for Discovery v5 protocol

(defstruct ping-message
  "PING request message."
  (request-id 0 :type integer)
  (enr-seq 0 :type integer))

(defstruct pong-message
  "PONG response message."
  (request-id 0 :type integer)
  (enr-seq 0 :type integer)
  (recipient-ip nil)
  (recipient-port 0 :type fixnum))

(defstruct findnode-message
  "FINDNODE request message."
  (request-id 0 :type integer)
  (distances nil :type list))  ; List of log-distances to query

(defstruct nodes-message
  "NODES response message."
  (request-id 0 :type integer)
  (total 1 :type fixnum)
  (enrs nil :type list))  ; List of ENRs

(defstruct talkreq-message
  "TALKREQ request message."
  (request-id 0 :type integer)
  (protocol nil)
  (request nil))

(defstruct talkresp-message
  "TALKRESP response message."
  (request-id 0 :type integer)
  (response nil))

(defun encode-message (msg-type msg)
  "Encode a message to RLP bytes."
  (let ((content
          (etypecase msg
            (ping-message
             (list (ping-message-request-id msg)
                   (ping-message-enr-seq msg)))
            (pong-message
             (list (pong-message-request-id msg)
                   (pong-message-enr-seq msg)
                   (pong-message-recipient-ip msg)
                   (pong-message-recipient-port msg)))
            (findnode-message
             (list (findnode-message-request-id msg)
                   (findnode-message-distances msg)))
            (nodes-message
             (list (nodes-message-request-id msg)
                   (nodes-message-total msg)
                   (mapcar #'enr-raw (nodes-message-enrs msg))))
            (talkreq-message
             (list (talkreq-message-request-id msg)
                   (talkreq-message-protocol msg)
                   (talkreq-message-request msg)))
            (talkresp-message
             (list (talkresp-message-request-id msg)
                   (talkresp-message-response msg))))))
    (concatenate '(vector (unsigned-byte 8))
                 (vector msg-type)
                 (rlp-encode content))))

(defun decode-message (bytes)
  "Decode a message from RLP bytes."
  (when (< (length bytes) 2)
    (error 'invalid-packet-error :message "Message too short"))
  (let* ((msg-type (aref bytes 0))
         (content (rlp-decode (subseq bytes 1))))
    (ecase msg-type
      (#.+msg-ping+
       (make-ping-message :request-id (first content)
                          :enr-seq (second content)))
      (#.+msg-pong+
       (make-pong-message :request-id (first content)
                          :enr-seq (second content)
                          :recipient-ip (third content)
                          :recipient-port (fourth content)))
      (#.+msg-findnode+
       (make-findnode-message :request-id (first content)
                              :distances (second content)))
      (#.+msg-nodes+
       (make-nodes-message :request-id (first content)
                           :total (second content)
                           :enrs (mapcar #'enr-decode (third content))))
      (#.+msg-talkreq+
       (make-talkreq-message :request-id (first content)
                             :protocol (second content)
                             :request (third content)))
      (#.+msg-talkresp+
       (make-talkresp-message :request-id (first content)
                              :response (second content))))))

(defun next-request-id ()
  "Generate a new request ID."
  (random (ash 1 64)))

(defun make-ping (enr-seq)
  "Create a PING message."
  (make-ping-message :request-id (next-request-id)
                     :enr-seq enr-seq))

(defun make-pong (request-id enr-seq ip port)
  "Create a PONG message."
  (make-pong-message :request-id request-id
                     :enr-seq enr-seq
                     :recipient-ip ip
                     :recipient-port port))

(defun make-findnode (distances)
  "Create a FINDNODE message."
  (make-findnode-message :request-id (next-request-id)
                         :distances distances))

(defun make-nodes (request-id enrs)
  "Create a NODES response message."
  (make-nodes-message :request-id request-id
                      :total 1
                      :enrs enrs))
