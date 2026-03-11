;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; topics.lisp - Topic advertisement
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Topic-based service discovery
;;; Allows nodes to advertise and discover services by topic name

(defstruct topic
  "A topic for service advertisement."
  (name nil :type (or null string))
  (hash nil)  ; Keccak-256 of topic name
  (nodes nil :type list)
  (created-at 0 :type integer))

(defstruct topic-table
  "Table of known topics and their advertisers."
  (topics (make-hash-table :test 'equal) :type hash-table)
  (max-ads-per-topic 100 :type fixnum)
  (ad-lifetime 900 :type fixnum))  ; 15 minutes

(defun make-topic-table-default ()
  "Create a default topic table."
  (make-topic-table))

(defun compute-topic-hash (name)
  "Compute the hash of a topic name."
  (keccak-256 (map 'vector #'char-code name)))

(defun topic-table-register (table topic-name node)
  "Register a node as advertising a topic."
  (let ((topic (or (gethash topic-name (topic-table-topics table))
                   (let ((new-topic (make-topic
                                     :name topic-name
                                     :hash (compute-topic-hash topic-name)
                                     :created-at (get-universal-time))))
                     (setf (gethash topic-name (topic-table-topics table)) new-topic)
                     new-topic))))
    ;; Add node if not already present
    (unless (find (discv5-node-id node) (topic-nodes topic)
                  :key #'discv5-node-id :test #'node-id=)
      (push node (topic-nodes topic))
      ;; Limit size
      (when (> (length (topic-nodes topic)) (topic-table-max-ads-per-topic table))
        (setf (topic-nodes topic)
              (subseq (topic-nodes topic) 0 (topic-table-max-ads-per-topic table)))))
    topic))

(defun topic-table-lookup (table topic-name)
  "Look up nodes advertising a topic."
  (let ((topic (gethash topic-name (topic-table-topics table))))
    (when topic
      (topic-nodes topic))))

(defun topic-table-remove (table topic-name node-id)
  "Remove a node from a topic."
  (let ((topic (gethash topic-name (topic-table-topics table))))
    (when topic
      (setf (topic-nodes topic)
            (remove node-id (topic-nodes topic)
                    :key #'discv5-node-id :test #'node-id=)))))

(defun topic-table-cleanup (table current-time)
  "Remove expired topic advertisements."
  (let ((lifetime (topic-table-ad-lifetime table))
        (to-remove nil))
    (maphash (lambda (name topic)
               (when (> (- current-time (topic-created-at topic)) lifetime)
                 (push name to-remove)))
             (topic-table-topics table))
    (dolist (name to-remove)
      (remhash name (topic-table-topics table)))
    (length to-remove)))

;;; Topic registration protocol messages

(defstruct regtopic-message
  "REGTOPIC request message."
  (request-id 0 :type integer)
  (topic nil :type (or null string))
  (enr nil)
  (ticket nil))

(defstruct ticket-message
  "TICKET response message."
  (request-id 0 :type integer)
  (ticket nil)
  (wait-time 0 :type fixnum))

(defstruct regconfirm-message
  "REGCONFIRMATION response message."
  (request-id 0 :type integer)
  (topic nil :type (or null string)))

(defstruct topicquery-message
  "TOPICQUERY request message."
  (request-id 0 :type integer)
  (topic nil :type (or null string)))

(defun handle-regtopic (discovery src-node msg)
  "Handle an incoming REGTOPIC request."
  (let* ((topic-name (regtopic-message-topic msg))
         (enr (regtopic-message-enr msg))
         (table (discovery-topic-table discovery)))
    ;; Verify ENR
    (when (and enr (enr-verify enr))
      (let ((node (node-from-enr enr)))
        (topic-table-register table topic-name node)
        ;; Send confirmation
        (discovery-send discovery src-node
                        (encode-message +msg-regconfirm+
                                        (make-regconfirm-message
                                         :request-id (regtopic-message-request-id msg)
                                         :topic topic-name)))))))

(defun handle-topicquery (discovery src-node msg)
  "Handle an incoming TOPICQUERY request."
  (let* ((topic-name (topicquery-message-topic msg))
         (table (discovery-topic-table discovery))
         (nodes (topic-table-lookup table topic-name))
         (enrs (mapcar #'discv5-node-enr nodes)))
    ;; Send NODES response with advertising nodes
    (send-nodes discovery src-node
                (topicquery-message-request-id msg)
                (subseq enrs 0 (min 16 (length enrs))))))

(defun advertise-topic (discovery topic-name)
  "Advertise that we provide a topic/service."
  (let* ((topic-hash (compute-topic-hash topic-name))
         (target-id (make-node-id-from-bytes topic-hash))
         (closest (routing-table-closest (discovery-routing-table discovery)
                                         target-id 3)))
    ;; Register with closest nodes to topic hash
    (dolist (node closest)
      (discovery-send discovery node
                      (encode-message +msg-regtopic+
                                      (make-regtopic-message
                                       :request-id (next-request-id)
                                       :topic topic-name
                                       :enr (discovery-local-enr discovery)
                                       :ticket nil))))))

(defun query-topic (discovery topic-name callback)
  "Query for nodes providing a topic/service."
  (declare (ignore callback))  ; Will be used for async response handling
  (let* ((topic-hash (compute-topic-hash topic-name))
         (target-id (make-node-id-from-bytes topic-hash))
         (closest (routing-table-closest (discovery-routing-table discovery)
                                         target-id 3)))
    ;; Query closest nodes to topic hash
    (dolist (node closest)
      (discovery-send discovery node
                      (encode-message +msg-topicquery+
                                      (make-topicquery-message
                                       :request-id (next-request-id)
                                       :topic topic-name))))))
