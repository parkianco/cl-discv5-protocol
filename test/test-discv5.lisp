;;;; test-discv5.lisp - Tests for Discovery v5 protocol
;;;; Part of cl-discv5-protocol

;;; Package discv5.test is defined in package.lisp with (:use #:cl #:discv5)
;;; so all discv5 exports are available without qualification.

(in-package #:discv5.test)

(defvar *test-count* 0)
(defvar *pass-count* 0)

(defmacro deftest (name &body body)
  `(progn
     (incf *test-count*)
     (handler-case
         (progn ,@body
                (incf *pass-count*)
                (format t "~&PASS: ~a~%" ',name))
       (error (e)
         (format t "~&FAIL: ~a - ~a~%" ',name e)))))

(defun run-tests ()
  "Run all Discovery v5 tests."
  (setf *test-count* 0 *pass-count* 0)

  ;; Node ID tests
  (deftest node-id-creation
    (let ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)))
      (let ((id (make-node-id-from-bytes bytes)))
        (assert (node-id-p id))
        (assert (equalp (node-id-bytes id) bytes)))))

  (deftest node-id-equality
    (let* ((bytes1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
           (bytes2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42))
           (bytes3 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x43))
           (id1 (make-node-id-from-bytes bytes1))
           (id2 (make-node-id-from-bytes bytes2))
           (id3 (make-node-id-from-bytes bytes3)))
      (assert (node-id= id1 id2))
      (assert (not (node-id= id1 id3)))))

  (deftest node-distance
    (let* ((bytes1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (bytes2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (id1 (make-node-id-from-bytes bytes1))
           (id2 (make-node-id-from-bytes bytes2)))
      ;; Same IDs have distance 0
      (assert (zerop (node-distance id1 id2)))
      ;; Different IDs have non-zero distance
      (setf (aref bytes2 31) 1)
      (let ((id3 (make-node-id-from-bytes bytes2)))
        (assert (= 1 (node-distance id1 id3))))))

  (deftest log-distance
    (let* ((bytes1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (bytes2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (id1 (make-node-id-from-bytes bytes1))
           (id2 (make-node-id-from-bytes bytes2)))
      ;; Same IDs have log-distance 0
      (assert (zerop (log-distance id1 id2)))
      ;; IDs differing in last bit have log-distance 1
      (setf (aref bytes2 31) 1)
      (let ((id3 (make-node-id-from-bytes bytes2)))
        (assert (= 1 (log-distance id1 id3))))))

  ;; Routing table tests
  (deftest routing-table-creation
    (let* ((local-id (make-node-id-from-bytes
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (table (make-routing-table-for-node local-id)))
      (assert (routing-table-p table))
      (assert (zerop (routing-table-node-count table)))))

  (deftest routing-table-add-node
    (let* ((local-id (make-node-id-from-bytes
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
           (table (make-routing-table-for-node local-id))
           (node-bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
           (node-id (make-node-id-from-bytes node-bytes))
           (node (make-discv5-node :id node-id)))
      (assert (routing-table-add table node))
      (assert (= 1 (routing-table-node-count table)))))

  ;; RLP tests
  (deftest rlp-encode-decode-integer
    (let ((val 12345))
      (assert (= val (rlp-decode (rlp-encode val))))))

  (deftest rlp-encode-decode-bytes
    (let ((val #(1 2 3 4 5)))
      (assert (equalp val (rlp-decode (rlp-encode val))))))

  (deftest rlp-encode-decode-list
    (let ((val (list 1 2 3)))
      (assert (equal val (rlp-decode (rlp-encode val))))))

  ;; Session tests
  (deftest session-cache-operations
    (let* ((cache (make-session-cache-default))
           (node-id (make-node-id-from-bytes
                     (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)))
           (session (make-discv5-session :node-id node-id)))
      (session-cache-put cache session)
      (assert (eq session (session-cache-get cache node-id)))
      (session-cache-remove cache node-id)
      (assert (null (session-cache-get cache node-id)))))

  ;; Topic table tests
  (deftest topic-table-operations
    (let* ((table (make-topic-table-default))
           (node-id (make-node-id-from-bytes
                     (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)))
           (node (make-discv5-node :id node-id)))
      (topic-table-register table "test-topic" node)
      (let ((nodes (topic-table-lookup table "test-topic")))
        (assert (= 1 (length nodes)))
        (assert (eq node (first nodes))))))

  ;; Summary
  (format t "~&~%~a/~a tests passed~%" *pass-count* *test-count*)
  (= *pass-count* *test-count*))
