;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; node-id.lisp - Node ID and distance calculations
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Node ID is a 256-bit identifier derived from the public key

(defstruct node-id
  "A 256-bit node identifier."
  (bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
         :type (simple-array (unsigned-byte 8) (32))))

(defun make-node-id-from-bytes (bytes)
  "Create a node ID from a 32-byte array."
  (let ((id-bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (replace id-bytes bytes :end1 (min 32 (length bytes)))
    (make-node-id :bytes id-bytes)))

(defun node-id-from-pubkey (pubkey)
  "Derive node ID from a public key using Keccak-256."
  (make-node-id-from-bytes (keccak-256 pubkey)))

(defun node-id= (a b)
  "Test if two node IDs are equal."
  (equalp (node-id-bytes a) (node-id-bytes b)))

(defun node-id-hash (id)
  "Hash a node ID for use in hash tables."
  (sxhash (node-id-bytes id)))

;;; Distance calculations (XOR metric for Kademlia)

(defun node-distance (id1 id2)
  "Calculate XOR distance between two node IDs.
   Returns a 256-bit integer."
  (let ((bytes1 (node-id-bytes id1))
        (bytes2 (node-id-bytes id2))
        (result 0))
    (dotimes (i 32)
      (setf result (logior (ash result 8)
                           (logxor (aref bytes1 i) (aref bytes2 i)))))
    result))

(defun log-distance (id1 id2)
  "Calculate log2 distance (bucket index) between two node IDs.
   Returns 0-256, where 0 means identical."
  (let ((dist (node-distance id1 id2)))
    (if (zerop dist)
        0
        (integer-length dist))))

(defun node-id-to-hex (id)
  "Convert node ID to hexadecimal string."
  (bytes-to-hex (node-id-bytes id)))

(defun hex-to-node-id (hex)
  "Parse node ID from hexadecimal string."
  (make-node-id-from-bytes (hex-to-bytes hex)))
