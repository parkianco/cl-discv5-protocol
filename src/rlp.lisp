;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: Apache-2.0

;;;; -*- Mode: Lisp; Syntax: Common-Lisp -*-
;;;; rlp.lisp - Recursive Length Prefix encoding for Ethereum
;;;;
;;;; RLP encoding is the main serialization format used in Ethereum.
;;;; This is a complete native implementation per the Ethereum Yellow Paper.

(in-package #:discv5)

;;; ============================================================================
;;; RLP Encoding
;;; ============================================================================

(defun octet-sequence-p (item)
  "Return true when ITEM is a vector whose elements are octets."
  (and (vectorp item)
       (every (lambda (value) (typep value '(unsigned-byte 8))) item)))

(defun ensure-octet-vector (item)
  "Coerce ITEM to a simple octet vector."
  (let ((result (make-octet-vector (length item))))
    (replace result item)
    result))

(defun rlp-encode (item)
  "Encode ITEM using RLP. ITEM can be bytes, a string, an integer, or a list."
  (cond
    ((octet-sequence-p item)
     (rlp-encode-bytes (ensure-octet-vector item)))
    ((stringp item)
     (rlp-encode-bytes (map '(vector (unsigned-byte 8)) #'char-code item)))
    ((integerp item)
     (rlp-encode-integer item))
    ((listp item)
     (rlp-encode-list item))
    ((null item)
     (rlp-encode-bytes (make-octet-vector 0)))
    (t
     (error "Unsupported RLP item: ~S" item))))

(defun rlp-encode-bytes (bytes)
  "RLP encode a byte array."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (let ((len (length bytes)))
    (cond
      ;; Single byte [0x00, 0x7f]: encode as itself
      ((and (= len 1) (<= (aref bytes 0) #x7f))
       (let ((result (make-octet-vector 1)))
         (setf (aref result 0) (aref bytes 0))
         result))
      ;; Short string (0-55 bytes): 0x80 + length, then data
      ((<= len 55)
       (let ((result (make-octet-vector (1+ len))))
         (setf (aref result 0) (+ #x80 len))
         (replace result bytes :start1 1)
         result))
      ;; Long string (>55 bytes): 0xb7 + length-of-length, length, data
      (t
       (let* ((len-bytes (rlp-encode-length len))
              (len-len (length len-bytes))
              (result (make-octet-vector (+ 1 len-len len))))
         (setf (aref result 0) (+ #xb7 len-len))
         (replace result len-bytes :start1 1)
         (replace result bytes :start1 (+ 1 len-len))
         result)))))

(defun rlp-encode-integer (n)
  "RLP encode a non-negative integer."
  (declare (type (integer 0) n))
  (if (zerop n)
      (rlp-encode-bytes (make-octet-vector 0))
      (let* ((byte-count (ceiling (integer-length n) 8))
             (bytes (make-octet-vector byte-count)))
        (loop for i from (1- byte-count) downto 0
              for shift from 0 by 8
              do (setf (aref bytes i) (ldb (byte 8 shift) n)))
        (rlp-encode-bytes bytes))))

(defun rlp-encode-list (items)
  "RLP encode a list of items."
  (let* ((encoded-items (mapcar #'rlp-encode items))
         (payload (apply #'concat-octets encoded-items))
         (payload-len (length payload)))
    (cond
      ;; Short list (0-55 bytes total): 0xc0 + length, then items
      ((<= payload-len 55)
       (let ((result (make-octet-vector (1+ payload-len))))
         (setf (aref result 0) (+ #xc0 payload-len))
         (replace result payload :start1 1)
         result))
      ;; Long list (>55 bytes): 0xf7 + length-of-length, length, items
      (t
       (let* ((len-bytes (rlp-encode-length payload-len))
              (len-len (length len-bytes))
              (result (make-octet-vector (+ 1 len-len payload-len))))
         (setf (aref result 0) (+ #xf7 len-len))
         (replace result len-bytes :start1 1)
         (replace result payload :start1 (+ 1 len-len))
         result)))))

(defun rlp-encode-length (length)
  "Encode LENGTH as big-endian bytes (no leading zeros)."
  (declare (type (integer 0) length))
  (let* ((byte-count (max 1 (ceiling (integer-length length) 8)))
         (bytes (make-octet-vector byte-count)))
    (loop for i from (1- byte-count) downto 0
          for shift from 0 by 8
          do (setf (aref bytes i) (ldb (byte 8 shift) length)))
    ;; Remove leading zeros
    (let ((start (position-if-not #'zerop bytes)))
      (if start
          (subseq-octets bytes start)
          (make-octet-vector 1)))))

;;; ============================================================================
;;; RLP Decoding
;;; ============================================================================

(defun rlp-decode-with-offset (data &optional (offset 0))
  "Decode RLP DATA starting at OFFSET and return VALUE and NEXT-OFFSET."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum offset))
  (when (>= offset (length data))
    (error 'validation-error :message "RLP: unexpected end of data"))
  (let ((prefix (aref data offset)))
    (cond
      ;; Single byte [0x00, 0x7f]
      ((<= prefix #x7f)
       (let ((result (make-octet-vector 1)))
         (setf (aref result 0) prefix)
         (values result (1+ offset))))
      ;; Short string [0x80, 0xb7]: length = prefix - 0x80
      ((<= prefix #xb7)
       (let* ((len (- prefix #x80))
              (start (1+ offset))
              (end (+ start len)))
         (when (> end (length data))
           (error 'validation-error :message "RLP: string length exceeds data"))
         (values (subseq-octets data start end) end)))
      ;; Long string [0xb8, 0xbf]: prefix - 0xb7 bytes for length
      ((<= prefix #xbf)
       (let* ((len-len (- prefix #xb7))
              (len (rlp-decode-length data (1+ offset) len-len))
              (start (+ 1 offset len-len))
              (end (+ start len)))
         (when (> end (length data))
           (error 'validation-error :message "RLP: string length exceeds data"))
         (values (subseq-octets data start end) end)))
      ;; Short list [0xc0, 0xf7]: length = prefix - 0xc0
      ((<= prefix #xf7)
       (let* ((len (- prefix #xc0))
              (start (1+ offset))
              (end (+ start len)))
         (when (> end (length data))
           (error 'validation-error :message "RLP: list length exceeds data"))
         (values (rlp-decode-list data start end) end)))
      ;; Long list [0xf8, 0xff]: prefix - 0xf7 bytes for length
      (t
       (let* ((len-len (- prefix #xf7))
              (len (rlp-decode-length data (1+ offset) len-len))
              (start (+ 1 offset len-len))
              (end (+ start len)))
         (when (> end (length data))
           (error 'validation-error :message "RLP: list length exceeds data"))
         (values (rlp-decode-list data start end) end))))))

(defun rlp-decode (data &optional (offset 0))
  "Decode RLP DATA starting at OFFSET and return the decoded value."
  (nth-value 0 (rlp-decode-with-offset data offset)))

(defun rlp-decode-length (data offset len-len)
  "Decode big-endian length from DATA at OFFSET with LEN-LEN bytes."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum offset len-len))
  (loop with result = 0
        for i from 0 below len-len
        do (setf result (logior (ash result 8) (aref data (+ offset i))))
        finally (return result)))

(defun rlp-decode-list (data start end)
  "Decode RLP list items between START and END in DATA."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum start end))
  (loop with offset = start
        with items = nil
        while (< offset end)
        do (multiple-value-bind (item next-offset)
               (rlp-decode-with-offset data offset)
             (push item items)
             (setf offset next-offset))
        finally (return (nreverse items))))

(defun rlp-decode-integer (bytes)
  "Decode bytes as big-endian unsigned integer."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (loop with result = 0
        for byte across bytes
        do (setf result (logior (ash result 8) byte))
        finally (return result)))

;;; ============================================================================
;;; RLP Content Type Checking
;;; ============================================================================

(defun rlp-list-p (data &optional (offset 0))
  "Check if RLP data at OFFSET is a list."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum offset))
  (>= (aref data offset) #xc0))

(defun rlp-string-p (data &optional (offset 0))
  "Check if RLP data at OFFSET is a string/bytes."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type fixnum offset))
  (< (aref data offset) #xc0))
