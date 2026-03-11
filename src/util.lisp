;;;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;;;; SPDX-License-Identifier: BSD-3-Clause

;;;; -*- Mode: Lisp; Syntax: Common-Lisp -*-
;;;; util.lisp - Utility functions for Discovery v5
;;;;
;;;; Byte operations, hex encoding, and general utilities.

(in-package #:discv5)

;;; ============================================================================
;;; Byte Array Operations
;;; ============================================================================

(deftype octet () '(unsigned-byte 8))
(deftype octet-vector () '(simple-array octet (*)))

(declaim (inline make-octet-vector))
(defun make-octet-vector (size &key (initial-element 0))
  "Create an octet vector of SIZE bytes."
  (declare (type fixnum size))
  (make-array size :element-type 'octet :initial-element initial-element))

(declaim (inline copy-octets))
(defun copy-octets (source dest &key (source-start 0) (dest-start 0) count)
  "Copy octets from SOURCE to DEST."
  (declare (type octet-vector source dest)
           (type fixnum source-start dest-start))
  (let ((n (or count (- (length source) source-start))))
    (declare (type fixnum n))
    (replace dest source
             :start1 dest-start :end1 (+ dest-start n)
             :start2 source-start :end2 (+ source-start n))
    dest))

(defun concat-octets (&rest vectors)
  "Concatenate multiple octet vectors into one."
  (let* ((total-length (reduce #'+ vectors :key #'length))
         (result (make-octet-vector total-length))
         (pos 0))
    (declare (type fixnum total-length pos))
    (dolist (vec vectors result)
      (let ((len (length vec)))
        (declare (type fixnum len))
        (replace result vec :start1 pos)
        (incf pos len)))))

(defun subseq-octets (vector start &optional end)
  "Extract a subsequence of octets."
  (declare (type octet-vector vector)
           (type fixnum start))
  (let* ((end (or end (length vector)))
         (len (- end start))
         (result (make-octet-vector len)))
    (declare (type fixnum end len))
    (replace result vector :start2 start :end2 end)
    result))

(defun octets= (a b)
  "Compare two octet vectors for equality."
  (declare (type octet-vector a b))
  (and (= (length a) (length b))
       (loop for i fixnum from 0 below (length a)
             always (= (aref a i) (aref b i)))))

(defun fill-random-bytes (buffer &optional (count (length buffer)))
  "Fill BUFFER with COUNT random bytes."
  (declare (type octet-vector buffer)
           (type fixnum count))
  (loop for i fixnum from 0 below count
        do (setf (aref buffer i) (random 256)))
  buffer)

(defun generate-random-bytes (count)
  "Generate COUNT random bytes."
  (declare (type fixnum count))
  (fill-random-bytes (make-octet-vector count)))

;;; ============================================================================
;;; Hex Encoding/Decoding
;;; ============================================================================

(defparameter +hex-chars+ "0123456789abcdef")

(defun bytes-to-hex (bytes)
  "Convert byte array to lowercase hex string."
  (declare (type octet-vector bytes))
  (let* ((len (length bytes))
         (result (make-string (* 2 len))))
    (declare (type fixnum len))
    (loop for i fixnum from 0 below len
          for byte = (aref bytes i)
          for j fixnum = (* i 2)
          do (setf (schar result j) (schar +hex-chars+ (ash byte -4)))
             (setf (schar result (1+ j)) (schar +hex-chars+ (logand byte #x0f))))
    result))

(defun hex-char-value (char)
  "Get numeric value of hex character."
  (declare (type character char))
  (cond
    ((char<= #\0 char #\9) (- (char-code char) (char-code #\0)))
    ((char<= #\a char #\f) (+ 10 (- (char-code char) (char-code #\a))))
    ((char<= #\A char #\F) (+ 10 (- (char-code char) (char-code #\A))))
    (t (error "Invalid hex character: ~A" char))))

(defun hex-to-bytes (hex-string)
  "Convert hex string to byte array."
  (declare (type string hex-string))
  (let* ((len (length hex-string))
         (start (if (and (>= len 2)
                        (char= (char hex-string 0) #\0)
                        (or (char= (char hex-string 1) #\x)
                            (char= (char hex-string 1) #\X)))
                   2 0))
         (hex-len (- len start))
         (byte-len (ceiling hex-len 2))
         (result (make-octet-vector byte-len)))
    (declare (type fixnum len start hex-len byte-len))
    (when (oddp hex-len)
      ;; Pad with leading zero
      (setf (aref result 0) (hex-char-value (char hex-string start)))
      (incf start))
    (loop for i fixnum from (if (oddp (- len start)) 1 0) below byte-len
          for j fixnum from start by 2
          do (setf (aref result i)
                   (logior (ash (hex-char-value (char hex-string j)) 4)
                           (hex-char-value (char hex-string (1+ j))))))
    result))

;;; ============================================================================
;;; Base64url Encoding (RFC 4648)
;;; ============================================================================

(defparameter +base64url-chars+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

(defun base64url-encode (bytes)
  "Encode bytes as base64url (no padding)."
  (declare (type octet-vector bytes))
  (let* ((len (length bytes))
         (out-len (ceiling (* len 4) 3))
         (result (make-string out-len))
         (out-pos 0))
    (declare (type fixnum len out-len out-pos))
    (loop for i fixnum from 0 below len by 3
          for b0 = (aref bytes i)
          for b1 = (if (< (1+ i) len) (aref bytes (1+ i)) 0)
          for b2 = (if (< (+ i 2) len) (aref bytes (+ i 2)) 0)
          for remaining = (- len i)
          do (setf (schar result out-pos)
                   (schar +base64url-chars+ (ash b0 -2)))
             (incf out-pos)
             (setf (schar result out-pos)
                   (schar +base64url-chars+
                          (logior (ash (logand b0 #x03) 4)
                                  (ash b1 -4))))
             (incf out-pos)
             (when (> remaining 1)
               (setf (schar result out-pos)
                     (schar +base64url-chars+
                            (logior (ash (logand b1 #x0f) 2)
                                    (ash b2 -6))))
               (incf out-pos))
             (when (> remaining 2)
               (setf (schar result out-pos)
                     (schar +base64url-chars+ (logand b2 #x3f)))
               (incf out-pos)))
    (subseq result 0 out-pos)))

(defun base64url-char-value (char)
  "Get numeric value of base64url character."
  (declare (type character char))
  (cond
    ((char<= #\A char #\Z) (- (char-code char) (char-code #\A)))
    ((char<= #\a char #\z) (+ 26 (- (char-code char) (char-code #\a))))
    ((char<= #\0 char #\9) (+ 52 (- (char-code char) (char-code #\0))))
    ((char= char #\-) 62)
    ((char= char #\_) 63)
    ((char= char #\=) -1)  ; Padding
    (t (error "Invalid base64url character: ~A" char))))

(defun base64url-decode (string)
  "Decode base64url string (with or without padding) to bytes."
  (declare (type string string))
  (let* ((len (length string))
         ;; Remove padding for length calculation
         (trimmed-len (loop for i from (1- len) downto 0
                           while (char= (char string i) #\=)
                           finally (return (1+ i))))
         (out-len (floor (* trimmed-len 3) 4))
         (result (make-octet-vector out-len))
         (out-pos 0))
    (declare (type fixnum len trimmed-len out-len out-pos))
    (loop for i fixnum from 0 below trimmed-len by 4
          for remaining = (- trimmed-len i)
          for c0 = (base64url-char-value (char string i))
          for c1 = (if (> remaining 1) (base64url-char-value (char string (+ i 1))) 0)
          for c2 = (if (> remaining 2) (base64url-char-value (char string (+ i 2))) 0)
          for c3 = (if (> remaining 3) (base64url-char-value (char string (+ i 3))) 0)
          do (setf (aref result out-pos)
                   (logior (ash c0 2) (ash c1 -4)))
             (incf out-pos)
             (when (and (> remaining 2) (< out-pos out-len))
               (setf (aref result out-pos)
                     (logior (ash (logand c1 #x0f) 4) (ash c2 -2)))
               (incf out-pos))
             (when (and (> remaining 3) (< out-pos out-len))
               (setf (aref result out-pos)
                     (logior (ash (logand c2 #x03) 6) c3))
               (incf out-pos)))
    result))

;;; ============================================================================
;;; Integer Encoding
;;; ============================================================================

(defun encode-uint16-be (value)
  "Encode 16-bit unsigned integer as big-endian bytes."
  (declare (type (unsigned-byte 16) value))
  (let ((result (make-octet-vector 2)))
    (setf (aref result 0) (ldb (byte 8 8) value))
    (setf (aref result 1) (ldb (byte 8 0) value))
    result))

(defun decode-uint16-be (bytes &optional (offset 0))
  "Decode big-endian 16-bit unsigned integer from bytes."
  (declare (type octet-vector bytes)
           (type fixnum offset))
  (logior (ash (aref bytes offset) 8)
          (aref bytes (1+ offset))))

(defun encode-uint32-be (value)
  "Encode 32-bit unsigned integer as big-endian bytes."
  (declare (type (unsigned-byte 32) value))
  (let ((result (make-octet-vector 4)))
    (setf (aref result 0) (ldb (byte 8 24) value))
    (setf (aref result 1) (ldb (byte 8 16) value))
    (setf (aref result 2) (ldb (byte 8 8) value))
    (setf (aref result 3) (ldb (byte 8 0) value))
    result))

(defun decode-uint32-be (bytes &optional (offset 0))
  "Decode big-endian 32-bit unsigned integer from bytes."
  (declare (type octet-vector bytes)
           (type fixnum offset))
  (logior (ash (aref bytes offset) 24)
          (ash (aref bytes (+ offset 1)) 16)
          (ash (aref bytes (+ offset 2)) 8)
          (aref bytes (+ offset 3))))

(defun encode-uint64-be (value)
  "Encode 64-bit unsigned integer as big-endian bytes."
  (declare (type (unsigned-byte 64) value))
  (let ((result (make-octet-vector 8)))
    (setf (aref result 0) (ldb (byte 8 56) value))
    (setf (aref result 1) (ldb (byte 8 48) value))
    (setf (aref result 2) (ldb (byte 8 40) value))
    (setf (aref result 3) (ldb (byte 8 32) value))
    (setf (aref result 4) (ldb (byte 8 24) value))
    (setf (aref result 5) (ldb (byte 8 16) value))
    (setf (aref result 6) (ldb (byte 8 8) value))
    (setf (aref result 7) (ldb (byte 8 0) value))
    result))

(defun decode-uint64-be (bytes &optional (offset 0))
  "Decode big-endian 64-bit unsigned integer from bytes."
  (declare (type octet-vector bytes)
           (type fixnum offset))
  (logior (ash (aref bytes offset) 56)
          (ash (aref bytes (+ offset 1)) 48)
          (ash (aref bytes (+ offset 2)) 40)
          (ash (aref bytes (+ offset 3)) 32)
          (ash (aref bytes (+ offset 4)) 24)
          (ash (aref bytes (+ offset 5)) 16)
          (ash (aref bytes (+ offset 6)) 8)
          (aref bytes (+ offset 7))))

;;; ============================================================================
;;; String Utilities
;;; ============================================================================

(defun split-string (string delimiter)
  "Split STRING by DELIMITER character."
  (declare (type string string)
           (type character delimiter))
  (loop for start fixnum = 0 then (1+ end)
        for end = (position delimiter string :start start)
        collect (subseq string start (or end (length string)))
        while end))

(defun string-prefix-p (prefix string)
  "Check if STRING starts with PREFIX."
  (declare (type string prefix string))
  (and (>= (length string) (length prefix))
       (string= prefix string :end2 (length prefix))))

;;; ============================================================================
;;; Time Utilities
;;; ============================================================================

(defun current-unix-time ()
  "Get current Unix timestamp in seconds."
  (- (get-universal-time) 2208988800))  ; Difference between 1900 and 1970

(defun current-unix-time-ms ()
  "Get current Unix timestamp in milliseconds."
  (* (current-unix-time) 1000))

;;; ============================================================================
;;; Logging
;;; ============================================================================

(defvar *log-level* :info)

(defun log-level-value (level)
  "Get numeric value for log level."
  (case level
    (:debug 0)
    (:info 1)
    (:warn 2)
    (:error 3)
    (otherwise 1)))

(defun log-message (level format-string &rest args)
  "Log a message at the given level."
  (when (>= (log-level-value level) (log-level-value *log-level*))
    (format t "~&[~A] [DISCV5] ~?~%" level format-string args)))

(defmacro log-debug (format-string &rest args)
  `(log-message :debug ,format-string ,@args))

(defmacro log-info (format-string &rest args)
  `(log-message :info ,format-string ,@args))

(defmacro log-warn (format-string &rest args)
  `(log-message :warn ,format-string ,@args))

(defmacro log-error (format-string &rest args)
  `(log-message :error ,format-string ,@args))
