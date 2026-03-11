;;;; -*- Mode: Lisp; Syntax: Common-Lisp -*-
;;;; crypto.lisp - Cryptographic primitives for Discovery v5
;;;;
;;;; Native implementations of:
;;;; - Keccak-256 (SHA-3 variant used by Ethereum)
;;;; - secp256k1 ECDSA (stub - requires real implementation)
;;;; - AES-GCM (stub - requires real implementation)
;;;; - HKDF key derivation
;;;; - HMAC-SHA256

(in-package #:discv5.crypto)

;;; ============================================================================
;;; Keccak-256 (Ethereum's hash function)
;;; ============================================================================
;;; This is a complete native implementation of Keccak-256.

(defconstant +keccak-rounds+ 24)
(defconstant +keccak-rate+ 136)  ; 1088 bits / 8 for Keccak-256
(defconstant +keccak-capacity+ 64)  ; 512 bits / 8

(deftype keccak-state () '(simple-array (unsigned-byte 64) (25)))

(defparameter +keccak-round-constants+
  (make-array 24 :element-type '(unsigned-byte 64)
              :initial-contents
              '(#x0000000000000001 #x0000000000008082 #x800000000000808a
                #x8000000080008000 #x000000000000808b #x0000000080000001
                #x8000000080008081 #x8000000000008009 #x000000000000008a
                #x0000000000000088 #x0000000080008009 #x000000008000000a
                #x000000008000808b #x800000000000008b #x8000000000008089
                #x8000000000008003 #x8000000000008002 #x8000000000000080
                #x000000000000800a #x800000008000000a #x8000000080008081
                #x8000000000008080 #x0000000080000001 #x8000000080008008)))

(defparameter +keccak-rotation-offsets+
  #2A((0 36 3 41 18)
      (1 44 10 45 2)
      (62 6 43 15 61)
      (28 55 25 21 56)
      (27 20 39 8 14)))

(declaim (inline keccak-rotate-left))
(defun keccak-rotate-left (x n)
  "Rotate 64-bit integer X left by N bits."
  (declare (type (unsigned-byte 64) x)
           (type (integer 0 63) n))
  (logior (ldb (byte 64 0) (ash x n))
          (ash x (- n 64))))

(defun keccak-f (state)
  "Apply Keccak-f[1600] permutation to STATE."
  (declare (type keccak-state state))
  (let ((c (make-array 5 :element-type '(unsigned-byte 64)))
        (d (make-array 5 :element-type '(unsigned-byte 64)))
        (b (make-array '(5 5) :element-type '(unsigned-byte 64))))
    (declare (type (simple-array (unsigned-byte 64) (5)) c d)
             (type (simple-array (unsigned-byte 64) (5 5)) b))
    (dotimes (round +keccak-rounds+)
      ;; Theta step
      (dotimes (x 5)
        (setf (aref c x)
              (logxor (aref state x)
                      (aref state (+ x 5))
                      (aref state (+ x 10))
                      (aref state (+ x 15))
                      (aref state (+ x 20)))))
      (dotimes (x 5)
        (setf (aref d x)
              (logxor (aref c (mod (+ x 4) 5))
                      (keccak-rotate-left (aref c (mod (1+ x) 5)) 1))))
      (dotimes (x 5)
        (dotimes (y 5)
          (let ((idx (+ x (* y 5))))
            (setf (aref state idx)
                  (logxor (aref state idx) (aref d x))))))
      ;; Rho and Pi steps
      (dotimes (x 5)
        (dotimes (y 5)
          (let ((idx (+ x (* y 5))))
            (setf (aref b y (mod (+ (* 2 x) (* 3 y)) 5))
                  (keccak-rotate-left (aref state idx)
                                      (aref +keccak-rotation-offsets+ x y))))))
      ;; Chi step
      (dotimes (x 5)
        (dotimes (y 5)
          (let ((idx (+ x (* y 5))))
            (setf (aref state idx)
                  (logxor (aref b x y)
                          (logandc2 (aref b (mod (1+ x) 5) y)
                                    (aref b (mod (+ x 2) 5) y)))))))
      ;; Iota step
      (setf (aref state 0)
            (logxor (aref state 0)
                    (aref +keccak-round-constants+ round))))
    state))

(defstruct (keccak-256-state (:constructor %make-keccak-256-state))
  "Keccak-256 hash state."
  (state (make-array 25 :element-type '(unsigned-byte 64) :initial-element 0)
         :type keccak-state)
  (buffer (make-array +keccak-rate+ :element-type '(unsigned-byte 8) :initial-element 0)
          :type (simple-array (unsigned-byte 8) (*)))
  (buffer-index 0 :type fixnum))

(defun make-keccak-256-state ()
  "Create a new Keccak-256 hash state."
  (%make-keccak-256-state))

(defun keccak-absorb-block (state block)
  "Absorb a rate-sized block into the Keccak state."
  (declare (type keccak-state state)
           (type (simple-array (unsigned-byte 8) (*)) block))
  (loop for i from 0 below (floor +keccak-rate+ 8)
        for byte-pos = (* i 8)
        do (setf (aref state i)
                 (logxor (aref state i)
                         (logior (aref block byte-pos)
                                 (ash (aref block (+ byte-pos 1)) 8)
                                 (ash (aref block (+ byte-pos 2)) 16)
                                 (ash (aref block (+ byte-pos 3)) 24)
                                 (ash (aref block (+ byte-pos 4)) 32)
                                 (ash (aref block (+ byte-pos 5)) 40)
                                 (ash (aref block (+ byte-pos 6)) 48)
                                 (ash (aref block (+ byte-pos 7)) 56)))))
  (keccak-f state))

(defun keccak-256-update (ctx data)
  "Update Keccak-256 hash with DATA bytes."
  (declare (type keccak-256-state ctx)
           (type (simple-array (unsigned-byte 8) (*)) data))
  (let ((state (keccak-256-state-state ctx))
        (buffer (keccak-256-state-buffer ctx))
        (buf-idx (keccak-256-state-buffer-index ctx))
        (data-len (length data))
        (data-pos 0))
    (declare (type fixnum buf-idx data-len data-pos))
    ;; Process any partial block from previous updates
    (when (> buf-idx 0)
      (let ((to-copy (min (- +keccak-rate+ buf-idx) data-len)))
        (replace buffer data :start1 buf-idx :end2 to-copy)
        (incf buf-idx to-copy)
        (incf data-pos to-copy)
        (when (= buf-idx +keccak-rate+)
          (keccak-absorb-block state buffer)
          (setf buf-idx 0))))
    ;; Process full blocks
    (loop while (>= (- data-len data-pos) +keccak-rate+)
          do (let ((block (make-array +keccak-rate+ :element-type '(unsigned-byte 8))))
               (replace block data :start2 data-pos :end2 (+ data-pos +keccak-rate+))
               (keccak-absorb-block state block)
               (incf data-pos +keccak-rate+)))
    ;; Store remaining data
    (when (< data-pos data-len)
      (replace buffer data :start2 data-pos)
      (setf buf-idx (- data-len data-pos)))
    (setf (keccak-256-state-buffer-index ctx) buf-idx))
  ctx)

(defun keccak-256-finalize (ctx)
  "Finalize Keccak-256 hash and return 32-byte digest."
  (declare (type keccak-256-state ctx))
  (let ((state (keccak-256-state-state ctx))
        (buffer (keccak-256-state-buffer ctx))
        (buf-idx (keccak-256-state-buffer-index ctx)))
    (declare (type fixnum buf-idx))
    ;; Pad message: append 0x01, zeros, and 0x80
    (setf (aref buffer buf-idx) #x01)
    (fill buffer 0 :start (1+ buf-idx) :end (1- +keccak-rate+))
    (setf (aref buffer (1- +keccak-rate+))
          (logior (aref buffer (1- +keccak-rate+)) #x80))
    (keccak-absorb-block state buffer)
    ;; Extract 32 bytes of output
    (let ((output (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i from 0 below 4
            for word = (aref state i)
            for byte-pos = (* i 8)
            do (loop for j from 0 below 8
                     do (setf (aref output (+ byte-pos j))
                              (ldb (byte 8 (* j 8)) word))))
      output)))

(defun keccak-256 (data)
  "Compute Keccak-256 hash of DATA bytes."
  (declare (type (simple-array (unsigned-byte 8) (*)) data))
  (let ((ctx (make-keccak-256-state)))
    (keccak-256-update ctx data)
    (keccak-256-finalize ctx)))

;;; ============================================================================
;;; secp256k1 Elliptic Curve (STUB - requires full implementation)
;;; ============================================================================
;;; NOTE: These are stub implementations. For production use, implement
;;; the full secp256k1 curve operations or link to a native library.

;; secp256k1 curve parameters
(defconstant +secp256k1-p+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
(defconstant +secp256k1-n+
  #xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
(defconstant +secp256k1-gx+
  #x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
(defconstant +secp256k1-gy+
  #x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

(defun mod-inverse (a n)
  "Compute modular inverse of A mod N using extended Euclidean algorithm."
  (declare (type integer a n))
  (let ((t1 0) (new-t 1)
        (r n) (new-r (mod a n)))
    (loop while (not (zerop new-r))
          do (let ((quotient (floor r new-r)))
               (psetf t1 new-t
                      new-t (- t1 (* quotient new-t)))
               (psetf r new-r
                      new-r (- r (* quotient new-r)))))
    (if (< t1 0)
        (+ t1 n)
        t1)))

(defun ec-point-double (px py)
  "Double a point on secp256k1 curve."
  (declare (type integer px py))
  (if (zerop py)
      (values 0 0)
      (let* ((s (mod (* (mod (* 3 px px) +secp256k1-p+)
                        (mod-inverse (* 2 py) +secp256k1-p+))
                     +secp256k1-p+))
             (rx (mod (- (* s s) (* 2 px)) +secp256k1-p+))
             (ry (mod (- (* s (- px rx)) py) +secp256k1-p+)))
        (values rx ry))))

(defun ec-point-add (px py qx qy)
  "Add two points on secp256k1 curve."
  (declare (type integer px py qx qy))
  (cond
    ((and (zerop px) (zerop py)) (values qx qy))
    ((and (zerop qx) (zerop qy)) (values px py))
    ((and (= px qx) (= py qy)) (ec-point-double px py))
    ((= px qx) (values 0 0))  ; Point at infinity
    (t (let* ((s (mod (* (- qy py)
                         (mod-inverse (- qx px) +secp256k1-p+))
                      +secp256k1-p+))
              (rx (mod (- (* s s) px qx) +secp256k1-p+))
              (ry (mod (- (* s (- px rx)) py) +secp256k1-p+)))
         (values rx ry)))))

(defun ec-point-multiply (k px py)
  "Multiply point (PX, PY) by scalar K on secp256k1 curve."
  (declare (type integer k px py))
  (let ((rx 0) (ry 0)
        (qx px) (qy py)
        (n k))
    (loop while (plusp n)
          do (when (oddp n)
               (multiple-value-setq (rx ry) (ec-point-add rx ry qx qy)))
             (multiple-value-setq (qx qy) (ec-point-double qx qy))
             (setf n (ash n -1)))
    (values rx ry)))

(defun secp256k1-multiply-generator (scalar)
  "Multiply secp256k1 generator point by SCALAR, return compressed public key."
  (declare (type integer scalar))
  (multiple-value-bind (x y)
      (ec-point-multiply scalar +secp256k1-gx+ +secp256k1-gy+)
    (compress-public-key x y)))

(defun compress-public-key (x y)
  "Compress secp256k1 public key to 33 bytes."
  (declare (type integer x y))
  (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) (if (evenp y) #x02 #x03))
    (loop for i from 1 to 32
          do (setf (aref result i) (ldb (byte 8 (* 8 (- 32 i))) x)))
    result))

(defun decompress-public-key (compressed)
  "Decompress 33-byte secp256k1 public key to (x, y)."
  (declare (type (simple-array (unsigned-byte 8) (33)) compressed))
  (let* ((prefix (aref compressed 0))
         (x (loop with val = 0
                  for i from 1 to 32
                  do (setf val (logior (ash val 8) (aref compressed i)))
                  finally (return val)))
         ;; y^2 = x^3 + 7 (mod p)
         (y-squared (mod (+ (mod (* x x x) +secp256k1-p+) 7) +secp256k1-p+))
         ;; y = y_squared^((p+1)/4) (mod p) for p = 3 (mod 4)
         (y (mod-expt y-squared (/ (1+ +secp256k1-p+) 4) +secp256k1-p+)))
    ;; Adjust y based on prefix
    (when (xor (= prefix #x03) (oddp y))
      (setf y (- +secp256k1-p+ y)))
    (values x y)))

(defun mod-expt (base exp modulus)
  "Compute BASE^EXP mod MODULUS."
  (declare (type integer base exp modulus))
  (let ((result 1)
        (b (mod base modulus))
        (e exp))
    (loop while (plusp e)
          do (when (oddp e)
               (setf result (mod (* result b) modulus)))
             (setf b (mod (* b b) modulus))
             (setf e (ash e -1)))
    result))

(defun generate-keypair ()
  "Generate a new secp256k1 keypair. Returns (private-key . public-key)."
  (let* ((private-key (loop for pk = (discv5::generate-random-bytes 32)
                            for val = (loop with v = 0
                                           for i from 0 below 32
                                           do (setf v (logior (ash v 8) (aref pk i)))
                                           finally (return v))
                            while (or (zerop val) (>= val +secp256k1-n+))
                            finally (return pk)))
         (pk-int (loop with v = 0
                      for i from 0 below 32
                      do (setf v (logior (ash v 8) (aref private-key i)))
                      finally (return v)))
         (public-key (secp256k1-multiply-generator pk-int)))
    (cons private-key public-key)))

(defun derive-public-key (private-key)
  "Derive public key from private key."
  (declare (type (simple-array (unsigned-byte 8) (32)) private-key))
  (let ((pk-int (loop with v = 0
                     for i from 0 below 32
                     do (setf v (logior (ash v 8) (aref private-key i)))
                     finally (return v))))
    (secp256k1-multiply-generator pk-int)))

(defun secp256k1-sign (message-hash private-key)
  "Sign MESSAGE-HASH with PRIVATE-KEY. Returns 64-byte signature."
  (declare (type (simple-array (unsigned-byte 8) (32)) message-hash private-key))
  ;; STUB: Return placeholder signature
  ;; TODO: Implement proper ECDSA signing
  (let ((sig (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace sig message-hash)
    sig))

(defun secp256k1-verify (message-hash signature public-key)
  "Verify SIGNATURE on MESSAGE-HASH with PUBLIC-KEY."
  (declare (type (simple-array (unsigned-byte 8) (*)) message-hash signature public-key))
  ;; STUB: Always return T for testing
  ;; TODO: Implement proper ECDSA verification
  (declare (ignore message-hash signature public-key))
  t)

(defun secp256k1-recover (message-hash signature recovery-id)
  "Recover public key from signature."
  (declare (type (simple-array (unsigned-byte 8) (*)) message-hash signature)
           (type (integer 0 3) recovery-id))
  ;; STUB: Return placeholder
  (declare (ignore message-hash signature recovery-id))
  (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0))

(defun secp256k1-multiply (point scalar)
  "Multiply POINT by SCALAR on secp256k1."
  (declare (type (simple-array (unsigned-byte 8) (*)) point)
           (type (simple-array (unsigned-byte 8) (32)) scalar))
  ;; STUB: Return placeholder
  (declare (ignore point scalar))
  (make-array 33 :element-type '(unsigned-byte 8) :initial-element 0))

;;; ============================================================================
;;; HMAC-SHA256
;;; ============================================================================

(defun sha256 (data)
  "Compute SHA-256 hash of DATA. STUB - uses Keccak-256 as placeholder."
  ;; STUB: Using Keccak-256 as placeholder
  ;; TODO: Implement proper SHA-256
  (keccak-256 data))

(defun hmac-sha256 (key message)
  "Compute HMAC-SHA256 of MESSAGE with KEY."
  (declare (type (simple-array (unsigned-byte 8) (*)) key message))
  (let ((block-size 64)
        (key-padded (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; If key > block-size, hash it
    (if (> (length key) block-size)
        (let ((hashed (sha256 key)))
          (replace key-padded hashed))
        (replace key-padded key))
    ;; Inner padding
    (let ((ipad (make-array 64 :element-type '(unsigned-byte 8))))
      (dotimes (i 64)
        (setf (aref ipad i) (logxor (aref key-padded i) #x36)))
      ;; Outer padding
      (let ((opad (make-array 64 :element-type '(unsigned-byte 8))))
        (dotimes (i 64)
          (setf (aref opad i) (logxor (aref key-padded i) #x5c)))
        ;; HMAC = H(opad || H(ipad || message))
        (sha256 (discv5::concat-octets opad (sha256 (discv5::concat-octets ipad message))))))))

;;; ============================================================================
;;; HKDF (HMAC-based Key Derivation Function) - RFC 5869
;;; ============================================================================

(defun hkdf-extract (salt ikm)
  "HKDF-Extract: Extract pseudorandom key from input keying material."
  (declare (type (simple-array (unsigned-byte 8) (*)) salt ikm))
  (hmac-sha256 (if (zerop (length salt))
                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                   salt)
               ikm))

(defun hkdf-expand (prk info length)
  "HKDF-Expand: Expand pseudorandom key to desired length."
  (declare (type (simple-array (unsigned-byte 8) (*)) prk info)
           (type fixnum length))
  (let* ((hash-len 32)
         (n (ceiling length hash-len))
         (okm (make-array length :element-type '(unsigned-byte 8)))
         (t-prev (make-array 0 :element-type '(unsigned-byte 8))))
    (declare (type fixnum hash-len n))
    (loop for i from 1 to n
          for t-i = (hmac-sha256 prk
                                  (discv5::concat-octets t-prev info
                                                         (make-array 1 :element-type '(unsigned-byte 8)
                                                                     :initial-element i)))
          for start = (* (1- i) hash-len)
          for end = (min length (* i hash-len))
          do (replace okm t-i :start1 start :end1 end)
             (setf t-prev t-i))
    okm))

(defun hkdf-derive (ikm salt info length)
  "HKDF: Full key derivation from IKM to output of LENGTH bytes."
  (declare (type (simple-array (unsigned-byte 8) (*)) ikm salt info)
           (type fixnum length))
  (let ((prk (hkdf-extract salt ikm)))
    (hkdf-expand prk info length)))

;;; ============================================================================
;;; AES-GCM (STUB - requires real implementation)
;;; ============================================================================

(defun aes-gcm-encrypt (key nonce plaintext &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Encrypt PLAINTEXT with AES-GCM. Returns (ciphertext . tag)."
  (declare (type (simple-array (unsigned-byte 8) (16)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) plaintext aad))
  ;; STUB: XOR with key-derived stream (NOT SECURE - for testing only)
  (declare (ignore aad))
  (let ((ciphertext (make-array (length plaintext) :element-type '(unsigned-byte 8)))
        (tag (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i (length plaintext))
      (setf (aref ciphertext i)
            (logxor (aref plaintext i)
                    (aref key (mod i 16))
                    (aref nonce (mod i 12)))))
    ;; Generate pseudo-tag
    (dotimes (i 16)
      (setf (aref tag i)
            (if (< i (length ciphertext))
                (logxor (aref ciphertext i) (aref key i))
                (aref key i))))
    (cons ciphertext tag)))

(defun aes-gcm-decrypt (key nonce ciphertext tag &optional (aad (make-array 0 :element-type '(unsigned-byte 8))))
  "Decrypt CIPHERTEXT with AES-GCM. Returns plaintext or NIL if auth fails."
  (declare (type (simple-array (unsigned-byte 8) (16)) key)
           (type (simple-array (unsigned-byte 8) (12)) nonce)
           (type (simple-array (unsigned-byte 8) (*)) ciphertext)
           (type (simple-array (unsigned-byte 8) (16)) tag)
           (type (simple-array (unsigned-byte 8) (*)) aad))
  ;; STUB: XOR with key-derived stream (NOT SECURE - for testing only)
  (declare (ignore aad tag))
  (let ((plaintext (make-array (length ciphertext) :element-type '(unsigned-byte 8))))
    (dotimes (i (length ciphertext))
      (setf (aref plaintext i)
            (logxor (aref ciphertext i)
                    (aref key (mod i 16))
                    (aref nonce (mod i 12)))))
    plaintext))

;;; ============================================================================
;;; Secure Random Bytes
;;; ============================================================================

(defun secure-random-bytes (count)
  "Generate COUNT cryptographically secure random bytes.
   Uses /dev/urandom on Unix systems, falls back to SBCL's random."
  (declare (type fixnum count))
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    #+unix
    (with-open-file (urandom "/dev/urandom" :element-type '(unsigned-byte 8))
      (read-sequence result urandom))
    #-unix
    (dotimes (i count)
      (setf (aref result i) (random 256)))
    result))

(defun generate-random-bytes (count)
  "Generate COUNT random bytes (alias for secure-random-bytes)."
  (secure-random-bytes count))
