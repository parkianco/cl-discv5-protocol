;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-discv5-protocol)

(define-condition cl-discv5-protocol-error (error)
  ((message :initarg :message :reader cl-discv5-protocol-error-message))
  (:report (lambda (condition stream)
             (format stream "cl-discv5-protocol error: ~A" (cl-discv5-protocol-error-message condition)))))
