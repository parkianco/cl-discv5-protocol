;; Copyright (c) 2024-2026 Parkian Company LLC. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

(in-package #:cl-discv5-protocol)

;;; Core types for cl-discv5-protocol
(deftype cl-discv5-protocol-id () '(unsigned-byte 64))
(deftype cl-discv5-protocol-status () '(member :ready :active :error :shutdown))
