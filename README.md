# cl-discv5-protocol

Pure Common Lisp implementation of Discv5 Protocol

## Overview
This library provides a robust, zero-dependency implementation of Discv5 Protocol for the Common Lisp ecosystem. It is designed to be highly portable, performant, and easy to integrate into any SBCL/CCL/ECL environment.

## Getting Started

Load the system using ASDF:

```lisp
(asdf:load-system #:cl-discv5-protocol)
```

## Usage Example

```lisp
;; Initialize the environment
(let ((ctx (cl-discv5-protocol:initialize-discv5-protocol :initial-id 42)))
  ;; Perform batch processing using the built-in standard toolkit
  (multiple-value-bind (results errors)
      (cl-discv5-protocol:discv5-protocol-batch-process '(1 2 3) #'identity)
    (format t "Processed ~A items with ~A errors.~%" (length results) (length errors))))
```

## License
Apache-2.0
