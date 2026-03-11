;;;; routing.lisp - Kademlia routing table
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; Kademlia routing table with 256 k-buckets
;;; Each bucket holds up to K nodes at a specific log-distance

(defconstant +k-bucket-size+ 16)
(defconstant +num-buckets+ 256)
(defconstant +alpha+ 3)  ; Concurrency factor for lookups

(defstruct k-bucket
  "A Kademlia k-bucket containing nodes at similar distance."
  (nodes nil :type list)
  (replacements nil :type list)  ; Pending replacement nodes
  (last-updated 0 :type integer))

(defstruct routing-table
  "Kademlia routing table with 256 k-buckets."
  (local-id nil :type (or null node-id))
  (buckets (make-array +num-buckets+ :initial-element nil) :type simple-vector)
  (node-count 0 :type fixnum))

(defun make-routing-table-for-node (local-id)
  "Create a routing table for a local node."
  (let ((table (make-routing-table :local-id local-id)))
    (dotimes (i +num-buckets+)
      (setf (aref (routing-table-buckets table) i)
            (make-k-bucket)))
    table))

(defun bucket-index (table node-id)
  "Get the bucket index for a node ID."
  (let ((dist (log-distance (routing-table-local-id table) node-id)))
    (min (1- +num-buckets+) (max 0 (1- dist)))))

(defun get-bucket (table node-id)
  "Get the bucket for a node ID."
  (aref (routing-table-buckets table) (bucket-index table node-id)))

(defun bucket-full-p (bucket)
  "Check if a bucket is full."
  (>= (length (k-bucket-nodes bucket)) +k-bucket-size+))

(defun routing-table-add (table node)
  "Add a node to the routing table.
   Returns T if added, NIL if rejected."
  (let* ((node-id (discv5-node-id node))
         (bucket (get-bucket table node-id)))
    (cond
      ;; Already in bucket - move to tail (most recently seen)
      ((find node-id (k-bucket-nodes bucket) :key #'discv5-node-id :test #'node-id=)
       (setf (k-bucket-nodes bucket)
             (append (remove node (k-bucket-nodes bucket) :key #'discv5-node-id
                             :test (lambda (a b) (node-id= a (discv5-node-id b))))
                     (list node)))
       (setf (k-bucket-last-updated bucket) (get-universal-time))
       t)
      ;; Bucket not full - add to tail
      ((not (bucket-full-p bucket))
       (push node (k-bucket-nodes bucket))
       (setf (k-bucket-last-updated bucket) (get-universal-time))
       (incf (routing-table-node-count table))
       t)
      ;; Bucket full - add to replacements
      (t
       (unless (find node-id (k-bucket-replacements bucket)
                     :key #'discv5-node-id :test #'node-id=)
         (push node (k-bucket-replacements bucket))
         (when (> (length (k-bucket-replacements bucket)) +k-bucket-size+)
           (setf (k-bucket-replacements bucket)
                 (subseq (k-bucket-replacements bucket) 0 +k-bucket-size+))))
       nil))))

(defun routing-table-remove (table node-id)
  "Remove a node from the routing table."
  (let ((bucket (get-bucket table node-id)))
    (when (find node-id (k-bucket-nodes bucket) :key #'discv5-node-id :test #'node-id=)
      (setf (k-bucket-nodes bucket)
            (remove node-id (k-bucket-nodes bucket)
                    :key #'discv5-node-id
                    :test (lambda (a b) (node-id= a b))))
      (decf (routing-table-node-count table))
      ;; Promote from replacements if available
      (when (k-bucket-replacements bucket)
        (push (pop (k-bucket-replacements bucket)) (k-bucket-nodes bucket))
        (incf (routing-table-node-count table)))
      t)))

(defun routing-table-get (table node-id)
  "Get a node from the routing table."
  (let ((bucket (get-bucket table node-id)))
    (find node-id (k-bucket-nodes bucket) :key #'discv5-node-id :test #'node-id=)))

(defun routing-table-closest (table target-id count)
  "Find the COUNT closest nodes to TARGET-ID."
  (let ((all-nodes nil))
    (dotimes (i +num-buckets+)
      (dolist (node (k-bucket-nodes (aref (routing-table-buckets table) i)))
        (push node all-nodes)))
    (let ((sorted (sort all-nodes #'<
                        :key (lambda (n)
                               (node-distance (discv5-node-id n) target-id)))))
      (subseq sorted 0 (min count (length sorted))))))

(defun routing-table-random-nodes (table count)
  "Get COUNT random nodes from the routing table."
  (let ((all-nodes nil))
    (dotimes (i +num-buckets+)
      (dolist (node (k-bucket-nodes (aref (routing-table-buckets table) i)))
        (push node all-nodes)))
    (let ((shuffled (shuffle-list all-nodes)))
      (subseq shuffled 0 (min count (length shuffled))))))

(defun shuffle-list (list)
  "Randomly shuffle a list."
  (let ((vec (coerce list 'vector)))
    (loop for i from (1- (length vec)) downto 1
          do (rotatef (aref vec i) (aref vec (random (1+ i)))))
    (coerce vec 'list)))
