;;;; findnode.lisp - FINDNODE/NODES handling
;;;; Part of cl-discv5-protocol

(in-package #:cl-discv5-protocol)

;;; FINDNODE query handling - Kademlia node lookup

(defstruct lookup-state
  "State for an in-progress node lookup."
  (target-id nil :type (or null node-id))
  (queried (make-hash-table :test 'equalp) :type hash-table)
  (pending nil :type list)
  (results nil :type list)
  (callback nil :type (or null function))
  (started-at 0 :type integer)
  (finished-p nil :type boolean))

(defun start-lookup (discovery target-id &key callback)
  "Start a lookup for nodes closest to TARGET-ID."
  (let* ((table (discovery-routing-table discovery))
         (closest (routing-table-closest table target-id +alpha+))
         (state (make-lookup-state
                 :target-id target-id
                 :callback callback
                 :started-at (get-universal-time))))
    ;; Initialize with closest known nodes
    (dolist (node closest)
      (lookup-add-result state node))
    ;; Query the initial set
    (lookup-query-next discovery state)
    state))

(defun lookup-add-result (state node)
  "Add a node to lookup results."
  (let ((node-id (discv5-node-id node)))
    (unless (gethash (node-id-bytes node-id) (lookup-state-queried state))
      (push node (lookup-state-results state)))))

(defun lookup-query-next (discovery state)
  "Query the next batch of nodes in the lookup."
  (let* ((target (lookup-state-target-id state))
         (results (lookup-state-results state))
         (queried (lookup-state-queried state))
         ;; Sort by distance and take unqueried nodes
         (sorted (sort (copy-list results) #'<
                       :key (lambda (n) (node-distance (discv5-node-id n) target))))
         (to-query (loop for node in sorted
                         for id = (discv5-node-id node)
                         for key = (node-id-bytes id)
                         unless (gethash key queried)
                         collect node
                         and do (setf (gethash key queried) t)
                         while (< (hash-table-count queried) +alpha+))))
    (if to-query
        (dolist (node to-query)
          (send-findnode discovery node
                         (list (log-distance target (discv5-node-id node)))))
        (lookup-finish state))))

(defun lookup-finish (state)
  "Complete the lookup."
  (setf (lookup-state-finished-p state) t)
  (when (lookup-state-callback state)
    (funcall (lookup-state-callback state)
             (lookup-state-results state))))

(defun handle-findnode (discovery src-node msg)
  "Handle an incoming FINDNODE request."
  (let* ((distances (findnode-message-distances msg))
         (table (discovery-routing-table discovery))
         (results nil))
    ;; Collect nodes at requested distances
    (dolist (dist distances)
      (let* ((bucket-idx (1- dist))
             (bucket (when (and (>= bucket-idx 0) (< bucket-idx +num-buckets+))
                       (aref (routing-table-buckets table) bucket-idx))))
        (when bucket
          (dolist (node (k-bucket-nodes bucket))
            (push (discv5-node-enr node) results)))))
    ;; Send NODES response
    (send-nodes discovery src-node
                (findnode-message-request-id msg)
                (subseq results 0 (min 16 (length results))))))

(defun handle-nodes (discovery src-node msg lookup-state)
  "Handle an incoming NODES response."
  (declare (ignore src-node))  ; Response validated by session
  (let ((enrs (nodes-message-enrs msg)))
    (dolist (enr enrs)
      (when (enr-verify enr)
        (let ((node (node-from-enr enr)))
          ;; Add to routing table
          (routing-table-add (discovery-routing-table discovery) node)
          ;; Add to lookup results if active
          (when lookup-state
            (lookup-add-result lookup-state node))))))
  ;; Continue lookup if active
  (when (and lookup-state (not (lookup-state-finished-p lookup-state)))
    (lookup-query-next discovery lookup-state)))

(defun send-findnode (discovery node distances)
  "Send a FINDNODE request to a node."
  (let ((msg (make-findnode distances)))
    (discovery-send discovery node
                    (encode-message +msg-findnode+ msg))))

(defun send-nodes (discovery node request-id enrs)
  "Send a NODES response to a node."
  (let ((msg (make-nodes request-id enrs)))
    (discovery-send discovery node
                    (encode-message +msg-nodes+ msg))))
