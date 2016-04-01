;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Merkle Trees
;;;
;;; Here we provide an implementation of Merkle Hash Trees as used in Google's
;;; Certificate Transparency and Revocation Transparency work.
;;;
;;; Cryptographic Components from RFC 6962 (Certificate Transparency)
;;; http://tools.ietf.org/html/rfc6962
;;;
;;; An implementation of Ben Laurie's "Verifiable Logs" as per
;;; http://sump2.links.org/files/CertificateTransparencyVersion2.1a.pdf
;;;   + Dense Merkle Hash Trees
;;;   + Merkle Audit Paths
;;;   + Merkle Consistency Proofs
;;;
;;; An implementation of Ben Laurie's "Verifiable Maps" as per
;;; http://sump2.links.org/files/RevocationTransparency.pdf
;;;   + Sparse Merkle Hash Trees
;;;
;;;
;;;  Copyright (C) 2016, Andy Bennett, Crown Copyright (Government Digital Service).
;;;
;;;  Permission is hereby granted, free of charge, to any person obtaining a
;;;  copy of this software and associated documentation files (the "Software"),
;;;  to deal in the Software without restriction, including without limitation
;;;  the rights to use, copy, modify, merge, publish, distribute, sublicense,
;;;  and/or sell copies of the Software, and to permit persons to whom the
;;;  Software is furnished to do so, subject to the following conditions:
;;;
;;;  The above copyright notice and this permission notice shall be included in
;;;  all copies or substantial portions of the Software.
;;;
;;;  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
;;;  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
;;;  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
;;;  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
;;;  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
;;;  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
;;;  DEALINGS IN THE SOFTWARE.
;;;
;;; Andy Bennett <andyjpb@digital.cabinet-office.gov.uk>, 2016/03/23
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(module merkle-tree
	(make-merkle-tree
	 merkle-tree?
	 merkle-tree-size
	 merkle-tree-levels
	 list->merkle-tree
	 ;merkle-tree-append!

	 merkle-tree-hash
	 dense-merkle-tree-hash
	 sparse-merkle-tree-hash
	 merkle-audit-path
	 merkle-consistency-proof
	 )

(import chicken scheme)

; Units - http://api.call-cc.org/doc/chicken/language
(use data-structures)

; Eggs - http://wiki.call-cc.org/chicken-projects/egg-index-4.html
(use dyn-vector message-digest)
(use numbers) ; The Sparse Merkle Tree needs some *really* big numbers!



;;; Supporting Maths

; logb(x) = (logd(x) / logd(b))
(define (log2 n)
  (/ (log n) (log 2)))

; Returns the largest power of 2 *smaller* than n which is
;  2^(floor(log2(n-1))) for n > 1.
;
; The largest power of 2 less than or equal to n is
;   2^(floor(log2(n))) for n > 0.
(define (pow2<n n)
 (assert (> n 1))
  (expt 2 (inexact->exact (floor (log2 (- n 1))))))


;;; Supporting ADTs

;;; Backing store for the data in a Merkle Hash Tree.
;;; For now we store the data in a dyn-vector but later we might want to store
;;; it somewhere more persistent.

; Makes a backing store that uses a dyn-vector.
(define (make-dyn-vector-backing-store) (make-dynvector 0 #f))

(define (dynvector->dyn-vector-backing-store dynvector) dynvector)

; Takes a backing store and returns the ref procedure for it.
; ref must be a procedure of two arguments: the handle for the store and the
; index of the element being referenced.
(define (backing-store-ref   store) (cut dynvector-ref store <>))

; Takes a backing store and returns a handle for the underlying data storage.
(define (backing-store-store store) store)

(define (backing-store-size  store) dynvector-length)

(define (backing-store-levels store)
  (lambda (store)
    (let ((size ((backing-store-size store) store)))
      (if (= 0 size)
	0
	(ceiling (log2 size))))))

; For a dense Merkle Tree stored in a dyn-vector every leaf is always present
(define (backing-store-count-leaves-in-range store)
  (lambda (start end)
    (assert (<= end ((backing-store-size store) store)))
    (assert (<= start end))
    (- end start)))



;;; Dense Merkle Hash Trees

;; ADTs

;; merkle-tree

; Allocates a new Merkle Hash Tree
(define (make-merkle-tree digest-primitive backing-store)
  `(merkle-tree
     (digest-primitive . ,(digest-primitive))
     (backing-store    . ,backing-store)))

(define (merkle-tree? tree)
  (and
    (list? tree)
    (= 3 (length tree))
    (eqv? 'merkle-tree (car tree))))

(define (merkle-tree-digest-primitive tree)
  (assert (merkle-tree? tree))
  (alist-ref 'digest-primitive (cdr tree)))

(define (merkle-tree-backing-store tree)
  (assert (merkle-tree? tree))
  (alist-ref 'backing-store (cdr tree)))

; Returns a procedure that can be used to resolve a leaf node by leaf index.
(define (merkle-tree-ref tree)
 (assert (merkle-tree? tree))
 (let ((store (merkle-tree-backing-store tree)))
  (backing-store-ref store)))

; Returns the number of leaf nodes in the tree
(define (merkle-tree-size tree)
  (assert (merkle-tree? tree))
  (let ((store (merkle-tree-backing-store tree)))
    ((backing-store-size store) store)))

; Returns the number of levels of interior nodes in the tree
(define (merkle-tree-levels tree)
  (assert (merkle-tree? tree))
  (let ((store (merkle-tree-backing-store tree)))
    ((backing-store-levels store) store)))

; Returns a procedure that can be used to count the number of non-default
; valued leafs between two leaf indexes
(define (merkle-tree-count-leaves-in-range tree)
  (assert (merkle-tree? tree))
  (let ((store (merkle-tree-backing-store tree)))
    (backing-store-count-leaves-in-range store)))

(define (dyn-vector->merkle-tree digest-primitive dynvector)
  (make-merkle-tree
    digest-primitive
    (dynvector->dyn-vector-backing-store dynvector)))

; Returns a new Merkle Hash Tree from an ordered list of data entries.
; Unlike in the RFC, we allow the user to specify the hashing algorithm to use.
(define (list->merkle-tree digest-primitive lst)
  (if (null? lst) ; list->dynvector doesn't work with lists of length 0.
    (dyn-vector->merkle-tree digest-primitive (make-dynvector 0 #f))
    (dyn-vector->merkle-tree digest-primitive (list->dynvector lst #f))))

; TODO: (define (merkle-tree-append! tree list) ...)




;; Operations

; "The hash of a list with one entry (also known as a leaf hash) is:
;
;  MTH({d(0)}) = SHA-256(0x00 || d(0))."
;   -- RFC6962, Section 2.1
(define (leaf-hash primitive leaf)
  (let ((digest        (initialize-message-digest primitive)))
    (assert (message-digest? digest))

    (message-digest-update-char-u8 digest #\nul) ; 0x0
    (message-digest-update-object  digest leaf)
    (finalize-message-digest digest 'blob)))


; "MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))"
;   -- RFC6962, Section 2.1
(define (interior-hash primitive left right)
  (let ((digest        (initialize-message-digest primitive)))
    (assert (message-digest? digest))

    (message-digest-update-char-u8 digest #\x1) ; 0x1
    (message-digest-update-object  digest left)
    (message-digest-update-object  digest right)
    (finalize-message-digest digest 'blob)))


; Calculates the Merkle Tree Hash for an ordered set of leaf nodes [start..end).
; "The output is a single 32-byte Merkle Tree Hash."
(define (dense-merkle-tree-hash tree #!optional (start 0) (end (merkle-tree-size tree)))
  (assert (<= start end))

  (let* ((primitive (merkle-tree-digest-primitive tree))
	 (ref       (merkle-tree-ref tree)))

    (cond
      ((= start end)
       ; "The hash of an empty list is the hash of an empty string"
       ;   -- RFC6962, Section 2.1
       (message-digest-string primitive "" 'blob))

      ((= 1 (- end start))
       ; "The hash of a list with one entry (also known as a leaf hash) is:
       ;
       ;  MTH({d(0)}) = SHA-256(0x00 || d(0))."
       ;   -- RFC6962, Section 2.1
       (leaf-hash primitive (ref start)))

      (else
	; "For n > 1, let k be the largest power of two smaller than n (i.e., k
	;  < n <= 2k).  The Merkle Tree Hash of an n-element list D[n] is then
	;  defined recursively as
	;
	;  MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
	;
	;  where || is concatenation and D[k1:k2] denotes the list {d(k1),
	;  d(k1+1),..., d(k2-1)} of length (k2 - k1).  (Note that the hash
	;  calculations for leaves and nodes differ.  This domain separation is
	;  required to give second preimage resistance.)"
	;   -- RFC6962, Section 2.1
	(let* ((n (- end start))
	       (k (pow2<n n)))
	  (interior-hash
	    primitive
	    (merkle-tree-hash tree start       (+ k start))
	    (merkle-tree-hash tree (+ k start) end)))))))


; Calculates the Merkle Tree Hash for a sparsely populated Merkle Tree of
; uncomputable size.
;
; level: The number of levels in the Merkle Tree. A Level of n gives a tree
;        with 2^n possible leaf nodes.
;
; The leaf nodes reachable from this part of the Merkle Tree are in the range
; [start..end).
;
; Returns a blob containing the hash.
;
; The hashing algorithm must be cryptographically strong as we do not support
; chains of entries in the leaf of the tree: each leaf can contain no more than
; one entry at a time and we expect that the hash algorithm returns a unique,
; non-colliding hash for each distinct data entry.
;
; Trees hashed with this procedure must always be "full", albeit with most of
; the leaves containing the default value.
(define (sparse-merkle-tree-hash tree #!optional (level (merkle-tree-levels tree)) (start 0) (end (expt 2 level)))

  (define (empty-tree-hash primitive default-leaf level)
    (if (= 0 level)
      (leaf-hash primitive default-leaf)
      (let ((h (empty-tree-hash primitive default-leaf (- level 1))))
	(interior-hash primitive h h))))

  (assert (<= start end))
  (assert (let ((size (merkle-tree-size tree)))
	    (if (= 0 size)
	      (<= end 1)
	      (<= end size))))
  (assert (let ((n (- end start))) ; check this part of the tree has a full complement of leaf nodes
	    (or (= 0 n)
		(let ((pow2 (log2 n)))
		  (= pow2 (ceiling pow2))))))

  (let* ((primitive      (merkle-tree-digest-primitive tree))
	 (ref            (merkle-tree-ref tree))
	 (leaves-between (merkle-tree-count-leaves-in-range tree)))

    (cond
      ((and
	 (= 0 level)
	 (= 0 (merkle-tree-size tree)))
       ; "The hash of an empty list is the hash of an empty string"
       ;   -- RFC6962, Section 2.1
       (message-digest-string primitive "" 'blob))

      ((= 1 (- end start))
       ; "The hash of a list with one entry (also known as a leaf hash) is:
       ;
       ;  MTH({d(0)}) = SHA-256(0x00 || d(0))."
       ;   -- RFC6962, Section 2.1
       (assert (= 0 level))
       (leaf-hash primitive (ref start)))

      ; If there are some non-default valued leaves in this part of the tree then we
      ; need to calculate the hash. Otherwise, we use the hash of an empty sub-tree.
      ((> (leaves-between start end) 0)
       (assert (> level 0))
       (let ((midpoint (inexact->exact (+ (/ (- end start) 2) start))))
	 (interior-hash
	   primitive
	   (sparse-merkle-tree-hash tree (- level 1) start    midpoint)
	   (sparse-merkle-tree-hash tree (- level 1) midpoint end))))

      (else
	(empty-tree-hash primitive #f level)))))


(define merkle-tree-hash dense-merkle-tree-hash)


; Merkle Audit Paths
; Calculates the Merkle Audit Path from the (m+1)th leaf of tree[start:end) to the root.
; RFC 6962 does not define any Merkle Audit Paths for trees with zero entries.
(define (merkle-audit-path m tree #!optional (start 0) (end (merkle-tree-size tree)))
  (assert (merkle-tree? tree))
  (assert (<  start (merkle-tree-size tree)))
  (assert (<= end   (merkle-tree-size tree)))
  (assert (< (+ m start) end)) ; < because m is a zero indexed leaf index.

  (let* ((n (- end start))
	 (k (if (> n 1) (pow2<n n))))
    (cond
      ((and
	 (= 0 m)
	 (= 1 n))
       ; "The path for the single leaf in a tree with a one-element input list
       ;  D[1] = {d(0)} is empty:
       ;
       ;  PATH(0, {d(0)}) = {}"
       ;   -- RFC6962, Section 2.1.1
       '())
      ; "For n > 1, let k be the largest power of two smaller than n.  The path
      ;  for the (m+1)th element d(m) in a list of n > m elements is then defined
      ;  recursively as
      ;
      ;  PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) for m < k; and
      ;
      ;  PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]) for m >= k,
      ;
      ;  where : is concatenation of lists and D[k1:k2] denotes the length (k2 -
      ;  k1) list {d(k1), d(k1+1),..., d(k2-1)} as before."
      ;   -- RFC6962, Section 2.1.1
      ;
      ; Rewriting the D[n] notation in terms of start:end slices gives us:
      ;
      ;  PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n]) for m < k; and
      ;  PATH(m, D[start:end]) = PATH(m, D[start:(+ start k)]) : MTH(D[(+ start k):end]) for m < k; and
      ;
      ;  PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k]) for m >= k,
      ;  PATH(m, D[start:end]) = PATH(m - k, D[(+ start k):end]) : MTH(D[start:(+ k start)]) for m >= k,
      ((and
	 (> n 1)
	 (< m k))
       (append
	 (merkle-audit-path m tree start (+ start k))
	 (list (merkle-tree-hash tree (+ start k) end))))
      ((and
	 (>  n 1)
	 (>= m k))
       (append
	 (merkle-audit-path (- m k) tree (+ start k) end)
	 (list (merkle-tree-hash tree start (+ start k)))))
      (else
	(abort
	  (conc "merkle-audit-path got incorrect parameters: "
		"tree: " tree ", m: " m ", start: " start ", end: " end
		", n: " n ", k: " k))))))


; Merkle Consistency Proofs
; Merkle consistency proofs prove the append-only property of the tree.  A
; Merkle consistency proof for a Merkle Tree Hash MTH(D[n]) and a previously
; advertised hash MTH(D[0:m]) of the first m leaves, m <= n, is the list of
; nodes in the Merkle Tree required to verify that the first m inputs D[0:m]
; are equal in both trees.
(define (merkle-consistency-proof m tree #!optional (start 0) (end (merkle-tree-size tree)) (original-m m))
  (assert (merkle-tree? tree))
  (assert (<  start (merkle-tree-size tree)))
  (assert (<= end   (merkle-tree-size tree)))
  (assert (<= (+ m start) end)) ; <= because m is an endpoint not a leaf index.

  (let* ((n (- end start))
	 (k (if (< m n) (pow2<n n))))
    (cond
      ((and
	 (= m n)
	 (= m original-m))
       ; "The subproof for m = n is empty if m is the value for which PROOF was
       ;  originally requested (meaning that the subtree Merkle Tree Hash
       ;  MTH(D[0:m]) is known):
       ;
       ;  SUBPROOF(m, D[m], true) = {}"
       ;   -- RFC6962, Section 2.1.2
       '())
      ((= m n)
       ; "The subproof for m = n is the Merkle Tree Hash committing inputs
       ;  D[0:m]; otherwise:
       ;
       ;  SUBPROOF(m, D[m], false) = {MTH(D[m])}"
       ;   -- RFC6962, Section 2.1.2
       ;
       ; Rewriting the D[m] notation in terms of start:end slices gives us:
       ;
       ;  SUBPROOF(m, D[m], false) = {MTH(D[m])}"
       ;  SUBPROOF(m, D[start:m], false) = {MTH(D[start:(+ start m)])}"
       (list (merkle-tree-hash tree start (+ start m))))
      ; "For m < n, let k be the largest power of two smaller than n.  The
      ;  subproof is then defined recursively."
      ;   -- RFC6962, Section 2.1.2
      ((and
	 (<  m n)
	 (<= m k))
       ; "If m <= k, the right subtree entries D[k:n] only exist in the current
       ;  tree.  We prove that the left subtree entries D[0:k] are consistent and
       ;  add a commitment to D[k:n]:
       ;
       ;  SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])"
       ;   -- RFC6962, Section 2.1.2
       ;
       ; Rewriting the D[n] notation in terms of start:end slices gives us:
       ;
       ;  SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])"
       ;  SUBPROOF(m, D[start:end], b) = SUBPROOF(m, D[start:(+ start k)], original-m) : MTH(D[(+ start k):end])"
       (append
	 (merkle-consistency-proof m tree start (+ start k) original-m)
	 (list (merkle-tree-hash tree (+ start k) end))))
      ((and
	 (< m n)
	 (> m k))
       ; "If m > k, the left subtree entries D[0:k] are identical in both trees.
       ;  We prove that the right subtree entries D[k:n] are consistent and add a
       ;  commitment to D[0:k].
       ;
       ;  SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])"
       ;   -- RFC6962, Section 2.1.2
       ;
       ; Rewriting the D[m] notation in terms of start:end slices gives us:
       ;
       ;  SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])"
       ;  SUBPROOF(m, D[start:end], b) = SUBPROOF(m - k, D[(+ start k):end], original-m) : MTH(D[start:(+ start k)])"
       (append
	 (merkle-consistency-proof (- m k) tree (+ start k) end original-m)
	 (list (merkle-tree-hash tree start (+ start k)))))
      (else
	(abort
	  (conc "merkle-consistency-proof got incorrect parameters: "
		"tree: " tree ", m: " m ", start: " start ", end: " end ", original-m: m"
		", n: " n ", k: " k))))))

)

