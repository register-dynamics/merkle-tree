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
	 merkle-tree-update
	 merkle-tree-append

	 merkle-tree-hash
	 dense-merkle-tree-hash
	 sparse-merkle-tree-hash
	 merkle-audit-path
	 merkle-consistency-proof

	 make-dense-backing-store
	 make-sparse-backing-store
	 open-sqlite-backing-store
	 create-sqlite-backing-store
	 )

(import chicken scheme)

; Units - http://api.call-cc.org/doc/chicken/language
(use data-structures srfi-1 srfi-4)

; Eggs - http://wiki.call-cc.org/chicken-projects/egg-index-4.html
(use dyn-vector message-digest)
(use numbers) ; The Sparse Merkle Tree needs some *really* big numbers!



;;; Supporting Maths

; Returns _log2(n)_
; (floor-log2 8) -> 3
; (floor-log2 9) -> 3
(define (floor-log2 n)
  (sub1 (integer-length n)))

; Returns the largest power of 2 *smaller* than n which is
;  2^(floor(log2(n-1))) for n > 1.
;
; The largest power of 2 less than or equal to n is
;   2^(floor(log2(n))) for n > 0.
(define (pow2<n n)
  (arithmetic-shift 1 (floor-log2 (- n 1))))

; Returns the exponent of the smallest power of 2 that is >= n.
; (log2-pow2>=n 7) -> 3
; (log2-pow2>=n 8) -> 3
; (log2-pow2>=n 9) -> 4
(define (log2-pow2>=n n)
  (+ 1 (floor-log2 (- n 1))))

; Says whether n is a power of 2 (or 0).
(define (pow2? n)
  (= (arithmetic-shift 1 (sub1 (integer-length n))) n))



;;; Supporting ADTs

;;; Backing store for the data in a Merkle Hash Tree.

(define (make-backing-store #!key store ref update size levels count-leaves-in-range default-leaf)
  `(backing-store
     ,store
     ,ref
     ,size
     ,levels
     ,count-leaves-in-range
     ,default-leaf
     ,update))

(define (backing-store? store)
 (and
  (list? store)
  (= 8 (length store))
  (eqv? 'backing-store (car store))))

; Takes a backing store and returns the ref procedure for it.
; ref must be a procedure of two arguments: the handle for the store and the
; index of the element being referenced.
(define backing-store-ref   third)

; Takes a backing store and returns a handle for the underlying data storage.
(define backing-store-store second)

; Returns the actual number of leaves in the backing store, not the size of the
; allocated storage.
(define (backing-store-size store)
  (assert (backing-store? store))
  ((fourth store)))

; Returns the number of levels of hash nodes in the tree. For dense trees this
; is related to the current size of the tree. For sparse trees it will be
; specified when the tree is declared.
(define (backing-store-levels store)
  (assert (backing-store? store))
  ((fifth store)))

; Returns a procedure of two arguments that, when called, will return the
; number of leaves between the two leaf indexes specifiec for the appropriate
; backing store.
(define backing-store-count-leaves-in-range sixth)

; Returns the default leaf value. Only really important for a sparse tree.
(define backing-store-default-leaf seventh)

; Takes a backing store and returns a procedure to do a functional update on
; it.
; The procedure must be a procedure of three arguments: leaf index, value and
; handle. The procedure must return a new backing store that is equivalent to
; the original backing store with the requested modification.
(define backing-store-update eighth)


;;; A quick and dirty backing store that uses a dyn-vector.
;;; For now we store the data in a dyn-vector but later we might want to store
;;; it somewhere more persistent.

; Makes a backing store that uses a dyn-vector.
(define (make-dyn-vector-backing-store #!optional (vector (make-dynvector 0 #f)))
  (make-backing-store
    store:  vector
    ref:    (cut dynvector-ref    vector <>)
    update: (lambda (n value)
	      ; This is inefficient as dynvector does not support functional updates!
	      (make-dyn-vector-backing-store
		(let ((new (dynvector-copy vector)))
		  (dynvector-set!
		    new
		    n value)
		  new)))
    size:   (cut dynvector-length vector)
    levels: (lambda ()
	      (log2-pow2>=n (dynvector-length vector)))
    count-leaves-in-range: (lambda (start end)
			     ; For a dense Merkle Tree stored in a dyn-vector every leaf is always present
			     (assert (<= end   (dynvector-length vector)))
			     (assert (<= start end))
			     (- end start))
    default-leaf: #f))

(define (dynvector->dyn-vector-backing-store dynvector)
  (make-dyn-vector-backing-store dynvector))

(define make-dense-backing-store make-dyn-vector-backing-store)


; Makes a backing store that stores the non-default leaves in an a-list mapping
; leaf indexes to values.
(define (make-sparse-backing-store levels #!optional (default #f) (lst '()))

  (define (blob->number blob)
    (let loop ((int   0)
	       (bytes  (u8vector->list
			 (blob->u8vector/shared blob))))
      (if (null? bytes)
	int
	(loop
	  (bitwise-ior
	    (arithmetic-shift int 8)
	    (car bytes))
	  (cdr bytes)))))

  (define (->number n)
    (cond
      ((number? n) n)
      ((blob? n)  (blob->number n))
      (else
	(abort (conc n " cannot be used by sparse-backing-store.")))))

  (make-backing-store
    store:  lst
    ref:    (let* ((max (expt 2 levels))
		   (ref (lambda (n)
			   (assert (>= n 0))
			   (assert (< n max))
			   (alist-ref n lst = default))))
	      (lambda (n)
	       (ref (->number n))))
    update: (let* ((max (expt 2 levels))
		   (update (lambda (n value)
			     (assert (>= n 0))
			     (assert (< n max))
			     (alist-update n value lst =))))
	      (lambda (n value)
		(make-sparse-backing-store
		  levels
		  default
		  (update (->number n) value))))
    size:   (constantly (expt 2 levels))
    levels: (constantly levels)
    count-leaves-in-range: (lambda (start end)
			     (fold ; naive and stupid linear search
			       (lambda (v s)
				 (assert (pair? v))
				 (if (and (>= (car v) start) (< (car v) end))
				   (+ 1 s)
				   s))
			       0
			       lst))
    default-leaf: default))


(use sql-de-lite pool)
; This backing-store persists both Dense and Sparse Merkle Trees to an SQLite
; Database.
;
; This requires an SQLite database with the following tables:
;
;   Metadata:
;     + leaves         : [ id leaf version ] content
;     + tree-versions  : [ id version ] leaf-count
;     + tree-info      : [ id ] sparse? default-leaf  ; these are required data
;     + tree-advice    : [ id ] name digest-algorithm ; these are advisory data
;     + store-info     : [ store ] max-id ; needed to avoid creation races and reusing identifiers
;
;   Contents:
;     + [ digest-primitive hash ] content
;
;
; db-pool: A pool of database connections to use for accessing the SQLite
;          database. This pool should be created with the 'pool' egg.
;
; sparse?: #t for a Sparse Merkle Tree, #f for a Dense Merkle Tree
;
; name   : A symbolic name for the tree. Optional but if specified, it must be
;          unique across the store.
;
; digest-algorithm : A human readable name for the digest algorithm used. This
;                    is optional and not used in the logic.
;
;

; Creates the required schema in an SQLite Database.
; Assumes that the table names it wants are not already in-use.
;
(define (initialise-sqlite-backing-store db-pool)
  (call-with-value-from-pool
    db-pool
    (lambda (db)
      (with-transaction
	db
	(lambda ()
	  (for-each
	    (lambda (q)
	      (exec
		(sql db q)))
	    '("CREATE  TABLE \"main\".\"store-info\" (\"store\" TEXT PRIMARY KEY  NOT NULL , \"next-id\" INTEGER);"
	      "INSERT INTO \"main\".\"store-info\" (\"store\",\"next-id\") VALUES (\"this\", 0);"
	      "CREATE  TABLE \"main\".\"tree-info\" (\"id\" INTEGER PRIMARY KEY  NOT NULL , \"sparse?\" INTEGER, \"levels\" INTEGER, \"default-leaf\" BLOB);"
	      "CREATE  TABLE \"main\".\"tree-advice\" (\"id\" INTEGER PRIMARY KEY  NOT NULL , \"name\" TEXT UNIQUE , \"digest-algorithm\" TEXT);"
	      "CREATE  TABLE \"main\".\"tree-versions\" (\"id\" INTEGER NOT NULL , \"version\" INTEGER NOT NULL , \"leaf-count\" INTEGER NOT NULL , PRIMARY KEY (\"id\", \"version\"));"
	      "CREATE  TABLE \"main\".\"leaves\" (\"id\" INTEGER NOT NULL , \"leaf\" INTEGER NOT NULL , \"version\" INTEGER NOT NULL , \"content\" BLOB, PRIMARY KEY (\"id\", \"leaf\", \"version\"));"))
	  #t)))))


; Creates a Merkle Tree that persists itself to an SQLite database.
; This allocates a new merkle-tree in a pre-existing SQLite database and
; returns the ID of the new Merkle Tree.
;
(define (create-sqlite-backing-store db-pool sparse? #!key name digest-algorithm default-leaf levels)

  (if sparse?
    (assert levels
	    "Sparse Merkle Trees must have a number of levels specified!"))

  (if (not sparse?)
    (assert (not levels)
	    "Dense Merkle Trees must not have a number of levels specified!"))

  (if (not sparse?)
    (assert (not default-leaf)
	    "Dense Merkle Trees must not have a default-leaf specified!"))

  (call-with-value-from-pool
    db-pool
    (lambda (db)

      (with-transaction
	db
	(lambda ()

	  (define (allocate-id)
	    (let ((id (car (exec (sql db "SELECT \"next-id\" FROM \"store-info\" WHERE \"store\" = \"this\";")))))
	      (assert
		(= 1
		   (exec (sql db "UPDATE \"store-info\" SET \"next-id\" = (?1 + 1) WHERE \"store\" = \"this\" AND \"next-id\" = ?1;") id)))
	      id))

	  (define (save-info id sparse? default-leaf)
	    (exec
	      (sql db "INSERT INTO \"tree-info\" (\"id\", \"sparse?\", \"levels\", \"default-leaf\") VALUES (?1, ?2, ?3, ?4);")
	      id                      ; id
	      (if sparse? 1 '())      ; sparse?
	      (if sparse? levels '()) ; levels
	      (or default-leaf '()))) ; default-leaf

	  (define (save-advice id name digest-algorithm)
	    (exec
	      (sql db "INSERT INTO \"tree-advice\" (\"id\", \"name\", \"digest-algorithm\") VALUES (?1, ?2, ?3);")
	      id                           ; id
	      (or name '())                ; name
	      (if digest-algorithm         ; digest-algorithm
		(->string digest-algorithm)
		'())))

	  (define (create-initial-version id)
	    (exec
	      (sql db "INSERT INTO \"tree-versions\" (\"id\", \"version\", \"leaf-count\") VALUES (?1, ?2, ?3);")
	      id 0 0))


	  ; Allocate a unique ID for this tree.
	  ; Save the info and advice about the tree.
	  (let ((id (allocate-id)))
	    (save-info              id sparse? default-leaf)
	    (save-advice            id name    digest-algorithm)
	    (create-initial-version id)
	    id))))))

; Opens a pre-existing backing store that persists itself to an SQLite
; database.
; This finds an existing merkle-tree in a pre-existing SQLite database and
; returns a backing-store object.
;
(define (open-sqlite-backing-store db-pool id version)

  (define (db-bool x)
    (cond
      ((null? x) #f)
      ((= 1 x)   #t)
      (else
	(abort (conc "Found " x " in database but expected '() or 1.")))))

  (define (db-optional x)
    (if (null? x)
      #f
      x))

  (call-with-value-from-pool
    db-pool
    (lambda (db)

      (define (read-tree-info id)
	(exec
	  (sql db "SELECT \"id\", \"sparse?\", \"levels\", \"default-leaf\" FROM \"tree-info\" WHERE \"id\" = ?1;")
	  id))

      (define (read-version-info id version)
	(exec
	  (sql db "SELECT \"id\", \"version\", \"leaf-count\" FROM \"tree-versions\" WHERE \"id\" = ?1 AND \"version\" = ?2;")
	  id version))


      (let ((tree-info    (read-tree-info id)))
	(if (null? tree-info)
	  (abort (conc "Could not find tree with id " id))
	  (let* ((id*          (first  tree-info))
		 (sparse?      (db-bool     (second tree-info)))
		 (levels       (db-optional (third  tree-info)))
		 (default-leaf (db-optional (fourth tree-info)))
		 (version-info (read-version-info id version)))
	    (if (null? version-info)
	      (abort (conc "Tree with id " id " does not exist at version " version))
	      (let ((leaf-count   (third version-info)))

		(assert (equal? id id*))

		(make-sqlite-backing-store db-pool id version sparse? leaf-count levels default-leaf)))))))))

; Makes a backing store that persists itself to an SQLite database.
; This requires a pre-allocated merkle-tree in a pre-existing SQLite database
; and returns a backing-store object.
;
(define (make-sqlite-backing-store db-pool id version sparse? leaf-count levels default-leaf)

  (define (SELECT-leaf db id n version)
    (exec
      (sql db "SELECT \"version\", \"content\" FROM \"leaves\" WHERE \"id\" = ?1 AND \"leaf\" = ?2 AND \"version\" <= ?3;")
      id n version))

   (use extras)
  (define (ref db version n)
   (pp (conc "getting n " n " @ version " version))
    (let ((value (SELECT-leaf db id n version)))
      (if (null? value)
	default-leaf
	(second value))))

  ;(define l '(0 2 4 6 8 10 12 14 16))
  ;(define l '(0 1 3 5 7 9 11 13 15))
  ;(define l '(0 16 17 18 19 20 21 22 23))
  (define l '(0 1 2 3 4 5 6 7 8))

  (define (next-version db)
    ;(let ((next-version (add1 version)))
    (let ((next-version (list-ref l (add1 (list-index (cut = version <>) l)))))
      (assert (null? (exec ; This is just open-sqlite-backing-store's read-version-info.
		       (sql db "SELECT \"id\", \"version\", \"leaf-count\" FROM \"tree-versions\" WHERE \"id\" = ?1 AND \"version\" = ?2;")
		       id next-version))
	      (conc "next-version: Tree " id " already exists at version " next-version))
      next-version))

  (make-backing-store
    store:  `(,db-pool ,id ,version)
    ref:    (lambda (n)
	      (call-with-value-from-pool
		db-pool
		(lambda (db)
		  (ref db version n))))
    update: (lambda (n value)
	      (call-with-value-from-pool
		db-pool
		(lambda (db)
		  ; number->blob if argument is a number (opposite of sparse-backing-store)
		  (with-transaction
		    db
		    (lambda ()
		      (let* ((new-version    (next-version db))
			     ; Is this a new leaf or a mutation of an existing one?
			     ; We use this to maintain the leaf count metadata.
			     (new-leaf?      (null? (SELECT-leaf db id n version)))
			     (new-leaf-count (+ (if new-leaf? 1 0) leaf-count)))
			; Fix implied values for this leaf in other versions.
			(let* ((next-version (exec ; exec only gets the first row of the result set which is exactly what we want.
					       (sql db "SELECT \"id\", \"version\" FROM \"tree-versions\" WHERE \"id\" = ?1 AND \"version\" > ?2 ORDER BY \"version\";")
					       id version)))
			 (pp (conc "On version " version ", making new-version " new-version " and found potential next-version " next-version " for leaf " n))
			  (pp (conc "next-version " next-version))
			  (if (not (null? next-version)) ; There exists a tree with a higher version number...
			    (let* ((next-version (second next-version))
				   (_ (pp "looking up next-value"))
				   (next-value   (SELECT-leaf db id n next-version)))
			      (if (and (not (null? next-value)) (not (= next-version (first next-value)))) ; ...but no explicit value for this particular leaf.
			       (begin
				(pp (conc "got next-value " next-value))
				(pp (conc "inserting version " version " of " n " as next-version " next-version))
				(exec
				  (sql db "INSERT INTO \"leaves\" (\"id\", \"leaf\", \"version\", \"content\") VALUES (?1, ?2, ?3, ?4);")
				  id n next-version (ref db version n)))))))
			; Insert the new value for this leaf.
			(exec
			  (sql db "INSERT INTO \"leaves\" (\"id\", \"leaf\", \"version\", \"content\") VALUES (?1, ?2, ?3, ?4);")
			  id n new-version value)
			; Record this version of the tree.
			(assert
			  (= 1
			     (exec
			       (sql db "INSERT INTO \"tree-versions\" (\"id\", \"version\", \"leaf-count\") VALUES (?1, ?2, ?3);")
			       id new-version (+ (if new-leaf? 1 0) leaf-count))))
			(make-sqlite-backing-store
			  db-pool id new-version sparse? new-leaf-count levels default-leaf)))))))
    size:   (if sparse?
	      (constantly (expt 2 levels))
	      (constantly leaf-count))
    levels: (if sparse?
	      (constantly levels)
	      (lambda ()
		(log2-pow2>=n leaf-count)))
    count-leaves-in-range: (lambda (start end) ; Leaves in the range [start..end) that are populated with a value.
			     (assert (<= start end))
			     (if sparse?
			       (call-with-value-from-pool
				 db-pool
				 (lambda (db)
				   (first
				     (exec
				       (sql db "SELECT COUNT(DISTINCT \"leaf\") FROM \"leaves\" WHERE \"id\" = ?1 AND \"version\" <= ?2 AND \"leaf\" >= ?3 AND \"leaf\" < ?4;")
				       id version start end))))
			       (begin
				 ; For a dense Merkle Tree every leaf is always present.
				 (assert (<= end leaf-count))
				 (- end start))))
    default-leaf: default-leaf))




;;; Dense Merkle Hash Trees

;; ADTs

;; merkle-tree

; Allocates a new Merkle Hash Tree
(define (make-merkle-tree digest-primitive backing-store)
  (assert (backing-store? backing-store))

  `(merkle-tree
     (digest-primitive . ,digest-primitive)
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
    (backing-store-size store)))

; Returns the number of levels of interior nodes in the tree
(define (merkle-tree-levels tree)
  (assert (merkle-tree? tree))
  (let ((store (merkle-tree-backing-store tree)))
    (backing-store-levels store)))

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

(define (merkle-tree-update leaf-number value tree)
  (assert (merkle-tree? tree))
  (let ((store (merkle-tree-backing-store tree)))
    (make-merkle-tree
      (merkle-tree-digest-primitive tree)
      ((backing-store-update store) leaf-number value))))

; This assumes that we are filling a tree up from left to right.
; Work out the size of the tree then map over the list and update the elements
; into the subsequent slots.
; This naive implementation will cause (- (length lst) 1) redundant merkle-tree
; objects to be allocated.
(define (merkle-tree-append tree lst)
  (assert (merkle-tree? tree))
  (fold
    merkle-tree-update ; n value tree
    tree
    (iota (length lst) (merkle-tree-size tree))
    lst))



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

  (let* ((primitive ((merkle-tree-digest-primitive tree)))
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
	    (dense-merkle-tree-hash tree start       (+ k start))
	    (dense-merkle-tree-hash tree (+ k start) end)))))))


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
  (assert (pow2? (- end start))) ; check this part of the tree has a full complement of leaf nodes

  (let* ((primitive      ((merkle-tree-digest-primitive tree)))
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
	(empty-tree-hash
	  primitive
	  (backing-store-default-leaf
	    (merkle-tree-backing-store tree))
	  level)))))


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

