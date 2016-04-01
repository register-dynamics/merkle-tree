;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Merkle Trees
;;;
;;; Helpers to generate a small Merkle tree for testing and verification.
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
;;; Andy Bennett <andyjpb@digital.cabinet-office.gov.uk>, 2016/03
;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; $ csi -ns tests/generate-tree.scm

(load "merkle-tree")
(import merkle-tree)

(use sha2 message-digest extras)


; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L254
(define leaves
  '(#${}
    #${00}
    #${10}
    #${2021}
    #${3031}
    #${40414243}
    #${5051525354555657}
    #${606162636465666768696a6b6c6d6e6f}))

(define (leaf-hash primitive leaf)
  (let ((digest (initialize-message-digest primitive)))
    (message-digest-update-char-u8 digest #\nul) ; 0x0
    (message-digest-update-object  digest leaf)
    (finalize-message-digest digest 'blob)))

(define (interior-hash primitive left right)
  (let ((digest (initialize-message-digest primitive)))
    (message-digest-update-char-u8 digest #\x1) ; 0x1
    (message-digest-update-blob    digest left)
    (message-digest-update-blob    digest right)
    (finalize-message-digest digest 'blob)))

(let* ((primitive (sha256-primitive))
       (level-0 (map (lambda (n)
		       (leaf-hash primitive
				  (list-ref leaves n)))
		     (iota 8)))
       (level-1 (map (lambda (n)
		       (interior-hash primitive
				      (list-ref level-0 n)
				      (list-ref level-0 (+ 1 n))))
		     (iota 4 0 2)))
       (level-2 (map (lambda (n)
		       (interior-hash primitive
				      (list-ref level-1 n)
				      (list-ref level-1 (+ 1 n))))
		     (iota 2 0 2)))
       (level-3 (map (lambda (n)
		       (interior-hash primitive
				      (list-ref level-2 n)
				      (list-ref level-2 (+ 1 n))))
		     (iota 1 0 2))))
  (pp "Level 0") (pp level-0)
  (pp "Level 1") (pp level-1)
  (pp "Level 2") (pp level-2)
  (pp "Level 3") (pp level-3))

