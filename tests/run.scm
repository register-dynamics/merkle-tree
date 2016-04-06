;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Merkle Tree Test Suite
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

;;; $ csi -ns tests/run.scm

(use merkle-tree)
(use test)

(use sha2)


;;; Test the Cryptographic Components from RFC 6962
(test-begin "Test the Cryptographic Components")


; Description of the reference tree that is used for the tests.
; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L254
; This defines the leaf nodes of a Reference Merkle Hash Tree with 8 leaf
; nodes. The internal nodes in the diagram below can be calculated with the
; helpers in tests/generate-tree.scm
;
;        5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328
;                                    /     \
;                                 /           \
;                              /                 \
;                           /                       \
;                        /                             \
;                    /                                     \
;                d37ee41                                 6b47aaf
;                  / \                                     / \
;                /     \                                 /     \
;              /         \                             /         \
;            /             \                         /             \
;          /                 \                     /                 \
;      fac5420             5f083f0             0ebc5d3             ca854ea
;        / \                 / \                 / \                 / \
;       /   \               /   \               /   \               /   \
;      /     \             /     \             /     \             /     \
;     /       \           /       \           /       \           /       \
; 6e340b9   96a296d   0298d12   07506a8   bc1a064   4271a26   b08693e   46f6ffa
;    |         |         |         |         |         |         |         |
;    |         |         |         |         |         |         |         |
;  #${}      #${00}   #${10}   #${2021}  #${3031}  #${40...} #${50...} #${60...}
; Leaf 0    Leaf 1    Leaf 2    Leaf 3    Leaf 4    Leaf 5    Leaf 5    Leaf 6
;
(define reference-leaves
  '(#${}
    #${00}
    #${10}
    #${2021}
    #${3031}
    #${40414243}
    #${5051525354555657}
    #${606162636465666768696a6b6c6d6e6f}))


;; Test the Dense Merkle Tree hashing algorithm
(test-group
 "Test the Dense Merkle Tree hashing algorithm"

; The hash of an empty tree is the hash of the empty string.
; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L249
(test
  "The hash of an empty tree is the hash of the empty string."
  #${e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}
  (dense-merkle-tree-hash
    (list->merkle-tree sha256-primitive '())))

; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L269
(let ((roots ; Incremental roots from building the reference tree from inputs leaf-by-leaf.
	'(#${6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d}
	  #${fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125}
	  #${aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77}
	  #${d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7}
	  #${4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4}
	  #${76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef}
	  #${ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c}
	  #${5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328})))

  (assert (= (length reference-leaves) (length roots)))

  (test-group
    "Incremental roots from building the reference tree from inputs leaf-by-leaf."
    (let loop ((n 1))
      (if (<= n (length reference-leaves))
	(let ((tree (list->merkle-tree sha256-primitive (take reference-leaves n))))
	  (test-group
	    (conc "Tree with " n " leaves")
	    (test
	      "Root hash"
	      (list-ref roots (- n 1))
	      (dense-merkle-tree-hash tree))
	    (let loop ((n 1))
	      (if (<= n (merkle-tree-size tree))
		(begin
		  (test ; Test each potential sub-tree has the correct root hash.
		    (conc "First " n " leaves")
		    (list-ref roots (- n 1))
		    (dense-merkle-tree-hash tree 0 n))
		  (loop (+ 1 n))))))
	  (loop (+ 1 n))))))))

; Test the Sparse Merkle Tree hashing algorithm
(test-group
  "Test the Sparse Merkle Tree hashing algorithm"

(test
  "The hash of an empty tree is the hash of the empty string."
  #${e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}
  (sparse-merkle-tree-hash
    (list->merkle-tree sha256-primitive '())))

; Test that the sparse algorithm matches the dense algorithm for full trees
(test-group
  "Test that the sparse algorithm matches the dense algorithm for full trees"
  (let loop ((n 1))
    (if (<= n (length reference-leaves))
      (let ((tree (list->merkle-tree sha256-primitive (take reference-leaves n))))
	(test
	  (conc "Tree with " n " leaves")
	  (dense-merkle-tree-hash  tree)
	  (sparse-merkle-tree-hash tree))
	(loop (* 2 n)))))))




;; Test the Merkle Audit Path
(test-group
 "Test the Merkle Audit Path algorithm"

; Test some Audit Paths in the reference tree
; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L456
(let ((tree (list->merkle-tree sha256-primitive reference-leaves))
      (paths ; '(leaf end expected-path)
	'(; (-1 0 ()) ; From merkle_tree_test.cc but doesn't seem to be valid.
	  (0 1 ())
	  (0 8 (#${96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7}
		#${5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e}
		#${6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4}))
	  (5 8 (#${bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b}
		#${ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0}
		#${d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7}))
	  (2 3 (#${fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125}))
	  (1 5 (#${6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d}
		#${5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e}
		#${bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b})))))

  (test
    "Checking Reference Tree Root Hash"
    #${5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328}
    (dense-merkle-tree-hash tree 0))

  (test-group
    "Test some Audit Paths in the reference tree."
    (map
      (lambda (path)
	(let ((leaf     (first  path))
	      (end      (second path))
	      (expected (third  path)))
	  (test
	    (conc "Leaf " leaf " of tree with end " end)
	    expected
	    (merkle-audit-path leaf tree 0 end))))
      paths))))


; Test the Merkle Consistency Proofs
(test-group
 "Test the Merkle Consistency Proof algorithm"

; Test some Proofs in the reference tree
; https://github.com/google/certificate-transparency/blob/master/cpp/merkletree/merkle_tree_test.cc#L530
(let ((tree (list->merkle-tree sha256-primitive reference-leaves))
      (proofs ; snapshot1 snapshot2 proof
	'((1 1 ())
	  (1 8 (#${96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7}
		#${5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e}
		#${6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4}))
	  (6 8 (#${0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a}
		#${ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0}
		#${d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7}))
	  (2 5 (#${5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e}
		#${bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b})))))

  (test
    "Checking Reference Tree Root Hash"
    #${5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328}
    (dense-merkle-tree-hash tree 0))

  (test-group
    "Test some Proofs in the reference tree."
    (map
      (lambda (proof)
	(let ((snapshot1 (first  proof))
	      (snapshot2 (second proof))
	      (expected  (third  proof)))
	  (test
	    (conc "Proving consistency between snapshot " snapshot1 " and snapshot " snapshot2)
	    expected
	    (merkle-consistency-proof snapshot1 tree 0 snapshot2))))
      proofs))))



(test-end)
(test-exit)

