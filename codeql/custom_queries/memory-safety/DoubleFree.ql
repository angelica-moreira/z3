/**
 * @name Double free
 * @description Detects cases where the same pointer is freed twice,
 *              including via Z3's dealloc() and memory::deallocate().
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision medium
 * @id z3/memory-safety/double-free
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-415
 */

import cpp

/** A call that frees memory. */
class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasGlobalName(["free", "operator delete", "operator delete[]"])
    or
    this.getTarget().hasQualifiedName("memory", "deallocate")
    or
    this.getTarget().getName() = "dealloc"
  }

  Expr getFreedExpr() { result = this.getArgument(0) }
}

/** A delete/delete[] expression. */
class DeleteOp extends Expr {
  Expr freed;

  DeleteOp() {
    this instanceof DeleteExpr and freed = this.(DeleteExpr).getExpr()
    or
    this instanceof DeleteArrayExpr and freed = this.(DeleteArrayExpr).getExpr()
  }

  Expr getFreedExpr() { result = freed }
}

/**
 * Holds if the same variable is freed at two different program points
 * with no reassignment in between.
 */
predicate doubleFreePattern(Expr firstFree, Expr secondFree, Variable v) {
  exists(Expr freed1, Expr freed2 |
    (freed1 = firstFree.(FreeCall).getFreedExpr() or freed1 = firstFree.(DeleteOp).getFreedExpr()) and
    (freed2 = secondFree.(FreeCall).getFreedExpr() or freed2 = secondFree.(DeleteOp).getFreedExpr()) and
    freed1.(VariableAccess).getTarget() = v and
    freed2.(VariableAccess).getTarget() = v and
    firstFree != secondFree and
    firstFree.getEnclosingFunction() = secondFree.getEnclosingFunction() and
    // First free dominates second free (sequential flow)
    firstFree.getBasicBlock().getASuccessor+() = secondFree.getBasicBlock() and
    // No reassignment of v between the two frees
    not exists(AssignExpr assign |
      assign.getLValue().(VariableAccess).getTarget() = v and
      exists(BasicBlock ab |
        ab = assign.getBasicBlock() and
        firstFree.getBasicBlock().getASuccessor+() = ab and
        ab.getASuccessor+() = secondFree.getBasicBlock()
      )
    )
  )
}

from Expr firstFree, Expr secondFree, Variable v
where doubleFreePattern(firstFree, secondFree, v)
select secondFree, "Potential double free: variable '" + v.getName() +
  "' was already freed $@.", firstFree, "here"
