/**
 * @name Use after free
 * @description Detects uses of memory after it has been freed, including
 *              Z3's custom dealloc() and memory::deallocate() patterns.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id z3/memory-safety/use-after-free
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-416
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

/**
 * Holds if `use` dereferences a variable freed by `freeCall` within the
 * same basic block (same straight-line code sequence), with no intervening
 * reassignment. This is a high-confidence, low-cost pattern.
 */
predicate useAfterFreeInSameBlock(FreeCall freeCall, VariableAccess use, Variable v) {
  freeCall.getFreedExpr().(VariableAccess).getTarget() = v and
  use.getTarget() = v and
  freeCall.getBasicBlock() = use.getBasicBlock() and
  // Use comes after free (by location)
  freeCall.getLocation().getStartLine() < use.getLocation().getStartLine() and
  // The use is a dereference, not just a comparison
  (
    use.getParent() instanceof PointerDereferenceExpr or
    use.getParent() instanceof PointerFieldAccess or
    use.getParent() instanceof ArrayExpr
  ) and
  // No reassignment in between
  not exists(AssignExpr assign |
    assign.getLValue().(VariableAccess).getTarget() = v and
    assign.getLocation().getStartLine() > freeCall.getLocation().getStartLine() and
    assign.getLocation().getStartLine() < use.getLocation().getStartLine() and
    assign.getBasicBlock() = freeCall.getBasicBlock()
  )
}

/**
 * Same pattern but for delete/delete[].
 */
predicate useAfterDeleteInSameBlock(DeleteExpr del, VariableAccess use, Variable v) {
  del.getExpr().(VariableAccess).getTarget() = v and
  use.getTarget() = v and
  del.getBasicBlock() = use.getBasicBlock() and
  del.getLocation().getStartLine() < use.getLocation().getStartLine() and
  (
    use.getParent() instanceof PointerDereferenceExpr or
    use.getParent() instanceof PointerFieldAccess or
    use.getParent() instanceof ArrayExpr
  ) and
  not exists(AssignExpr assign |
    assign.getLValue().(VariableAccess).getTarget() = v and
    assign.getLocation().getStartLine() > del.getLocation().getStartLine() and
    assign.getLocation().getStartLine() < use.getLocation().getStartLine() and
    assign.getBasicBlock() = del.getBasicBlock()
  )
}

/**
 * Use in immediate successor block (one step after free's block).
 */
predicate useAfterFreeNextBlock(FreeCall freeCall, VariableAccess use, Variable v) {
  freeCall.getFreedExpr().(VariableAccess).getTarget() = v and
  use.getTarget() = v and
  freeCall.getBasicBlock().getASuccessor() = use.getBasicBlock() and
  (
    use.getParent() instanceof PointerDereferenceExpr or
    use.getParent() instanceof PointerFieldAccess or
    use.getParent() instanceof ArrayExpr
  ) and
  not exists(AssignExpr assign |
    assign.getLValue().(VariableAccess).getTarget() = v and
    (
      assign.getBasicBlock() = freeCall.getBasicBlock() and
      assign.getLocation().getStartLine() > freeCall.getLocation().getStartLine()
      or
      assign.getBasicBlock() = use.getBasicBlock() and
      assign.getLocation().getStartLine() < use.getLocation().getStartLine()
    )
  ) and
  not use.getParent() instanceof EqualityOperation
}

from Expr freeOp, VariableAccess use, Variable v
where
  useAfterFreeInSameBlock(freeOp, use, v)
  or
  useAfterDeleteInSameBlock(freeOp, use, v)
  or
  useAfterFreeNextBlock(freeOp, use, v)
select use, "Potential use-after-free: variable '" + v.getName() +
  "' is accessed here after being freed $@.", freeOp, "here"
