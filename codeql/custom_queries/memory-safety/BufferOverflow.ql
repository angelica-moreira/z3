/**
 * @name Buffer overflow from unchecked size
 * @description Detects array or buffer accesses where the index or size
 *              may exceed the allocated bounds, including unsafe memcpy/memmove usage.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision medium
 * @id z3/memory-safety/buffer-overflow
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-120
 *       external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

/**
 * A call to a memory-copy function (memcpy, memmove, memset, std::copy)
 * where the size argument may overflow the destination buffer.
 */
class UnsafeMemCopyCall extends FunctionCall {
  UnsafeMemCopyCall() {
    this.getTarget().hasGlobalName(["memcpy", "memmove", "memset", "wmemcpy", "wmemmove", "wmemset"])
  }

  Expr getDest() { result = this.getArgument(0) }
  Expr getSize() { result = this.getArgument(this.getNumberOfArguments() - 1) }
}

/**
 * An array access where the index is derived from user-controllable or
 * unchecked arithmetic.
 */
predicate uncheckedArrayAccess(ArrayExpr ae) {
  exists(Expr index | index = ae.getArrayOffset() |
    // Index from a subtraction that could underflow
    index instanceof SubExpr
    or
    // Index from a cast that could truncate
    exists(CStyleCast c | c = index | c.getExpr().getType().getSize() > c.getType().getSize())
  )
}

/**
 * A memcpy/memmove where the size comes from an arithmetic expression
 * that could overflow or is not bounded by the destination size.
 */
predicate unsafeMemCopy(UnsafeMemCopyCall call) {
  exists(Expr size | size = call.getSize() |
    // Size from subtraction (could underflow to large positive for unsigned)
    size instanceof SubExpr
    or
    // Size from multiplication (could overflow)
    size instanceof MulExpr
    or
    // Size from cast that narrows
    exists(CStyleCast c | c = size |
      c.getExpr().getType().getSize() > c.getType().getSize()
    )
  )
}

/**
 * Stack buffer accessed with a variable index that has no
 * upper-bound check visible in the same function.
 */
predicate stackBufferOverflow(ArrayExpr ae) {
  exists(Variable buf, Expr index |
    buf = ae.getArrayBase().(VariableAccess).getTarget() and
    index = ae.getArrayOffset() and
    buf.getType().(ArrayType).getArraySize() > 0 and
    index instanceof VariableAccess and
    not exists(GuardCondition gc |
      gc.controls(ae.getBasicBlock(), _) and
      gc.comparesLt(index, _, _, _, _)
    )
    and
    not exists(GuardCondition gc |
      gc.controls(ae.getBasicBlock(), _) and
      gc.comparesEq(index, _, _, _, _)
    )
  )
}

from Expr e, string msg
where
  (
    exists(UnsafeMemCopyCall call |
      unsafeMemCopy(call) and e = call and
      msg = "Memory copy with potentially unsafe size from arithmetic expression: " +
            call.getTarget().getName()
    )
  )
  or
  (
    exists(ArrayExpr ae |
      stackBufferOverflow(ae) and e = ae and
      msg = "Stack buffer access with unchecked variable index"
    )
  )
  or
  (
    exists(ArrayExpr ae |
      uncheckedArrayAccess(ae) and e = ae and
      msg = "Array access with index from potentially unsafe arithmetic"
    )
  )
select e, msg
