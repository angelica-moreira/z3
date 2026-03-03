/**
 * @name Null pointer dereference
 * @description Detects pointer dereferences that may be null, including
 *              unchecked return values from allocation and lookup functions.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @precision medium
 * @id z3/memory-safety/null-deref
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-476
 */

import cpp
import semmle.code.cpp.controlflow.Guards

/**
 * A function whose return value may be null and should be checked.
 */
class NullableFunction extends Function {
  NullableFunction() {
    // Standard allocation functions that return null on failure
    this.hasGlobalName(["malloc", "calloc", "realloc", "strdup", "strndup"])
    or
    // C++ functions that may return nullptr
    this.hasGlobalName(["getenv", "fopen", "tmpfile", "freopen"])
    or
    // dynamic_cast to pointer type can return nullptr
    this.getName() = "dynamic_cast"
  }
}

/**
 * A dereference of a pointer returned from a nullable function
 * without a null check.
 */
predicate uncheckedNullDeref(Expr deref, FunctionCall call, Variable v) {
  call.getTarget() instanceof NullableFunction and
  exists(AssignExpr assign |
    assign.getRValue() = call and
    assign.getLValue().(VariableAccess).getTarget() = v
  ) and
  (
    deref.(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = v
    or
    deref.(PointerFieldAccess).getQualifier().(VariableAccess).getTarget() = v
    or
    deref.(ArrayExpr).getArrayBase().(VariableAccess).getTarget() = v
  ) and
  call.getEnclosingFunction() = deref.getEnclosingFunction() and
  // No null check between allocation and dereference
  not exists(GuardCondition gc |
    gc.controls(deref.getBasicBlock(), _) and
    (
      gc.comparesEq(any(VariableAccess va | va.getTarget() = v), 0, _, _)
      or
      gc.comparesEq(any(VariableAccess va | va.getTarget() = v), any(Expr other), 0, _, _)
    )
  )
}

/**
 * Dereference of a pointer after an explicit comparison to null
 * on the same path (dereferenced in the null branch).
 */
predicate derefAfterNullCheck(Expr deref, Expr check, Variable v) {
  exists(EqualityOperation eq, NullValue nv |
    eq = check and
    eq.getAnOperand() = nv and
    eq.getAnOperand().(VariableAccess).getTarget() = v and
    // The dereference is in the "equal to null" branch
    eq.getBasicBlock().getASuccessor() = deref.getBasicBlock() and
    (
      deref.(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget() = v
      or
      deref.(PointerFieldAccess).getQualifier().(VariableAccess).getTarget() = v
    )
  )
}

from Expr deref, string msg, Expr related
where
  (
    exists(FunctionCall call, Variable v |
      uncheckedNullDeref(deref, call, v) and
      msg = "Pointer '" + v.getName() + "' dereferenced without null check after $@." and
      related = call
    )
  )
  or
  (
    exists(Expr check, Variable v |
      derefAfterNullCheck(deref, check, v) and
      msg = "Pointer '" + v.getName() + "' may be null when dereferenced; null check at $@." and
      related = check
    )
  )
select deref, msg, related, "this point"
