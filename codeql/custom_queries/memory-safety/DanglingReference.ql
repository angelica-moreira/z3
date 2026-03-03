/**
 * @name Dangling reference or pointer
 * @description Detects functions that return references or pointers to
 *              local variables or temporaries, leading to undefined behavior.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id z3/memory-safety/dangling-reference
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-562
 */

import cpp

/**
 * A return statement that returns a pointer or reference to a local variable.
 */
predicate returnsLocalAddress(ReturnStmt ret, Variable local) {
  exists(Expr returned |
    returned = ret.getExpr() and
    (
      // Return &localVar
      returned.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = local
      or
      // Return localArray (decays to pointer)
      returned.(VariableAccess).getTarget() = local and
      local.getType() instanceof ArrayType
      or
      // Return reference to local
      returned.(VariableAccess).getTarget() = local and
      ret.getEnclosingFunction().getType().(ReferenceType).getBaseType() = local.getType()
    ) and
    local instanceof LocalVariable and
    not local.isStatic()
  )
}

/**
 * A function that stores a pointer to a local variable in an output
 * parameter or member field (escaping the local's lifetime).
 */
predicate localAddressEscapes(AssignExpr assign, Variable local) {
  exists(AddressOfExpr addr |
    addr.getOperand().(VariableAccess).getTarget() = local and
    local instanceof LocalVariable and
    not local.isStatic() and
    assign.getRValue() = addr and
    (
      // Assigned to a dereferenced parameter
      assign.getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget().(Parameter).getIndex() >= 0
      or
      // Assigned to a field access (this->field = &local)
      assign.getLValue() instanceof FieldAccess
    )
  )
}

from Locatable loc, Variable local, string msg
where
  (
    exists(ReturnStmt ret |
      returnsLocalAddress(ret, local) and
      loc = ret and
      msg = "Returns address of local variable '" + local.getName() +
            "', which will be invalid after the function returns"
    )
  )
  or
  (
    exists(AssignExpr assign |
      localAddressEscapes(assign, local) and
      loc = assign and
      msg = "Address of local variable '" + local.getName() +
            "' escapes its scope through assignment to output parameter or field"
    )
  )
select loc, msg
