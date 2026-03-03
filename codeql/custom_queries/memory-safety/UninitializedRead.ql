/**
 * @name Use of uninitialized memory
 * @description Detects reads from local variables or fields that may not
 *              have been initialized on all paths, a common source of
 *              non-deterministic bugs and potential security issues.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id z3/memory-safety/uninitialized-read
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-457
 */

import cpp

/**
 * A local variable of pointer or arithmetic type that has no initializer
 * and is read before any assignment on at least one path.
 */
predicate uninitializedLocalRead(VariableAccess va, LocalVariable v) {
  v = va.getTarget() and
  // No initializer in the declaration
  not exists(v.getInitializer()) and
  // It's a scalar, pointer, or small struct (not a class with a constructor)
  (
    v.getType().getUnspecifiedType() instanceof ArithmeticType or
    v.getType().getUnspecifiedType() instanceof PointerType or
    v.getType().getUnspecifiedType() instanceof Enum
  ) and
  // The access is a read (not an lvalue of assignment)
  not va = any(AssignExpr ae).getLValue() and
  not va = any(AddressOfExpr aoe).getOperand() and
  not va = any(CrementOperation co).getOperand() and
  // There's at least one path from function entry to this read with no assignment
  exists(BasicBlock entry, BasicBlock readBlock |
    entry = v.getFunction().getEntryPoint() and
    readBlock = va.getBasicBlock() and
    entry.getASuccessor*() = readBlock and
    not exists(AssignExpr assign |
      assign.getLValue().(VariableAccess).getTarget() = v and
      exists(BasicBlock assignBlock |
        assignBlock = assign.getBasicBlock() and
        entry.getASuccessor*() = assignBlock and
        assignBlock.getASuccessor*() = readBlock and
        assignBlock != readBlock
      )
    )
  )
}

/**
 * Memory allocated via malloc/calloc/realloc/alloca that is read
 * without initialization (calloc excluded as it zero-initializes).
 */
predicate uninitializedHeapRead(VariableAccess va, Variable v) {
  exists(FunctionCall alloc, AssignExpr assign |
    alloc.getTarget().hasGlobalName(["malloc", "realloc", "alloca"]) and
    assign.getLValue().(VariableAccess).getTarget() = v and
    assign.getRValue() = alloc and
    va.getTarget() = v and
    // Read via dereference or array access
    (
      va.getParent() instanceof PointerDereferenceExpr or
      va.getParent() instanceof ArrayExpr
    ) and
    // No memset/memcpy between allocation and read
    not exists(FunctionCall init |
      init.getTarget().hasGlobalName(["memset", "memcpy", "bzero"]) and
      init.getArgument(0).(VariableAccess).getTarget() = v and
      exists(BasicBlock allocBlock, BasicBlock initBlock, BasicBlock readBlock |
        allocBlock = alloc.getBasicBlock() and
        initBlock = init.getBasicBlock() and
        readBlock = va.getBasicBlock() and
        allocBlock.getASuccessor*() = initBlock and
        initBlock.getASuccessor*() = readBlock
      )
    )
  )
}

from VariableAccess va, Variable v, string msg
where
  (uninitializedLocalRead(va, v) and msg = "Local variable '" + v.getName() + "' may be read before initialization")
  or
  (uninitializedHeapRead(va, v) and msg = "Heap-allocated buffer '" + v.getName() + "' may be read without initialization")
select va, msg
