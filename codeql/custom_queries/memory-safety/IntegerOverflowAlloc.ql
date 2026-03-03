/**
 * @name Integer overflow in allocation size
 * @description Detects integer overflow in expressions used as sizes for
 *              memory allocation, which can lead to undersized buffers.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision medium
 * @id z3/memory-safety/integer-overflow-alloc
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-190
 *       external/cwe/cwe-680
 */

import cpp

/**
 * An allocation function call.
 */
class AllocCall extends FunctionCall {
  AllocCall() {
    this.getTarget().hasGlobalName(["malloc", "calloc", "realloc", "alloca"])
    or
    this.getTarget().hasQualifiedName("memory", "allocate")
    or
    this.getTarget().getName().matches("%alloc%")
  }

  /** The size argument. For calloc, the product of both args is the actual size. */
  Expr getSizeExpr() {
    if this.getTarget().hasGlobalName("calloc")
    then result = this.getArgument(0)  // nmemb (size is arg 1)
    else result = this.getArgument(this.getNumberOfArguments() - 1)
  }
}

/**
 * A `new` expression with an array size that involves arithmetic.
 */
class ArrayNewExpr extends NewArrayExpr {
  Expr getSizeExpr() { result = this.getExtent() }
}

/**
 * Holds if `sizeExpr` involves arithmetic that could overflow
 * for unsigned integer types.
 */
predicate unsafeArithmeticSize(Expr sizeExpr) {
  // Multiplication without overflow check
  (
    sizeExpr instanceof MulExpr and
    sizeExpr.getType().getUnspecifiedType().(IntegralType).isUnsigned()
  )
  or
  // Addition without overflow check
  (
    sizeExpr instanceof AddExpr and
    sizeExpr.getType().getUnspecifiedType().(IntegralType).isUnsigned()
  )
  or
  // Left shift (equivalent to multiply by power of 2)
  (
    sizeExpr instanceof LShiftExpr and
    sizeExpr.getType().getUnspecifiedType().(IntegralType).isUnsigned()
  )
  or
  // Nested: arithmetic in a sub-expression of the size
  exists(Expr child |
    child = sizeExpr.getAChild+() and
    unsafeArithmeticSize(child)
  )
}

/**
 * Holds if the size expression is a narrowing cast from a wider type.
 */
predicate narrowingCastSize(Expr sizeExpr) {
  exists(CStyleCast cast |
    cast = sizeExpr and
    cast.getExpr().getType().getSize() > cast.getType().getSize()
  )
}

from Expr alloc, Expr sizeExpr, string msg
where
  (
    exists(AllocCall call |
      alloc = call and
      sizeExpr = call.getSizeExpr() and
      unsafeArithmeticSize(sizeExpr) and
      msg = "Allocation size involves unchecked arithmetic that may overflow: " +
            call.getTarget().getName() + "()"
    )
  )
  or
  (
    exists(ArrayNewExpr newExpr |
      alloc = newExpr and
      sizeExpr = newExpr.getSizeExpr() and
      unsafeArithmeticSize(sizeExpr) and
      msg = "Array new[] size involves unchecked arithmetic that may overflow"
    )
  )
  or
  (
    exists(AllocCall call |
      alloc = call and
      sizeExpr = call.getSizeExpr() and
      narrowingCastSize(sizeExpr) and
      msg = "Allocation size is narrowed by a cast, potentially truncating: " +
            call.getTarget().getName() + "()"
    )
  )
select alloc, msg
