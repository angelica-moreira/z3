/**
 * @name Unsafe pointer cast
 * @description Detects reinterpret_cast and C-style casts between unrelated
 *              pointer types that may violate strict aliasing or cause
 *              alignment issues.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id z3/memory-safety/unsafe-cast
 * @tags security
 *       correctness
 *       memory-safety
 *       external/cwe/cwe-704
 */

import cpp

/**
 * Holds if the type is a char-like type (1 byte integral).
 */
predicate isCharLike(Type t) {
  t.getUnspecifiedType().getSize() = 1 and t.getUnspecifiedType() instanceof IntegralType
}

predicate relatedTypes(Type fromType, Type toType) {
  fromType = toType
  or
  // void* is always safe
  toType instanceof VoidType or fromType instanceof VoidType
  or
  // char*/unsigned char* for raw byte access is standard practice
  isCharLike(toType) or isCharLike(fromType)
  or
  // Base class / derived class relationship
  toType.(Class).getABaseClass+() = fromType.(Class)
  or
  fromType.(Class).getABaseClass+() = toType.(Class)
}

/**
 * A reinterpret_cast between unrelated pointer types.
 */
predicate unsafeReinterpretCast(ReinterpretCast cast) {
  exists(PointerType fromPtr, PointerType toPtr |
    fromPtr = cast.getExpr().getType().getUnspecifiedType() and
    toPtr = cast.getType().getUnspecifiedType() and
    not relatedTypes(fromPtr.getBaseType().getUnspecifiedType(),
                     toPtr.getBaseType().getUnspecifiedType())
  )
}

/**
 * A C-style cast between unrelated pointer types (not just const-casting).
 */
predicate unsafeCStyleCast(CStyleCast cast) {
  exists(PointerType fromPtr, PointerType toPtr |
    fromPtr = cast.getExpr().getType().getUnspecifiedType() and
    toPtr = cast.getType().getUnspecifiedType() and
    not relatedTypes(fromPtr.getBaseType().getUnspecifiedType(),
                     toPtr.getBaseType().getUnspecifiedType()) and
    // Exclude const_cast-equivalent casts
    fromPtr.getBaseType().getUnspecifiedType() != toPtr.getBaseType().getUnspecifiedType()
  )
}

/**
 * Cast from a pointer to an integer type that is too small to hold
 * a pointer value.
 */
predicate pointerToSmallInt(CStyleCast cast) {
  cast.getExpr().getType().getUnspecifiedType() instanceof PointerType and
  cast.getType().getUnspecifiedType() instanceof IntegralType and
  cast.getType().getSize() < cast.getExpr().getType().getSize()
}

from Expr cast, string msg
where
  (
    unsafeReinterpretCast(cast) and
    msg = "reinterpret_cast between unrelated pointer types: " +
          cast.(ReinterpretCast).getExpr().getType().toString() + " to " +
          cast.getType().toString()
  )
  or
  (
    unsafeCStyleCast(cast) and
    msg = "C-style cast between unrelated pointer types: " +
          cast.(CStyleCast).getExpr().getType().toString() + " to " +
          cast.getType().toString()
  )
  or
  (
    pointerToSmallInt(cast) and
    msg = "Pointer cast to integer type too small to hold a pointer value"
  )
select cast, msg
