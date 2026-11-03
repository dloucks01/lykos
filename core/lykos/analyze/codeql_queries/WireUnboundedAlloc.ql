/**
 * @name Wire-controlled value reaches an allocation size or array index (interprocedural)
 * @description A network-read value flows to a malloc/realloc size, a memcpy length, or an array
 *              index without a bounding guard -- the ClearCodec (dims->size), planar (len) and
 *              order/index classes. Interprocedural taint tracking (CodeQL), so a value read in one
 *              function and used in a callee is caught.
 * @kind path-problem
 * @problem.severity warning
 * @id lykos/wire-unbounded-alloc
 * @tags security external/cwe/cwe-190 external/cwe/cwe-787
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.controlflow.Guards
import WireAllocFlow::PathGraph

predicate isWireSource(DataFlow::Node n) {
  exists(FunctionCall c |
    c.getTarget().getName().matches("Stream_Read\\_%") or
    c.getTarget().getName() = "audio_format_read" |
    n.asDefiningArgument() = c.getArgument(1)
  )
}

/** An allocation-size / copy-length / array-index position. */
predicate isSizeSink(DataFlow::Node n) {
  exists(FunctionCall c | c.getTarget().getName().regexpMatch("malloc|realloc|calloc|alloca") |
    n.asExpr() = c.getAnArgument())
  or
  exists(FunctionCall c | c.getTarget().getName().regexpMatch("memcpy|memmove|memset") |
    n.asExpr() = c.getArgument(2))
  or
  exists(ArrayExpr a | n.asExpr() = a.getArrayOffset())
}

module WireAllocConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { isWireSource(n) }
  predicate isSink(DataFlow::Node n) { isSizeSink(n) }
  /** a guard comparing the value stops the flow (approximate: any relational barrier). */
  predicate isBarrier(DataFlow::Node n) {
    exists(GuardCondition g | g.controls(n.asExpr().getBasicBlock(), _))
  }
}

module WireAllocFlow = TaintTracking::Global<WireAllocConfig>;

from WireAllocFlow::PathNode source, WireAllocFlow::PathNode sink
where WireAllocFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Wire-controlled value reaches an allocation size / copy length / array index here with no bound (CWE-190/787)."
