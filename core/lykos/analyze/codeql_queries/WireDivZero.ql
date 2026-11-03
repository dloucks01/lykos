/**
 * @name Wire-controlled value reaches a divisor (interprocedural)
 * @description A value read from the network (a WinPR Stream_Read_* / audio_format_read field) flows
 *              interprocedurally to a division or modulo with no intervening zero-check. This is the
 *              class behind the confirmed FreeRDP DSP divide-by-zero (nBlockAlign flows from
 *              audio_format_read through a struct into freerdp_dsp_context_reset / decode and divides).
 *              Sound interprocedural dataflow -- the half the intraprocedural detectors miss.
 * @kind path-problem
 * @problem.severity warning
 * @id lykos/wire-div-zero
 * @tags security external/cwe/cwe-369
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import WireDivZeroFlow::PathGraph

/** A value read off the wire: an argument of a WinPR stream reader / audio_format_read. */
predicate isWireSource(DataFlow::Node n) {
  exists(FunctionCall c |
    c.getTarget().getName().matches("Stream_Read\\_%") or
    c.getTarget().getName() = "audio_format_read" or
    c.getTarget().getName().matches("%_recv_%") |
    n.asDefiningArgument() = c.getArgument(1) or
    n.asExpr() = c
  )
}

/** The divisor operand of a `/` or `%`. */
predicate isDivisorSink(DataFlow::Node n) {
  exists(DivExpr d | n.asExpr() = d.getRightOperand()) or
  exists(RemExpr r | n.asExpr() = r.getRightOperand())
}

module WireDivZeroConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { isWireSource(n) }
  predicate isSink(DataFlow::Node n) { isDivisorSink(n) }
}

module WireDivZeroFlow = TaintTracking::Global<WireDivZeroConfig>;

from WireDivZeroFlow::PathNode source, WireDivZeroFlow::PathNode sink
where WireDivZeroFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Wire-controlled value is used as a divisor here; a zero value causes a divide-by-zero (CWE-369)."
