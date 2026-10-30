// The no-build tagged-template (htm bound to Preact's h), shared by every view module.
import { h } from "preact";
import htm from "htm";
export const html = htm.bind(h);
