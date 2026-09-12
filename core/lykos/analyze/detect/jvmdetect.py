"""CWE detection for Java targets, from the constant pool.

There is no machine code in a jar, so the P-Code channels -- taint, bounds, integer overflow,
the deref classifier -- have nothing to work on and `detect_cwe` produced exactly zero
findings for a Java target. That is not a limitation of the approach, only of the substrate:
a .class file names every method it calls and every string it holds, in the clear, with no
decompiler in between. What an ELF gives up only after Ghidra, a jar states outright.

The detectors here are deliberately few and strict. The rule that matters is the one this
platform learned the hard way on native code: a pattern match is not a finding. Everything
below is filed as a CANDIDATE with the evidence it actually has, ranks under anything
demonstrated, and the ones that are merely "this program is capable of X" say so rather than
dressing a capability up as a vulnerability.
"""
from __future__ import annotations

import re

# --- sinks that are worth naming, and what each one actually implies --------------------
#
# `state` is the honest ceiling for a constant-pool match alone:
#   candidate  -- the call is present; whether input reaches it is not known from here.
_SINKS = (
    # Deserializing untrusted data is remote code execution with a gadget chain, and unlike
    # the rest of this list there is no safe way to call it on attacker data.
    ("CWE-502", "high", "Untrusted deserialization",
     ("java/io/ObjectInputStream.readObject", "java/io/ObjectInputStream.readUnshared"),
     "ObjectInputStream.readObject on attacker-controlled bytes is remote code execution "
     "with a gadget chain (ysoserial); there is no input validation that makes it safe"),
    ("CWE-78", "high", "Command execution",
     ("java/lang/Runtime.exec", "java/lang/ProcessBuilder.start",
      "java/lang/ProcessBuilder.<init>"),
     "the program launches external commands; if any part of the command line comes from "
     "input, this is command injection"),
    ("CWE-94", "high", "Dynamic class loading",
     ("java/lang/ClassLoader.defineClass", "java/net/URLClassLoader.<init>",
      "java/lang/Class.forName"),
     "the program loads classes by name or from a URL at runtime; an input that reaches the "
     "name or the URL chooses the code that runs"),
    ("CWE-89", "high", "SQL executed as a statement",
     ("java/sql/Statement.executeQuery", "java/sql/Statement.execute",
      "java/sql/Statement.executeUpdate"),
     "java.sql.Statement takes a finished SQL string, so the query was built by "
     "concatenation; PreparedStatement is the parameterised form"),
    ("CWE-611", "medium", "XML parsed with external entities",
     ("javax/xml/parsers/DocumentBuilderFactory.newInstance",
      "javax/xml/parsers/SAXParserFactory.newInstance",
      "javax/xml/stream/XMLInputFactory.newInstance"),
     "an XML parser resolves external entities unless explicitly told not to, which reads "
     "local files and reaches the network"),
    ("CWE-22", "medium", "Filesystem path built at runtime",
     ("java/io/FileInputStream.<init>", "java/io/FileOutputStream.<init>",
      "java/nio/file/Paths.get", "java/io/File.<init>"),
     "a path is constructed at runtime; if input reaches it without normalisation, `../` "
     "escapes the intended directory"),
)
# The XML sinks above are only a defect when the hardening call is ABSENT. A parser configured
# with setFeature(...disallow-doctype-decl...) is the fixed form, and reporting it anyway is
# how a report teaches its reader to ignore it.
_XXE_GUARDS = ("javax/xml/parsers/DocumentBuilderFactory.setFeature",
               "javax/xml/parsers/SAXParserFactory.setFeature",
               "javax/xml/stream/XMLInputFactory.setProperty",
               "javax/xml/parsers/DocumentBuilderFactory.setExpandEntityReferences",
               "javax/xml/parsers/DocumentBuilderFactory.setXIncludeAware")

# Weak algorithms, matched against the STRING the program passes to the factory rather than
# against the factory call -- Cipher.getInstance is not a defect, "DES" is.
_WEAK_CRYPTO = re.compile(
    r"^(DES|DESede|RC2|RC4|ARCFOUR|Blowfish)(/|$)|/ECB/|^(MD2|MD5|SHA-?1)$", re.I)
_CRYPTO_CALLS = ("javax/crypto/Cipher.getInstance", "java/security/MessageDigest.getInstance",
                 "javax/crypto/KeyGenerator.getInstance",
                 "javax/crypto/SecretKeyFactory.getInstance")

# Disabling certificate checking. A custom TrustManager is the usual way it is done, and it is
# almost never right in a program that is not a test.
_TRUST_CALLS = ("javax/net/ssl/SSLContext.init", "javax/net/ssl/HttpsURLConnection"
                ".setDefaultHostnameVerifier", "javax/net/ssl/HttpsURLConnection"
                ".setHostnameVerifier")
_TRUST_HINT = re.compile(r"(?i)javax/net/ssl/X509TrustManager|TrustAllCerts|"
                         r"ALLOW_ALL_HOSTNAME_VERIFIER")


def _owner(call: str) -> str:
    return call.rsplit(".", 1)[0]


def analyze(info, *, max_sites: int = 40) -> list:
    """Findings for a parsed jar/class. Each names the classes the call appears in."""
    out: list = []
    by_class = info.by_class or {}
    all_calls = set(info.calls or ())

    def classes_calling(names):
        hit = [c for c, d in by_class.items()
               if any(n in d["calls"] for n in names)]
        return sorted(hit)[:max_sites]

    for cwe, sev, title, names, why in _SINKS:
        present = [n for n in names if n in all_calls]
        if not present:
            continue
        if cwe == "CWE-611" and any(g in all_calls for g in _XXE_GUARDS):
            continue                         # the hardening call is there; not a finding
        where = classes_calling(names)
        detail = why + " -- calls: " + ", ".join(sorted(present)[:4])
        if where:
            detail += "; in " + ", ".join(w.replace("/", ".") for w in where[:6])
            if len(where) > 6:
                detail += f" (+{len(where) - 6} more)"
        out.append({
            "cwe": cwe, "severity": sev, "title": title,
            "state": "candidate", "confidence": 0.5, "detector": "jvm_sink",
            "dedup_key": f"jvm-sink:{cwe}:{','.join(sorted(present))}",
            "evidence": [{"channel": "constant-pool", "detail": detail}],
        })

    # weak crypto: the algorithm STRING, not the factory call
    if any(c in all_calls for c in _CRYPTO_CALLS):
        weak = sorted({s for s in (info.strings or ()) if _WEAK_CRYPTO.match(s.strip())})
        if weak:
            out.append({
                "cwe": "CWE-327", "severity": "medium",
                "title": "Broken or risky cryptographic algorithm",
                "state": "candidate", "confidence": 0.6, "detector": "jvm_crypto",
                "dedup_key": "jvm-crypto:" + ",".join(weak[:6]),
                "evidence": [{"channel": "constant-pool", "detail":
                              "algorithm passed to a JCA factory: " + ", ".join(weak[:6])
                              + " -- DES/RC4/MD5/SHA-1 and any ECB mode are broken or "
                                "leak plaintext structure"}]})

    if any(c in all_calls for c in _TRUST_CALLS) and any(
            _TRUST_HINT.search(x) for x in list(info.strings or ()) + sorted(all_calls)):
        out.append({
            "cwe": "CWE-295", "severity": "high",
            "title": "TLS certificate validation may be disabled",
            "state": "candidate", "confidence": 0.5, "detector": "jvm_tls",
            "dedup_key": "jvm-tls:trustmanager",
            "evidence": [{"channel": "constant-pool", "detail":
                          "the program installs its own TrustManager or hostname verifier "
                          "alongside SSLContext.init; a permissive one accepts any "
                          "certificate, which removes TLS's authentication entirely"}]})
    return out
