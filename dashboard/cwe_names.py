"""
CWE identifier -> official MITRE name.

The NVD feed records weakness identifiers only, never their names, so without
this table a language model asked about "CWE-416" has nothing to work from and
will invent a plausible-sounding expansion. (Observed: CWE-416 rendered as
"Improper Use of a Long or Cyclic Buffer", which is not a real weakness.)

Covers the identifiers that account for the large majority of classified
records. Anything absent must be shown as a bare identifier rather than
guessed -- lookup() returns None so callers can tell the difference.
"""

CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
    "CWE-74": "Injection (improper neutralization in downstream component)",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-98": "PHP Remote File Inclusion",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Classic Buffer Overflow (copy without size check)",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-189": "Numeric Errors",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-203": "Observable Discrepancy",
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-266": "Incorrect Privilege Assignment",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-310": "Cryptographic Issues",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-367": "Time-of-check Time-of-use (TOCTOU) Race Condition",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Missing Release of Memory after Effective Lifetime (memory leak)",
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-617": "Reachable Assertion",
    "CWE-639": "Authorization Bypass Through User-Controlled Key",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-835": "Loop with Unreachable Exit Condition (infinite loop)",
    "CWE-843": "Type Confusion (access using incompatible type)",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-908": "Use of Uninitialized Resource",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    # Generic NVD placeholders, not real weakness classes.
    "NVD-CWE-noinfo": "No weakness information provided",
    "NVD-CWE-Other": "Other / not mapped to a specific weakness",
}

# Coarse families, used to describe what a vendor's profile looks like.
MEMORY_SAFETY = {"CWE-787", "CWE-119", "CWE-125", "CWE-416", "CWE-476", "CWE-120",
                 "CWE-190", "CWE-908", "CWE-415", "CWE-121", "CWE-122", "CWE-843"}
WEB_INJECTION = {"CWE-79", "CWE-89", "CWE-352", "CWE-22", "CWE-78", "CWE-94",
                 "CWE-74", "CWE-77", "CWE-434", "CWE-98", "CWE-918", "CWE-611"}


def lookup(cwe_id):
    """Official name, or None when the identifier is not in the table."""
    return CWE_NAMES.get(cwe_id)


def label(cwe_id):
    """'CWE-416 (Use After Free)', or just 'CWE-416' when the name is unknown."""
    name = lookup(cwe_id)
    return f"{cwe_id} ({name})" if name else cwe_id
