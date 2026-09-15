-- Vulnerability Intelligence Dashboard — SQLite schema
-- Adapted from design doc Section 5.2 to match the actual NVD JSON feed
-- structure (fkie-cad/nvd-json-data-feeds reconstruction of the legacy feeds).
--
-- Deviations from the design doc's simplified schema, and why:
--   1. cve_cwe carries `source` and `type` (Primary/Secondary) because a CVE
--      can have CWE assignments from multiple sources (e.g. the reporting
--      CNA AND nvd@nist.gov) that sometimes disagree. We keep both and let
--      downstream queries pick the NVD-primary one as the default label.
--   2. cve_cpe is derived from `configurations[].nodes[].cpeMatch[]`
--      (CPE 2.3 URI strings), not a separate CPE dictionary join, since the
--      reconstructed feed embeds match criteria directly on the CVE record.
--   3. cvss_score/severity are picked by a version-preference cascade
--      (v3.1 > v3.0 > v2) at load time, and cvss_version is recorded so the
--      choice is auditable.

CREATE TABLE cves (
    id              TEXT PRIMARY KEY,      -- e.g. 'CVE-2023-0001'
    published_date  TEXT NOT NULL,         -- ISO date, truncated from published timestamp
    published_year  INTEGER NOT NULL,
    last_modified   TEXT,
    vuln_status     TEXT,
    description     TEXT NOT NULL,
    cvss_score      REAL,                  -- NULL if no metrics published
    cvss_version    TEXT,                  -- 'v31' | 'v30' | 'v2' | NULL
    severity        TEXT                   -- CRITICAL/HIGH/MEDIUM/LOW/NULL
);

CREATE TABLE cve_cwe (
    cve_id      TEXT NOT NULL,
    cwe_id      TEXT NOT NULL,             -- 'CWE-79', or generic 'NVD-CWE-noinfo' / 'NVD-CWE-Other'
    source      TEXT,                      -- e.g. 'nvd@nist.gov'
    type        TEXT,                      -- 'Primary' | 'Secondary'
    is_generic  INTEGER NOT NULL DEFAULT 0,-- 1 if cwe_id is NVD-CWE-Other/noinfo
    PRIMARY KEY (cve_id, cwe_id, source, type),
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

CREATE TABLE cve_cpe (
    cve_id      TEXT NOT NULL,
    part        TEXT,                      -- 'a' (application) | 'o' (OS) | 'h' (hardware)
    vendor      TEXT NOT NULL,
    product     TEXT NOT NULL,
    version     TEXT,                      -- '*' if unbounded/version-range-only
    PRIMARY KEY (cve_id, vendor, product, version),
    FOREIGN KEY (cve_id) REFERENCES cves(id)
);

CREATE INDEX idx_cves_year ON cves(published_year);
CREATE INDEX idx_cve_cwe_cve ON cve_cwe(cve_id);
CREATE INDEX idx_cve_cwe_cwe ON cve_cwe(cwe_id);
CREATE INDEX idx_cve_cpe_cve ON cve_cpe(cve_id);
CREATE INDEX idx_cve_cpe_vendor_product ON cve_cpe(vendor, product);
