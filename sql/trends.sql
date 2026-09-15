-- Phase 2 — SQL trend layer (Module 2: statistics, filtering, joins, window
-- functions). Builds on cves_in_scope / cve_cwe / cve_cpe from Phase 1.
--
-- Design note on a subtlety that would otherwise silently bias every
-- CVSS average in this file: cve_cpe has one row per (cve_id, vendor,
-- product, version) match, so a single CVE affecting 3 versions of the same
-- product -- or 2 products from the same vendor -- appears 2-3 times in that
-- table. A plain `AVG(cvss_score)` after joining cve_cpe would then count
-- that CVE's severity 2-3x while COUNT(DISTINCT cve_id) correctly counts it
-- once, silently overweighting multi-product/multi-version CVEs in every
-- severity statistic. Every view below dedupes to one row per (grouping
-- key, cve_id) in a CTE *before* aggregating, so cve_count and avg_cvss stay
-- consistent with each other.

-- ---------------------------------------------------------------------
-- v_canonical_cwe: one CWE per CVE, not one row per (cve_id, cwe_id, source).
-- The design doc's own Section 5.2 note observes a CVE "almost always has
-- *one* assigned CWE" -- but our schema (Section 6.1 doc note) keeps every
-- source's assignment, since sources sometimes disagree. For any analysis
-- that wants a single label per CVE (this trend view, and later the Module 3
-- classifier), pick NVD's Primary assignment first, then any NVD assignment,
-- then whatever's left -- rather than counting a CVE toward multiple CWEs
-- just because two sources both filed a weakness entry for it.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_canonical_cwe;
CREATE VIEW v_canonical_cwe AS
WITH ranked AS (
    SELECT
        cve_id, cwe_id, is_generic,
        ROW_NUMBER() OVER (
            PARTITION BY cve_id
            ORDER BY CASE
                WHEN source = 'nvd@nist.gov' AND type = 'Primary' THEN 0
                WHEN source = 'nvd@nist.gov'                      THEN 1
                ELSE 2
            END
        ) AS rn
    FROM cve_cwe
)
SELECT cve_id, cwe_id, is_generic FROM ranked WHERE rn = 1;

-- ---------------------------------------------------------------------
-- v_vendor_year_trend: Objective 1's core deliverable -- vendor/year trend
-- with a genuine pooled 3-year rolling average CVSS (sum/count carried
-- through the window, not an average-of-yearly-averages, which would drift
-- when year-to-year record counts are uneven) and year-over-year CVE growth.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_vendor_year_trend;
CREATE VIEW v_vendor_year_trend AS
WITH vendor_cve AS (
    SELECT DISTINCT vendor, cve_id FROM cve_cpe
),
per_vendor_year AS (
    SELECT
        vc.vendor,
        cv.published_year AS year,
        COUNT(*) AS cve_count,
        SUM(cv.cvss_score) AS cvss_sum,
        SUM(CASE WHEN cv.cvss_score IS NOT NULL THEN 1 ELSE 0 END) AS cvss_n,
        MIN(cv.cvss_score) AS min_cvss,
        MAX(cv.cvss_score) AS max_cvss
    FROM vendor_cve vc
    JOIN cves_in_scope cv ON vc.cve_id = cv.id
    GROUP BY vc.vendor, cv.published_year
),
windowed AS (
    SELECT *,
        SUM(cvss_sum) OVER (
            PARTITION BY vendor ORDER BY year ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
        ) AS roll_cvss_sum,
        SUM(cvss_n) OVER (
            PARTITION BY vendor ORDER BY year ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
        ) AS roll_cvss_n,
        LAG(cve_count) OVER (PARTITION BY vendor ORDER BY year) AS prev_year_count
    FROM per_vendor_year
)
SELECT
    vendor, year, cve_count,
    ROUND(cvss_sum * 1.0 / NULLIF(cvss_n, 0), 2) AS avg_cvss,
    min_cvss, max_cvss,
    ROUND(roll_cvss_sum * 1.0 / NULLIF(roll_cvss_n, 0), 2) AS rolling_avg_cvss_3yr,
    ROUND(100.0 * (cve_count - prev_year_count) / NULLIF(prev_year_count, 0), 1) AS yoy_cve_growth_pct
FROM windowed;

-- ---------------------------------------------------------------------
-- v_vendor_rank_by_year: leaderboard -- which vendors had the most
-- disclosed CVEs in a given year. Ties share a rank (RANK, not ROW_NUMBER),
-- which matters for a leaderboard: two vendors tied for 3rd should both
-- show 3rd, not arbitrarily 3rd/4th.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_vendor_rank_by_year;
CREATE VIEW v_vendor_rank_by_year AS
SELECT
    vendor, year, cve_count,
    RANK() OVER (PARTITION BY year ORDER BY cve_count DESC) AS rank_in_year
FROM v_vendor_year_trend;

-- ---------------------------------------------------------------------
-- v_product_year_trend: same trend shape one level down, at vendor+product
-- granularity, with an in-year ranking for "top products this year" queries.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_product_year_trend;
CREATE VIEW v_product_year_trend AS
WITH product_cve AS (
    SELECT DISTINCT vendor, product, cve_id FROM cve_cpe
),
per_product_year AS (
    SELECT
        pc.vendor, pc.product, cv.published_year AS year,
        COUNT(*) AS cve_count,
        ROUND(AVG(cv.cvss_score), 2) AS avg_cvss
    FROM product_cve pc
    JOIN cves_in_scope cv ON pc.cve_id = cv.id
    GROUP BY pc.vendor, pc.product, cv.published_year
)
SELECT
    vendor, product, year, cve_count, avg_cvss,
    RANK() OVER (PARTITION BY year ORDER BY cve_count DESC) AS rank_in_year
FROM per_product_year;

-- ---------------------------------------------------------------------
-- v_cwe_year_trend: weakness-category trend using the canonical (one-per-CVE)
-- CWE label, with each year's share-of-total and YoY growth. This is a
-- purely SQL-side trend signal -- distinct from, and a useful sanity check
-- against, the NLP drift-detection method planned for Module 4.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_cwe_year_trend;
CREATE VIEW v_cwe_year_trend AS
WITH per_cwe_year AS (
    SELECT cc.cwe_id, cv.published_year AS year, COUNT(*) AS cve_count
    FROM v_canonical_cwe cc
    JOIN cves_in_scope cv ON cc.cve_id = cv.id
    GROUP BY cc.cwe_id, cv.published_year
),
year_totals AS (
    SELECT published_year AS year, COUNT(*) AS total_cves
    FROM cves_in_scope
    GROUP BY published_year
)
SELECT
    p.cwe_id, p.year, p.cve_count,
    ROUND(100.0 * p.cve_count / t.total_cves, 2) AS pct_of_year,
    ROUND(100.0 * (p.cve_count - LAG(p.cve_count) OVER (PARTITION BY p.cwe_id ORDER BY p.year))
          / NULLIF(LAG(p.cve_count) OVER (PARTITION BY p.cwe_id ORDER BY p.year), 0), 1) AS yoy_growth_pct
FROM per_cwe_year p
JOIN year_totals t ON p.year = t.year;

-- ---------------------------------------------------------------------
-- v_severity_year_trend: descriptive statistics -- yearly severity mix
-- (CRITICAL/HIGH/MEDIUM/LOW/UNSCORED) as counts and % of that year's total.
-- ---------------------------------------------------------------------
DROP VIEW IF EXISTS v_severity_year_trend;
CREATE VIEW v_severity_year_trend AS
WITH per_severity_year AS (
    SELECT
        published_year AS year,
        COALESCE(severity, 'UNSCORED') AS severity,
        COUNT(*) AS cve_count
    FROM cves_in_scope
    GROUP BY published_year, COALESCE(severity, 'UNSCORED')
),
year_totals AS (
    SELECT published_year AS year, COUNT(*) AS total_cves
    FROM cves_in_scope
    GROUP BY published_year
)
SELECT
    p.year, p.severity, p.cve_count,
    ROUND(100.0 * p.cve_count / t.total_cves, 2) AS pct_of_year
FROM per_severity_year p
JOIN year_totals t ON p.year = t.year;