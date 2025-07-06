@@ .. @@
 -- Create vulnerabilities table
 CREATE TABLE IF NOT EXISTS vulnerabilities (
     id BIGSERIAL PRIMARY KEY,
     cve_id TEXT UNIQUE NOT NULL,
     description TEXT,
     published_date TIMESTAMPTZ,
     last_modified_date TIMESTAMPTZ,
     cvss_score DECIMAL(3,1),
+    vendor_name TEXT DEFAULT NULL,
     updated_at TIMESTAMPTZ DEFAULT NOW(),
     created_at TIMESTAMPTZ DEFAULT NOW()
 );

 -- Create indexes for better query performance
 CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
 CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date DESC);
 CREATE INDEX IF NOT EXISTS idx_vulnerabilities_last_modified ON vulnerabilities(last_modified_date DESC);
 CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score DESC);
+CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor_name ON vulnerabilities(vendor_name);
 CREATE INDEX IF NOT EXISTS idx_vulnerabilities_updated_at ON vulnerabilities(updated_at DESC);