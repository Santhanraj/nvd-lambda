/*
  # NVD Vulnerability Database Schema

  This migration creates the complete schema for storing vulnerability data from the National Vulnerability Database (NVD).

  ## 1. New Tables
    - `vulnerabilities`
      - `id` (bigserial, primary key)
      - `cve_id` (text, unique, not null) - CVE identifier
      - `description` (text) - Vulnerability description
      - `published_date` (timestamptz) - Publication date
      - `last_modified_date` (timestamptz) - Last modification date
      - `cvss_score` (decimal) - CVSS base score
      - `vendor_name` (text, default null) - Vendor name from CPE data
      - `updated_at` (timestamptz) - Record update timestamp
      - `created_at` (timestamptz) - Record creation timestamp

  ## 2. Security
    - Enable RLS on `vulnerabilities` table
    - Service role: Full access for Lambda function
    - Authenticated users: Read-only access
    - Anonymous users: Read access to recent vulnerabilities (30 days)

  ## 3. Performance
    - Indexes on all frequently queried columns
    - Automatic timestamp updates via trigger

  ## 4. Views and Functions
    - `high_severity_vulnerabilities` view (CVSS >= 7.0)
    - `recent_vulnerabilities` view (last 30 days)
    - `get_vulnerability_stats()` function for dashboard metrics
*/

-- Create vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    published_date TIMESTAMPTZ,
    last_modified_date TIMESTAMPTZ,
    cvss_score DECIMAL(3,1),
    vendor_name TEXT DEFAULT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_date ON vulnerabilities(published_date DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_last_modified ON vulnerabilities(last_modified_date DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cvss_score ON vulnerabilities(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_vendor_name ON vulnerabilities(vendor_name);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_updated_at ON vulnerabilities(updated_at DESC);

-- Enable Row Level Security (RLS)
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Create policy for service role access (full access)
CREATE POLICY "Service role can manage vulnerabilities"
    ON vulnerabilities
    FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- Create policy for authenticated users (read-only)
CREATE POLICY "Authenticated users can read vulnerabilities"
    ON vulnerabilities
    FOR SELECT
    TO authenticated
    USING (true);

-- Create policy for anonymous users (read-only, limited)
CREATE POLICY "Anonymous users can read recent vulnerabilities"
    ON vulnerabilities
    FOR SELECT
    TO anon
    USING (published_date >= NOW() - INTERVAL '30 days');

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to automatically update updated_at
CREATE TRIGGER update_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create view for high-severity vulnerabilities
CREATE OR REPLACE VIEW high_severity_vulnerabilities AS
SELECT 
    cve_id,
    description,
    published_date,
    last_modified_date,
    cvss_score,
    vendor_name,
    updated_at
FROM vulnerabilities
WHERE cvss_score >= 7.0
ORDER BY cvss_score DESC, published_date DESC;

-- Create view for recent vulnerabilities
CREATE OR REPLACE VIEW recent_vulnerabilities AS
SELECT 
    cve_id,
    description,
    published_date,
    last_modified_date,
    cvss_score,
    vendor_name,
    updated_at
FROM vulnerabilities
WHERE published_date >= NOW() - INTERVAL '30 days'
ORDER BY published_date DESC;

-- Grant access to views
GRANT SELECT ON high_severity_vulnerabilities TO authenticated, anon;
GRANT SELECT ON recent_vulnerabilities TO authenticated, anon;

-- Create function to get vulnerability statistics
CREATE OR REPLACE FUNCTION get_vulnerability_stats()
RETURNS JSON AS $$
DECLARE
    result JSON;
BEGIN
    SELECT json_build_object(
        'total_vulnerabilities', (SELECT COUNT(*) FROM vulnerabilities),
        'high_severity_count', (SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score >= 7.0),
        'medium_severity_count', (SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score >= 4.0 AND cvss_score < 7.0),
        'low_severity_count', (SELECT COUNT(*) FROM vulnerabilities WHERE cvss_score < 4.0),
        'recent_count', (SELECT COUNT(*) FROM vulnerabilities WHERE published_date >= NOW() - INTERVAL '30 days'),
        'vendors_count', (SELECT COUNT(DISTINCT vendor_name) FROM vulnerabilities WHERE vendor_name IS NOT NULL),
        'last_updated', (SELECT MAX(updated_at) FROM vulnerabilities)
    ) INTO result;
    
    RETURN result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant execute permission on the function
GRANT EXECUTE ON FUNCTION get_vulnerability_stats() TO authenticated, anon;

-- Add comments for documentation
COMMENT ON TABLE vulnerabilities IS 'Stores CVE vulnerability data from NVD API with vendor information';
COMMENT ON COLUMN vulnerabilities.cve_id IS 'Unique CVE identifier (e.g., CVE-2023-12345)';
COMMENT ON COLUMN vulnerabilities.description IS 'Vulnerability description from NVD';
COMMENT ON COLUMN vulnerabilities.published_date IS 'Date when vulnerability was published';
COMMENT ON COLUMN vulnerabilities.last_modified_date IS 'Date when vulnerability was last modified';
COMMENT ON COLUMN vulnerabilities.cvss_score IS 'CVSS base score (preferring 3.1, fallback to 3.0, then 2.0)';
COMMENT ON COLUMN vulnerabilities.vendor_name IS 'Vendor name extracted from CPE data (nullable)';
COMMENT ON COLUMN vulnerabilities.updated_at IS 'Timestamp when record was last updated in our database';
COMMENT ON COLUMN vulnerabilities.created_at IS 'Timestamp when record was first created in our database';