"""
AWS Lambda function to fetch vulnerability data from NVD API and upsert to Supabase.

This function:
1. Fetches CVE data from the NVD API for the last 365 days
2. Processes data in 120-day chunks with proper rate limiting
3. Extracts key vulnerability information
4. Upserts data to Supabase in batches of 2000 records
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import requests
from supabase import create_client, Client

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Constants
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
CHUNK_DAYS = 120
BATCH_SIZE = 2000
RATE_LIMIT_DELAY = 6  # seconds between requests (NVD allows 10 requests per minute)
MAX_RETRIES = 3
RETRY_DELAY = 30  # seconds


class NVDAPIError(Exception):
    """Custom exception for NVD API errors."""
    pass


class SupabaseError(Exception):
    """Custom exception for Supabase errors."""
    pass


def lambda_handler(event, context):
    """
    Main Lambda handler function.
    
    Args:
        event: Lambda event object
        context: Lambda context object
        
    Returns:
        dict: Response with status code and message
    """
    try:
        logger.info("Starting NVD vulnerability data sync")
        
        # Initialize clients
        nvd_api_key = os.environ.get('NVD_API_KEY')
        supabase_client = initialize_supabase_client()
        
        # Calculate date range (last 365 days)
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=365)
        
        logger.info(f"Fetching vulnerabilities from {start_date.date()} to {end_date.date()}")
        
        # Process data in chunks
        total_processed = 0
        date_chunks = generate_date_chunks(start_date, end_date, CHUNK_DAYS)
        
        for chunk_start, chunk_end in date_chunks:
            logger.info(f"Processing chunk: {chunk_start.date()} to {chunk_end.date()}")
            
            # Fetch vulnerabilities
            vulnerabilities = fetch_nvd_vulnerabilities(
                chunk_start, chunk_end, nvd_api_key
            )
            
            # Fetch CPE data for the same time period
            cpe_data = fetch_nvd_cpe_data(
                chunk_start, chunk_end, nvd_api_key
            )
            
            if vulnerabilities:
                # Process vulnerabilities with CPE vendor lookup
                processed_vulnerabilities = process_nvd_response(vulnerabilities, cpe_data)
                processed_count = upsert_to_supabase(supabase_client, processed_vulnerabilities)
                total_processed += processed_count
                logger.info(f"Processed {processed_count} vulnerabilities in this chunk")
            
            if cpe_data:
                logger.info(f"Fetched {len(cpe_data)} CPE records in this chunk (not processed yet)")
            
            # Rate limiting between chunks
            time.sleep(RATE_LIMIT_DELAY)
        
        logger.info(f"Successfully processed {total_processed} total vulnerabilities")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully processed {total_processed} vulnerabilities',
                'processed_count': total_processed
            })
        }
        
    except Exception as e:
        logger.error(f"Lambda execution failed: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }


def initialize_supabase_client() -> Client:
    """
    Initialize and return Supabase client.
    
    Returns:
        Client: Configured Supabase client
        
    Raises:
        SupabaseError: If required environment variables are missing
    """
    supabase_url = os.environ.get('SUPABASE_URL')
    supabase_key = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
    
    if not supabase_url or not supabase_key:
        raise SupabaseError("Missing required Supabase environment variables")
    
    try:
        client = create_client(supabase_url, supabase_key)
        logger.info("Supabase client initialized successfully")
        return client
    except Exception as e:
        raise SupabaseError(f"Failed to initialize Supabase client: {str(e)}")


def generate_date_chunks(start_date: datetime, end_date: datetime, chunk_days: int) -> List[Tuple[datetime, datetime]]:
    """
    Generate date chunks for API requests.
    
    Args:
        start_date: Start date for data retrieval
        end_date: End date for data retrieval
        chunk_days: Number of days per chunk
        
    Returns:
        List[Tuple[datetime, datetime]]: List of (start, end) date tuples
    """
    chunks = []
    current_start = start_date
    
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=chunk_days), end_date)
        chunks.append((current_start, current_end))
        current_start = current_end
    
    logger.info(f"Generated {len(chunks)} date chunks of {chunk_days} days each")
    return chunks


def fetch_nvd_vulnerabilities(start_date: datetime, end_date: datetime, api_key: Optional[str]) -> List[Dict]:
    """
    Fetch vulnerabilities from NVD API for the specified date range.
    
    Args:
        start_date: Start date for vulnerability search
        end_date: End date for vulnerability search
        api_key: NVD API key (optional but recommended)
        
    Returns:
        List[Dict]: List of processed vulnerability records
        
    Raises:
        NVDAPIError: If API request fails
    """
    vulnerabilities = []
    start_index = 0
    results_per_page = 2000  # NVD API maximum
    
    # Format dates for API
    pub_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    pub_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    headers = {
        'User-Agent': 'AWS-Lambda-NVD-Sync/1.0',
        'Accept': 'application/json'
    }
    
    if api_key:
        headers['apiKey'] = api_key
        logger.info("Using API key for NVD requests")
    else:
        logger.warning("No API key provided - requests will be rate limited")
    
    while True:
        params = {
            'pubStartDate': pub_start_date,
            'pubEndDate': pub_end_date,
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        try:
            response = make_nvd_request(headers, params)
            data = response.json()
            
            # Extract vulnerabilities from response
            if 'vulnerabilities' in data:
                batch_vulnerabilities = data['vulnerabilities']
                vulnerabilities.extend(batch_vulnerabilities)
                
                logger.info(f"Fetched {len(batch_vulnerabilities)} raw vulnerabilities "
                           f"(total: {len(vulnerabilities)})")
            
            # Check if we have more results
            total_results = data.get('totalResults', 0)
            if start_index + results_per_page >= total_results:
                break
                
            start_index += results_per_page
            
            # Rate limiting between requests
            time.sleep(RATE_LIMIT_DELAY)
            
        except Exception as e:
            raise NVDAPIError(f"Failed to fetch NVD data: {str(e)}")
    
    logger.info(f"Total vulnerabilities fetched: {len(vulnerabilities)}")
    return vulnerabilities


def make_nvd_request(headers: Dict, params: Dict) -> requests.Response:
    """
    Make HTTP request to NVD API with retry logic.
    
    Args:
        headers: Request headers
        params: Request parameters
        
    Returns:
        requests.Response: API response
        
    Raises:
        NVDAPIError: If all retry attempts fail
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                NVD_BASE_URL,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response
            elif response.status_code == 429:  # Rate limited
                logger.warning(f"Rate limited, waiting {RETRY_DELAY} seconds")
                time.sleep(RETRY_DELAY)
                continue
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request attempt {attempt + 1} failed: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise NVDAPIError(f"All retry attempts failed: {str(e)}")


def process_nvd_response(vulnerabilities_data: List[Dict], cpe_data: List[Dict] = None) -> List[Dict]:
    """
    Process raw NVD API response and extract required fields, including vendor lookup from CPE data.
    
    Args:
        vulnerabilities_data: Raw vulnerability data from NVD API
        cpe_data: CPE data for vendor lookup (optional)
        
    Returns:
        List[Dict]: Processed vulnerability records
    """
    # Build vendor lookup dictionary from CPE data
    vendor_lookup = build_vendor_lookup(cpe_data) if cpe_data else {}
    
    processed_vulnerabilities = []
    
    for vuln_data in vulnerabilities_data:
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                logger.warning("Skipping vulnerability without CVE ID")
                continue
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = ''
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract dates
            published = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            # Extract CVSS score (prefer 3.1, fallback to 3.0)
            cvss_score = extract_cvss_score(cve.get('metrics', {}))
            
            # Extract vendor name from CPE configurations
            vendor_name = extract_vendor_from_cve(cve, vendor_lookup)
            
            vulnerability_record = {
                'cve_id': cve_id,
                'description': description,
                'published_date': published,
                'last_modified_date': last_modified,
                'cvss_score': cvss_score,
                'vendor_name': vendor_name,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            processed_vulnerabilities.append(vulnerability_record)
            
        except Exception as e:
            logger.error(f"Error processing vulnerability {cve_id}: {str(e)}")
            continue
    
    return processed_vulnerabilities


def build_vendor_lookup(cpe_data: List[Dict]) -> Dict[str, str]:
    """
    Build a lookup dictionary mapping CPE names to vendor names.
    
    Args:
        cpe_data: List of CPE records from NVD API
        
    Returns:
        Dict[str, str]: Dictionary mapping CPE names to vendor names
    """
    vendor_lookup = {}
    
    if not cpe_data:
        return vendor_lookup
    
    for cpe_record in cpe_data:
        try:
            cpe_info = cpe_record.get('cpe', {})
            cpe_name = cpe_info.get('cpeName', '')
            
            if cpe_name:
                # Parse CPE name to extract vendor
                # CPE format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
                vendor_name = extract_vendor_from_cpe_name(cpe_name)
                if vendor_name:
                    vendor_lookup[cpe_name] = vendor_name
                    
        except Exception as e:
            logger.warning(f"Error processing CPE record: {str(e)}")
            continue
    
    logger.info(f"Built vendor lookup with {len(vendor_lookup)} CPE entries")
    return vendor_lookup


def extract_vendor_from_cpe_name(cpe_name: str) -> Optional[str]:
    """
    Extract vendor name from CPE name string.
    
    Args:
        cpe_name: CPE name in format cpe:2.3:part:vendor:product:...
        
    Returns:
        Optional[str]: Vendor name or None if not extractable
    """
    try:
        # Split CPE name by colons
        parts = cpe_name.split(':')
        
        # CPE 2.3 format has vendor at index 3
        if len(parts) >= 4 and parts[0] == 'cpe' and parts[1] == '2.3':
            vendor = parts[3]
            
            # Clean up vendor name (remove URL encoding, etc.)
            if vendor and vendor != '*':
                # Replace common URL encodings
                vendor = vendor.replace('%20', ' ')
                vendor = vendor.replace('_', ' ')
                
                # Capitalize first letter of each word
                vendor = ' '.join(word.capitalize() for word in vendor.split())
                
                return vendor
                
    except Exception as e:
        logger.warning(f"Error parsing CPE name {cpe_name}: {str(e)}")
    
    return None


def extract_vendor_from_cve(cve_data: Dict, vendor_lookup: Dict[str, str]) -> Optional[str]:
    """
    Extract vendor name from CVE data using CPE configurations.
    
    Args:
        cve_data: CVE data from NVD API
        vendor_lookup: Dictionary mapping CPE names to vendor names
        
    Returns:
        Optional[str]: Vendor name or None if not found
    """
    try:
        # Look for CPE configurations in the CVE data
        configurations = cve_data.get('configurations', [])
        
        for config in configurations:
            # Check nodes in configuration
            nodes = config.get('nodes', [])
            
            for node in nodes:
                # Check CPE matches
                cpe_matches = node.get('cpeMatch', [])
                
                for cpe_match in cpe_matches:
                    cpe_name = cpe_match.get('criteria', '')
                    
                    # First try exact match in vendor lookup
                    if cpe_name in vendor_lookup:
                        return vendor_lookup[cpe_name]
                    
                    # If no exact match, try to extract vendor directly from CPE name
                    vendor = extract_vendor_from_cpe_name(cpe_name)
                    if vendor:
                        return vendor
        
        # If no vendor found in configurations, return None
        return None
        
    except Exception as e:
        logger.warning(f"Error extracting vendor from CVE: {str(e)}")
        return None


def extract_cvss_score(metrics: Dict) -> Optional[float]:
    """
    Extract CVSS score from metrics, preferring 3.1 over 3.0.
    
    Args:
        metrics: Metrics data from NVD API
        
    Returns:
        Optional[float]: CVSS base score or None if not available
    """
    # Try CVSS 3.1 first
    cvss_v31 = metrics.get('cvssMetricV31', [])
    if cvss_v31:
        return cvss_v31[0].get('cvssData', {}).get('baseScore')
    
    # Fallback to CVSS 3.0
    cvss_v30 = metrics.get('cvssMetricV30', [])
    if cvss_v30:
        return cvss_v30[0].get('cvssData', {}).get('baseScore')
    
    # Fallback to CVSS 2.0 if needed
    cvss_v2 = metrics.get('cvssMetricV2', [])
    if cvss_v2:
        return cvss_v2[0].get('cvssData', {}).get('baseScore')
    
    return None


def fetch_nvd_cpe_data(start_date: datetime, end_date: datetime, api_key: Optional[str]) -> List[Dict]:
    """
    Fetch CPE (Common Platform Enumeration) data from NVD API for the specified date range.
    
    Args:
        start_date: Start date for CPE search
        end_date: End date for CPE search
        api_key: NVD API key (optional but recommended)
        
    Returns:
        List[Dict]: List of raw CPE records (not processed yet)
        
    Raises:
        NVDAPIError: If API request fails
    """
    cpe_records = []
    start_index = 0
    results_per_page = 2000  # NVD API maximum
    
    # Format dates for API
    mod_start_date = start_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    mod_end_date = end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
    
    headers = {
        'User-Agent': 'AWS-Lambda-NVD-Sync/1.0',
        'Accept': 'application/json'
    }
    
    if api_key:
        headers['apiKey'] = api_key
        logger.info("Using API key for NVD CPE requests")
    else:
        logger.warning("No API key provided for CPE requests - requests will be rate limited")
    
    while True:
        params = {
            'lastModStartDate': mod_start_date,
            'lastModEndDate': mod_end_date,
            'startIndex': start_index,
            'resultsPerPage': results_per_page
        }
        
        try:
            response = make_nvd_cpe_request(headers, params)
            data = response.json()
            
            # Extract CPE records from response
            if 'products' in data:
                batch_cpe_records = data['products']
                cpe_records.extend(batch_cpe_records)
                
                logger.info(f"Fetched {len(batch_cpe_records)} CPE records "
                           f"(total: {len(cpe_records)})")
            
            # Check if we have more results
            total_results = data.get('totalResults', 0)
            if start_index + results_per_page >= total_results:
                break
                
            start_index += results_per_page
            
            # Rate limiting between requests
            time.sleep(RATE_LIMIT_DELAY)
            
        except Exception as e:
            raise NVDAPIError(f"Failed to fetch NVD CPE data: {str(e)}")
    
    logger.info(f"Total CPE records fetched: {len(cpe_records)}")
    return cpe_records


def make_nvd_cpe_request(headers: Dict, params: Dict) -> requests.Response:
    """
    Make HTTP request to NVD CPE API with retry logic.
    
    Args:
        headers: Request headers
        params: Request parameters
        
    Returns:
        requests.Response: API response
        
    Raises:
        NVDAPIError: If all retry attempts fail
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(
                CPE_BASE_URL,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return response
            elif response.status_code == 429:  # Rate limited
                logger.warning(f"CPE API rate limited, waiting {RETRY_DELAY} seconds")
                time.sleep(RETRY_DELAY)
                continue
            else:
                response.raise_for_status()
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"CPE request attempt {attempt + 1} failed: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                raise NVDAPIError(f"All CPE retry attempts failed: {str(e)}")


def upsert_to_supabase(client: Client, vulnerabilities: List[Dict]) -> int:
    """
    Upsert vulnerability data to Supabase in batches.
    
    Args:
        client: Supabase client
        vulnerabilities: List of vulnerability records
        
    Returns:
        int: Number of records processed
        
    Raises:
        SupabaseError: If upsert operation fails
    """
    total_processed = 0
    
    # Process in batches
    for i in range(0, len(vulnerabilities), BATCH_SIZE):
        batch = vulnerabilities[i:i + BATCH_SIZE]
        
        try:
            # Upsert batch to Supabase
            result = client.table('vulnerabilities').upsert(
                batch,
                on_conflict='cve_id'
            ).execute()
            
            batch_count = len(batch)
            total_processed += batch_count
            
            logger.info(f"Successfully upserted batch of {batch_count} records "
                       f"(total processed: {total_processed})")
            
        except Exception as e:
            logger.error(f"Failed to upsert batch starting at index {i}: {str(e)}")
            raise SupabaseError(f"Batch upsert failed: {str(e)}")
    
    return total_processed