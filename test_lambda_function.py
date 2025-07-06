"""
Unit tests for the NVD Lambda function.
"""

import json
import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import pytest
import requests_mock

# Import the lambda function
import lambda_function


class TestNVDLambdaFunction(unittest.TestCase):
    """Test cases for NVD Lambda function."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_context = Mock()
        self.mock_context.aws_request_id = 'test-request-id'
        
        # Set up environment variables
        os.environ['SUPABASE_URL'] = 'https://test.supabase.co'
        os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test-key'
        os.environ['NVD_API_KEY'] = 'test-nvd-key'
    
    def tearDown(self):
        """Clean up after tests."""
        # Clean up environment variables
        for key in ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NVD_API_KEY']:
            if key in os.environ:
                del os.environ[key]
    
    def test_generate_date_chunks(self):
        """Test date chunk generation."""
        start_date = datetime(2023, 1, 1)
        end_date = datetime(2023, 12, 31)
        chunk_days = 120
        
        chunks = lambda_function.generate_date_chunks(start_date, end_date, chunk_days)
        
        self.assertGreater(len(chunks), 0)
        self.assertEqual(chunks[0][0], start_date)
        self.assertLessEqual(chunks[-1][1], end_date)
        
        # Verify chunk sizes
        for i, (chunk_start, chunk_end) in enumerate(chunks[:-1]):
            delta = chunk_end - chunk_start
            self.assertEqual(delta.days, chunk_days)
    
    def test_extract_cvss_score_v31(self):
        """Test CVSS 3.1 score extraction."""
        metrics = {
            'cvssMetricV31': [{
                'cvssData': {
                    'baseScore': 7.5
                }
            }]
        }
        
        score = lambda_function.extract_cvss_score(metrics)
        self.assertEqual(score, 7.5)
    
    def test_extract_cvss_score_v30_fallback(self):
        """Test CVSS 3.0 fallback when 3.1 not available."""
        metrics = {
            'cvssMetricV30': [{
                'cvssData': {
                    'baseScore': 6.8
                }
            }]
        }
        
        score = lambda_function.extract_cvss_score(metrics)
        self.assertEqual(score, 6.8)
    
    def test_extract_cvss_score_v2_fallback(self):
        """Test CVSS 2.0 fallback when 3.x not available."""
        metrics = {
            'cvssMetricV2': [{
                'cvssData': {
                    'baseScore': 5.0
                }
            }]
        }
        
        score = lambda_function.extract_cvss_score(metrics)
        self.assertEqual(score, 5.0)
    
    def test_extract_cvss_score_none(self):
        """Test CVSS score extraction when no metrics available."""
        metrics = {}
        
        score = lambda_function.extract_cvss_score(metrics)
        self.assertIsNone(score)
    
    def test_process_nvd_response(self):
        """Test processing of NVD API response."""
        mock_data = [{
            'cve': {
                'id': 'CVE-2023-12345',
                'descriptions': [{
                    'lang': 'en',
                    'value': 'Test vulnerability description'
                }],
                'published': '2023-01-01T00:00:00.000',
                'lastModified': '2023-01-02T00:00:00.000',
                'configurations': [{
                    'nodes': [{
                        'cpeMatch': [{
                            'criteria': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
                        }]
                    }]
                }],
                'metrics': {
                    'cvssMetricV31': [{
                        'cvssData': {
                            'baseScore': 8.5
                        }
                    }]
                }
            }
        }]
        
        # Mock CPE data
        mock_cpe_data = [{
            'cpe': {
                'cpeName': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
            }
        }]
        
        processed = lambda_function.process_nvd_response(mock_data, mock_cpe_data)
        
        self.assertEqual(len(processed), 1)
        vuln = processed[0]
        self.assertEqual(vuln['cve_id'], 'CVE-2023-12345')
        self.assertEqual(vuln['description'], 'Test vulnerability description')
        self.assertEqual(vuln['cvss_score'], 8.5)
        self.assertEqual(vuln['vendor_name'], 'Apache')
    
    def test_extract_vendor_from_cpe_name(self):
        """Test vendor extraction from CPE name."""
        test_cases = [
            ('cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*', 'Apache'),
            ('cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*', 'Microsoft'),
            ('cpe:2.3:a:oracle:database:19c:*:*:*:*:*:*:*', 'Oracle'),
            ('cpe:2.3:a:red_hat:enterprise_linux:8:*:*:*:*:*:*:*', 'Red Hat'),
            ('cpe:2.3:a:*:product:1.0:*:*:*:*:*:*:*', None),  # Wildcard vendor
            ('invalid:cpe:format', None),  # Invalid format
        ]
        
        for cpe_name, expected_vendor in test_cases:
            with self.subTest(cpe_name=cpe_name):
                result = lambda_function.extract_vendor_from_cpe_name(cpe_name)
                self.assertEqual(result, expected_vendor)
    
    def test_build_vendor_lookup(self):
        """Test building vendor lookup dictionary from CPE data."""
        mock_cpe_data = [
            {
                'cpe': {
                    'cpeName': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
                }
            },
            {
                'cpe': {
                    'cpeName': 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*'
                }
            },
            {
                'cpe': {
                    'cpeName': 'invalid:format'  # Should be skipped
                }
            }
        ]
        
        vendor_lookup = lambda_function.build_vendor_lookup(mock_cpe_data)
        
        self.assertEqual(len(vendor_lookup), 2)
        self.assertEqual(vendor_lookup['cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'], 'Apache')
        self.assertEqual(vendor_lookup['cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*'], 'Microsoft')
    
    def test_extract_vendor_from_cve(self):
        """Test vendor extraction from CVE data."""
        mock_cve_data = {
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'
                    }]
                }]
            }]
        }
        
        vendor_lookup = {
            'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*': 'Apache'
        }
        
        vendor = lambda_function.extract_vendor_from_cve(mock_cve_data, vendor_lookup)
        self.assertEqual(vendor, 'Apache')
    
    def test_extract_vendor_from_cve_no_match(self):
        """Test vendor extraction when no match found."""
        mock_cve_data = {
            'configurations': [{
                'nodes': [{
                    'cpeMatch': [{
                        'criteria': 'cpe:2.3:a:unknown:product:1.0:*:*:*:*:*:*:*'
                    }]
                }]
            }]
        }
        
        vendor_lookup = {}
        
        vendor = lambda_function.extract_vendor_from_cve(mock_cve_data, vendor_lookup)
        self.assertEqual(vendor, 'Unknown')  # Should extract from CPE name directly
    
    @patch('lambda_function.create_client')
    def test_initialize_supabase_client_success(self, mock_create_client):
        """Test successful Supabase client initialization."""
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        
        client = lambda_function.initialize_supabase_client()
        
        self.assertEqual(client, mock_client)
        mock_create_client.assert_called_once_with(
            'https://test.supabase.co',
            'test-key'
        )
    
    def test_initialize_supabase_client_missing_env(self):
        """Test Supabase client initialization with missing environment variables."""
        del os.environ['SUPABASE_URL']
        
        with self.assertRaises(lambda_function.SupabaseError):
            lambda_function.initialize_supabase_client()
    
    @patch('lambda_function.requests.get')
    def test_make_nvd_request_success(self, mock_get):
        """Test successful NVD API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'test': 'data'}
        mock_get.return_value = mock_response
        
        headers = {'test': 'header'}
        params = {'test': 'param'}
        
        response = lambda_function.make_nvd_request(headers, params)
        
        self.assertEqual(response, mock_response)
        mock_get.assert_called_once()
    
    @patch('lambda_function.requests.get')
    @patch('lambda_function.time.sleep')
    def test_make_nvd_request_rate_limited(self, mock_sleep, mock_get):
        """Test NVD API request with rate limiting."""
        # First call returns 429, second call succeeds
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {'test': 'data'}
        
        mock_get.side_effect = [mock_response_429, mock_response_200]
        
        headers = {'test': 'header'}
        params = {'test': 'param'}
        
        response = lambda_function.make_nvd_request(headers, params)
        
        self.assertEqual(response, mock_response_200)
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(lambda_function.RETRY_DELAY)
    
    @patch('lambda_function.upsert_to_supabase')
    @patch('lambda_function.fetch_nvd_vulnerabilities')
    @patch('lambda_function.initialize_supabase_client')
    @patch('lambda_function.time.sleep')
    def test_lambda_handler_success(self, mock_sleep, mock_init_supabase, 
                                   mock_fetch_nvd, mock_upsert):
        """Test successful lambda handler execution."""
        # Mock dependencies
        mock_client = Mock()
        mock_init_supabase.return_value = mock_client
        
        mock_vulnerabilities = [{'cve_id': 'CVE-2023-12345'}]
        mock_fetch_nvd.return_value = mock_vulnerabilities
        
        mock_upsert.return_value = 1
        
        event = {}
        
        result = lambda_function.lambda_handler(event, self.mock_context)
        
        self.assertEqual(result['statusCode'], 200)
        response_body = json.loads(result['body'])
        self.assertIn('processed_count', response_body)
    
    @patch('lambda_function.initialize_supabase_client')
    def test_lambda_handler_error(self, mock_init_supabase):
        """Test lambda handler error handling."""
        mock_init_supabase.side_effect = Exception('Test error')
        
        event = {}
        
        result = lambda_function.lambda_handler(event, self.mock_context)
        
        self.assertEqual(result['statusCode'], 500)
        response_body = json.loads(result['body'])
        self.assertIn('error', response_body)


class TestIntegration(unittest.TestCase):
    """Integration tests for the NVD Lambda function."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        # Set up environment variables for integration tests
        os.environ['SUPABASE_URL'] = 'https://test.supabase.co'
        os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test-key'
        os.environ['NVD_API_KEY'] = 'test-nvd-key'
    
    def tearDown(self):
        """Clean up after integration tests."""
        for key in ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NVD_API_KEY']:
            if key in os.environ:
                del os.environ[key]
    
    @patch('lambda_function.requests.get')
    @patch('lambda_function.create_client')
    def test_end_to_end_processing(self, mock_create_client, mock_get):
        """Test end-to-end vulnerability processing."""
        # Mock NVD API response
        mock_nvd_response = Mock()
        mock_nvd_response.status_code = 200
        mock_nvd_response.json.return_value = {
            'totalResults': 1,
            'vulnerabilities': [{
                'cve': {
                    'id': 'CVE-2023-12345',
                    'descriptions': [{
                        'lang': 'en',
                        'value': 'Test vulnerability'
                    }],
                    'published': '2023-01-01T00:00:00.000',
                    'lastModified': '2023-01-02T00:00:00.000',
                    'metrics': {
                        'cvssMetricV31': [{
                            'cvssData': {
                                'baseScore': 7.5
                            }
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_nvd_response
        
        # Mock Supabase client
        mock_client = Mock()
        mock_table = Mock()
        mock_upsert = Mock()
        mock_execute = Mock()
        
        mock_client.table.return_value = mock_table
        mock_table.upsert.return_value = mock_upsert
        mock_upsert.execute.return_value = Mock()
        
        mock_create_client.return_value = mock_client
        
        # Test the integration
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        vulnerabilities = lambda_function.fetch_nvd_vulnerabilities(
            start_date, end_date, 'test-key'
        )
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['cve_id'], 'CVE-2023-12345')
        
        # Test upsert
        processed_count = lambda_function.upsert_to_supabase(mock_client, vulnerabilities)
        self.assertEqual(processed_count, 1)


class TestCPEFunctionality(unittest.TestCase):
    """Test cases for CPE data fetching functionality."""
    
    def setUp(self):
        """Set up test fixtures for CPE tests."""
        os.environ['SUPABASE_URL'] = 'https://test.supabase.co'
        os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test-key'
        os.environ['NVD_API_KEY'] = 'test-nvd-key'
    
    def tearDown(self):
        """Clean up after CPE tests."""
        for key in ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NVD_API_KEY']:
            if key in os.environ:
                del os.environ[key]
    
    @patch('lambda_function.requests.get')
    def test_make_nvd_cpe_request_success(self, mock_get):
        """Test successful NVD CPE API request."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'products': []}
        mock_get.return_value = mock_response
        
        headers = {'test': 'header'}
        params = {'test': 'param'}
        
        response = lambda_function.make_nvd_cpe_request(headers, params)
        
        self.assertEqual(response, mock_response)
        mock_get.assert_called_once_with(
            lambda_function.CPE_BASE_URL,
            headers=headers,
            params=params,
            timeout=30
        )
    
    @patch('lambda_function.requests.get')
    @patch('lambda_function.time.sleep')
    def test_make_nvd_cpe_request_rate_limited(self, mock_sleep, mock_get):
        """Test NVD CPE API request with rate limiting."""
        # First call returns 429, second call succeeds
        mock_response_429 = Mock()
        mock_response_429.status_code = 429
        
        mock_response_200 = Mock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {'products': []}
        
        mock_get.side_effect = [mock_response_429, mock_response_200]
        
        headers = {'test': 'header'}
        params = {'test': 'param'}
        
        response = lambda_function.make_nvd_cpe_request(headers, params)
        
        self.assertEqual(response, mock_response_200)
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once_with(lambda_function.RETRY_DELAY)
    
    @requests_mock.Mocker()
    @patch('lambda_function.time.sleep')
    def test_fetch_nvd_cpe_data(self, mock_sleep, m):
        """Test fetching CPE data from NVD API."""
        # Mock CPE API response
        mock_cpe_response = {
            'totalResults': 2,
            'products': [
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*',
                        'cpeNameId': 'test-id-1',
                        'lastModified': '2023-01-01T00:00:00.000'
                    }
                },
                {
                    'cpe': {
                        'cpeName': 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*',
                        'cpeNameId': 'test-id-2',
                        'lastModified': '2023-01-02T00:00:00.000'
                    }
                }
            ]
        }
        
        m.get(lambda_function.CPE_BASE_URL, json=mock_cpe_response, status_code=200)
        
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        cpe_data = lambda_function.fetch_nvd_cpe_data(start_date, end_date, 'test-key')
        
        self.assertEqual(len(cpe_data), 2)
        self.assertEqual(cpe_data[0]['cpe']['cpeName'], 'cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*')
        self.assertEqual(cpe_data[1]['cpe']['cpeName'], 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*')
    
    @requests_mock.Mocker()
    @patch('lambda_function.time.sleep')
    def test_fetch_nvd_cpe_data_pagination(self, mock_sleep, m):
        """Test CPE data fetching with pagination."""
        # First page response
        first_page_response = {
            'totalResults': 3000,
            'products': [
                {
                    'cpe': {
                        'cpeName': f'cpe:2.3:a:test:product{i}:1.0:*:*:*:*:*:*:*',
                        'cpeNameId': f'test-id-{i}',
                        'lastModified': '2023-01-01T00:00:00.000'
                    }
                } for i in range(2000)
            ]
        }
        
        # Second page response
        second_page_response = {
            'totalResults': 3000,
            'products': [
                {
                    'cpe': {
                        'cpeName': f'cpe:2.3:a:test:product{i}:1.0:*:*:*:*:*:*:*',
                        'cpeNameId': f'test-id-{i}',
                        'lastModified': '2023-01-01T00:00:00.000'
                    }
                } for i in range(2000, 3000)
            ]
        }
        
        # Register mock responses for pagination
        m.get(lambda_function.CPE_BASE_URL, [
            {'json': first_page_response, 'status_code': 200},
            {'json': second_page_response, 'status_code': 200}
        ])
        
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
        
        cpe_data = lambda_function.fetch_nvd_cpe_data(start_date, end_date, 'test-key')
        
        self.assertEqual(len(cpe_data), 3000)
        self.assertEqual(cpe_data[0]['cpe']['cpeNameId'], 'test-id-0')
        self.assertEqual(cpe_data[-1]['cpe']['cpeNameId'], 'test-id-2999')


if __name__ == '__main__':
    unittest.main()