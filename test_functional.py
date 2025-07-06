"""
Functional tests for the NVD Lambda function.
"""

import json
import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import requests_mock

import lambda_function


class TestFunctionalScenarios(unittest.TestCase):
    """Functional test scenarios for the NVD Lambda function."""
    
    def setUp(self):
        """Set up functional test fixtures."""
        os.environ['SUPABASE_URL'] = 'https://test.supabase.co'
        os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test-key'
        os.environ['NVD_API_KEY'] = 'test-nvd-key'
        
        self.mock_context = Mock()
        self.mock_context.aws_request_id = 'test-request-id'
    
    def tearDown(self):
        """Clean up after functional tests."""
        for key in ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NVD_API_KEY']:
            if key in os.environ:
                del os.environ[key]
    
    @requests_mock.Mocker()
    @patch('lambda_function.create_client')
    @patch('lambda_function.time.sleep')
    def test_large_dataset_processing(self, mock_sleep, mock_create_client, m):
        """Test processing of large dataset with pagination."""
        # Mock Supabase client
        mock_client = Mock()
        mock_table = Mock()
        mock_upsert = Mock()
        mock_execute = Mock()
        
        mock_client.table.return_value = mock_table
        mock_table.upsert.return_value = mock_upsert
        mock_upsert.execute.return_value = Mock()
        mock_create_client.return_value = mock_client
        
        # Mock NVD API responses with pagination
        base_url = lambda_function.NVD_BASE_URL
        
        # First page response
        first_page_response = {
            'totalResults': 3000,
            'vulnerabilities': [
                {
                    'cve': {
                        'id': f'CVE-2023-{i:05d}',
                        'descriptions': [{
                            'lang': 'en',
                            'value': f'Test vulnerability {i}'
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
                } for i in range(2000)
            ]
        }
        
        # Second page response
        second_page_response = {
            'totalResults': 3000,
            'vulnerabilities': [
                {
                    'cve': {
                        'id': f'CVE-2023-{i:05d}',
                        'descriptions': [{
                            'lang': 'en',
                            'value': f'Test vulnerability {i}'
                        }],
                        'published': '2023-01-01T00:00:00.000',
                        'lastModified': '2023-01-02T00:00:00.000',
                        'metrics': {
                            'cvssMetricV31': [{
                                'cvssData': {
                                    'baseScore': 8.0
                                }
                            }]
                        }
                    }
                } for i in range(2000, 3000)
            ]
        }
        
        # Register mock responses
        m.get(base_url, [
            {'json': first_page_response, 'status_code': 200},
            {'json': second_page_response, 'status_code': 200}
        ])
        
        # Test processing
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
        
        vulnerabilities = lambda_function.fetch_nvd_vulnerabilities(
            start_date, end_date, 'test-key'
        )
        
        # Verify results
        self.assertEqual(len(vulnerabilities), 3000)
        self.assertEqual(vulnerabilities[0]['cve_id'], 'CVE-2023-00000')
        self.assertEqual(vulnerabilities[-1]['cve_id'], 'CVE-2023-02999')
        
        # Test batch processing
        processed_count = lambda_function.upsert_to_supabase(mock_client, vulnerabilities)
        self.assertEqual(processed_count, 3000)
        
        # Verify batching (should be called twice: 2000 + 1000)
        self.assertEqual(mock_table.upsert.call_count, 2)
    
    @requests_mock.Mocker()
    @patch('lambda_function.create_client')
    @patch('lambda_function.time.sleep')
    def test_api_error_recovery(self, mock_sleep, mock_create_client, m):
        """Test recovery from API errors."""
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        
        base_url = lambda_function.NVD_BASE_URL
        
        # Mock API responses: first fails, second succeeds
        success_response = {
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
        
        m.get(base_url, [
            {'status_code': 500},  # First request fails
            {'json': success_response, 'status_code': 200}  # Second succeeds
        ])
        
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        vulnerabilities = lambda_function.fetch_nvd_vulnerabilities(
            start_date, end_date, 'test-key'
        )
        
        self.assertEqual(len(vulnerabilities), 1)
        self.assertEqual(vulnerabilities[0]['cve_id'], 'CVE-2023-12345')
    
    @requests_mock.Mocker()
    @patch('lambda_function.create_client')
    @patch('lambda_function.time.sleep')
    def test_rate_limiting_handling(self, mock_sleep, mock_create_client, m):
        """Test proper handling of rate limiting."""
        mock_client = Mock()
        mock_create_client.return_value = mock_client
        
        base_url = lambda_function.NVD_BASE_URL
        
        success_response = {
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
                    'metrics': {}
                }
            }]
        }
        
        # Mock rate limiting response followed by success
        m.get(base_url, [
            {'status_code': 429},  # Rate limited
            {'json': success_response, 'status_code': 200}  # Success
        ])
        
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        vulnerabilities = lambda_function.fetch_nvd_vulnerabilities(
            start_date, end_date, 'test-key'
        )
        
        self.assertEqual(len(vulnerabilities), 1)
        # Verify sleep was called for rate limiting
        mock_sleep.assert_called()
    
    def test_date_chunking_accuracy(self):
        """Test accuracy of date chunking for 365-day period."""
        end_date = datetime(2023, 12, 31, 23, 59, 59)
        start_date = end_date - timedelta(days=365)
        
        chunks = lambda_function.generate_date_chunks(start_date, end_date, 120)
        
        # Verify complete coverage
        self.assertEqual(chunks[0][0], start_date)
        self.assertLessEqual(chunks[-1][1], end_date)
        
        # Verify no gaps between chunks
        for i in range(len(chunks) - 1):
            self.assertEqual(chunks[i][1], chunks[i + 1][0])
        
        # Verify total time span
        total_span = chunks[-1][1] - chunks[0][0]
        expected_span = end_date - start_date
        self.assertLessEqual(abs((total_span - expected_span).total_seconds()), 1)
    
    @patch('lambda_function.create_client')
    def test_supabase_batch_processing(self, mock_create_client):
        """Test Supabase batch processing with different batch sizes."""
        mock_client = Mock()
        mock_table = Mock()
        mock_upsert = Mock()
        mock_execute = Mock()
        
        mock_client.table.return_value = mock_table
        mock_table.upsert.return_value = mock_upsert
        mock_upsert.execute.return_value = Mock()
        mock_create_client.return_value = mock_client
        
        # Create test data with different sizes
        test_cases = [
            1500,  # Less than batch size
            2000,  # Exactly batch size
            2500,  # More than batch size
            5000   # Multiple batches
        ]
        
        for data_size in test_cases:
            with self.subTest(data_size=data_size):
                vulnerabilities = [
                    {
                        'cve_id': f'CVE-2023-{i:05d}',
                        'description': f'Test vulnerability {i}',
                        'published_date': '2023-01-01T00:00:00.000',
                        'last_modified_date': '2023-01-02T00:00:00.000',
                        'cvss_score': 7.5,
                        'updated_at': datetime.utcnow().isoformat()
                    }
                    for i in range(data_size)
                ]
                
                processed_count = lambda_function.upsert_to_supabase(
                    mock_client, vulnerabilities
                )
                
                self.assertEqual(processed_count, data_size)
                
                # Calculate expected number of batches
                expected_batches = (data_size + lambda_function.BATCH_SIZE - 1) // lambda_function.BATCH_SIZE
                self.assertEqual(mock_table.upsert.call_count, expected_batches)
                
                # Reset mock for next test
                mock_table.upsert.reset_mock()


class TestCPEFunctionalScenarios(unittest.TestCase):
    """Functional test scenarios for CPE data fetching."""
    
    def setUp(self):
        """Set up functional test fixtures for CPE tests."""
        os.environ['SUPABASE_URL'] = 'https://test.supabase.co'
        os.environ['SUPABASE_SERVICE_ROLE_KEY'] = 'test-key'
        os.environ['NVD_API_KEY'] = 'test-nvd-key'
        
        self.mock_context = Mock()
        self.mock_context.aws_request_id = 'test-request-id'
    
    def tearDown(self):
        """Clean up after CPE functional tests."""
        for key in ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'NVD_API_KEY']:
            if key in os.environ:
                del os.environ[key]
    
    @requests_mock.Mocker()
    @patch('lambda_function.time.sleep')
    def test_cpe_large_dataset_processing(self, mock_sleep, m):
        """Test processing of large CPE dataset with pagination."""
        cpe_base_url = lambda_function.CPE_BASE_URL
        
        # First page response
        first_page_response = {
            'totalResults': 3000,
            'products': [
                {
                    'cpe': {
                        'cpeName': f'cpe:2.3:a:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*',
                        'cpeNameId': f'cpe-id-{i:05d}',
                        'lastModified': '2023-01-01T00:00:00.000',
                        'created': '2023-01-01T00:00:00.000'
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
                        'cpeName': f'cpe:2.3:a:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*',
                        'cpeNameId': f'cpe-id-{i:05d}',
                        'lastModified': '2023-01-01T00:00:00.000',
                        'created': '2023-01-01T00:00:00.000'
                    }
                } for i in range(2000, 3000)
            ]
        }
        
        # Register mock responses
        m.get(cpe_base_url, [
            {'json': first_page_response, 'status_code': 200},
            {'json': second_page_response, 'status_code': 200}
        ])
        
        # Test processing
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
        
        cpe_data = lambda_function.fetch_nvd_cpe_data(
            start_date, end_date, 'test-key'
        )
        
        # Verify results
        self.assertEqual(len(cpe_data), 3000)
        self.assertEqual(cpe_data[0]['cpe']['cpeNameId'], 'cpe-id-00000')
        self.assertEqual(cpe_data[-1]['cpe']['cpeNameId'], 'cpe-id-02999')
    
    @requests_mock.Mocker()
    @patch('lambda_function.time.sleep')
    def test_cpe_api_error_recovery(self, mock_sleep, m):
        """Test recovery from CPE API errors."""
        cpe_base_url = lambda_function.CPE_BASE_URL
        
        # Mock API responses: first fails, second succeeds
        success_response = {
            'totalResults': 1,
            'products': [{
                'cpe': {
                    'cpeName': 'cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*',
                    'cpeNameId': 'test-cpe-id',
                    'lastModified': '2023-01-01T00:00:00.000',
                    'created': '2023-01-01T00:00:00.000'
                }
            }]
        }
        
        m.get(cpe_base_url, [
            {'status_code': 500},  # First request fails
            {'json': success_response, 'status_code': 200}  # Second succeeds
        ])
        
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        cpe_data = lambda_function.fetch_nvd_cpe_data(
            start_date, end_date, 'test-key'
        )
        
        self.assertEqual(len(cpe_data), 1)
        self.assertEqual(cpe_data[0]['cpe']['cpeNameId'], 'test-cpe-id')
    
    @requests_mock.Mocker()
    @patch('lambda_function.create_client')
    @patch('lambda_function.time.sleep')
    def test_integrated_cve_and_cpe_processing(self, mock_sleep, mock_create_client, m):
        """Test integrated processing of both CVE and CPE data."""
        # Mock Supabase client
        mock_client = Mock()
        mock_table = Mock()
        mock_upsert = Mock()
        mock_execute = Mock()
        
        mock_client.table.return_value = mock_table
        mock_table.upsert.return_value = mock_upsert
        mock_upsert.execute.return_value = Mock()
        mock_create_client.return_value = mock_client
        
        # Mock CVE API response
        cve_response = {
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
        
        # Mock CPE API response
        cpe_response = {
            'totalResults': 1,
            'products': [{
                'cpe': {
                    'cpeName': 'cpe:2.3:a:test:product:1.0:*:*:*:*:*:*:*',
                    'cpeNameId': 'test-cpe-id',
                    'lastModified': '2023-01-01T00:00:00.000'
                }
            }]
        }
        
        # Register mock responses
        m.get(lambda_function.NVD_BASE_URL, json=cve_response, status_code=200)
        m.get(lambda_function.CPE_BASE_URL, json=cpe_response, status_code=200)
        
        # Test the integration by calling lambda handler
        event = {}
        result = lambda_function.lambda_handler(event, self.mock_context)
        
        # Verify successful execution
        self.assertEqual(result['statusCode'], 200)
        response_body = json.loads(result['body'])
        self.assertIn('processed_count', response_body)
        self.assertEqual(response_body['processed_count'], 1)  # 1 vulnerability processed


if __name__ == '__main__':
    unittest.main()