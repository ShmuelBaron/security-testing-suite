"""
API security tester for security testing.
"""
import logging
import requests
import time
import json
import re
from typing import Dict, Any, Optional, List, Union

class ApiSecurityTester:
    """Class for testing API security."""
    
    def __init__(self, base_url: str = None, timeout: int = 10):
        """
        Initialize the API security tester.
        
        Args:
            base_url: Base URL for API endpoints
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
    
    def test_authentication(
        self,
        endpoint: str,
        auth_types: List[str] = None,
        username: str = None,
        password: str = None,
        api_key: str = None,
        token: str = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test API authentication mechanisms.
        
        Args:
            endpoint: API endpoint to test
            auth_types: List of authentication types to test ('none', 'basic', 'bearer', 'api_key')
            username: Username for basic auth
            password: Password for basic auth
            api_key: API key for key-based auth
            token: Bearer token for token-based auth
            headers: Additional headers to include
            
        Returns:
            Dict: Test results for each authentication type
        """
        url = self._get_full_url(endpoint)
        
        if not auth_types:
            auth_types = ['none', 'basic', 'bearer', 'api_key']
        
        self.logger.info(f"Testing API authentication at {url}")
        
        results = {}
        
        # Test with no authentication
        if 'none' in auth_types:
            self.logger.info("Testing with no authentication")
            
            try:
                response = self.session.get(
                    url,
                    headers=headers,
                    timeout=self.timeout
                )
                
                results['none'] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'authenticated': response.status_code not in [401, 403],
                    'elapsed_time': response.elapsed.total_seconds()
                }
                
                if response.status_code not in [401, 403]:
                    self.logger.warning(f"API endpoint accessible without authentication: {url}")
                
            except Exception as e:
                self.logger.error(f"Error testing no authentication: {str(e)}")
                results['none'] = {
                    'error': str(e)
                }
        
        # Test with basic authentication
        if 'basic' in auth_types and username and password:
            self.logger.info(f"Testing with basic authentication: {username}")
            
            try:
                response = self.session.get(
                    url,
                    auth=(username, password),
                    headers=headers,
                    timeout=self.timeout
                )
                
                results['basic'] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'authenticated': response.status_code not in [401, 403],
                    'elapsed_time': response.elapsed.total_seconds()
                }
                
            except Exception as e:
                self.logger.error(f"Error testing basic authentication: {str(e)}")
                results['basic'] = {
                    'error': str(e)
                }
        
        # Test with bearer token
        if 'bearer' in auth_types and token:
            self.logger.info("Testing with bearer token authentication")
            
            try:
                auth_headers = headers.copy() if headers else {}
                auth_headers['Authorization'] = f"Bearer {token}"
                
                response = self.session.get(
                    url,
                    headers=auth_headers,
                    timeout=self.timeout
                )
                
                results['bearer'] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'authenticated': response.status_code not in [401, 403],
                    'elapsed_time': response.elapsed.total_seconds()
                }
                
            except Exception as e:
                self.logger.error(f"Error testing bearer token authentication: {str(e)}")
                results['bearer'] = {
                    'error': str(e)
                }
        
        # Test with API key
        if 'api_key' in auth_types and api_key:
            self.logger.info("Testing with API key authentication")
            
            # Try API key in header
            try:
                auth_headers = headers.copy() if headers else {}
                auth_headers['X-API-Key'] = api_key
                
                response = self.session.get(
                    url,
                    headers=auth_headers,
                    timeout=self.timeout
                )
                
                results['api_key_header'] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'authenticated': response.status_code not in [401, 403],
                    'elapsed_time': response.elapsed.total_seconds()
                }
                
            except Exception as e:
                self.logger.error(f"Error testing API key in header: {str(e)}")
                results['api_key_header'] = {
                    'error': str(e)
                }
            
            # Try API key as query parameter
            try:
                response = self.session.get(
                    url,
                    params={'api_key': api_key},
                    headers=headers,
                    timeout=self.timeout
                )
                
                results['api_key_query'] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'authenticated': response.status_code not in [401, 403],
                    'elapsed_time': response.elapsed.total_seconds()
                }
                
            except Exception as e:
                self.logger.error(f"Error testing API key in query parameter: {str(e)}")
                results['api_key_query'] = {
                    'error': str(e)
                }
        
        return {
            'url': url,
            'results': results
        }
    
    def test_rate_limiting(
        self,
        endpoint: str,
        requests_count: int = 20,
        interval: float = 0.1,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test API rate limiting.
        
        Args:
            endpoint: API endpoint to test
            requests_count: Number of requests to send
            interval: Interval between requests in seconds
            auth: Authentication details (type, username, password, token, api_key)
            headers: Additional headers to include
            
        Returns:
            Dict: Test results with rate limiting details
        """
        url = self._get_full_url(endpoint)
        
        self.logger.info(f"Testing API rate limiting at {url} with {requests_count} requests")
        
        results = []
        rate_limited = False
        
        # Prepare authentication
        auth_type = auth.get('type') if auth else None
        username = auth.get('username') if auth else None
        password = auth.get('password') if auth else None
        token = auth.get('token') if auth else None
        api_key = auth.get('api_key') if auth else None
        
        for i in range(requests_count):
            try:
                start_time = time.time()
                
                # Apply authentication
                if auth_type == 'basic' and username and password:
                    response = self.session.get(
                        url,
                        auth=(username, password),
                        headers=headers,
                        timeout=self.timeout
                    )
                elif auth_type == 'bearer' and token:
                    auth_headers = headers.copy() if headers else {}
                    auth_headers['Authorization'] = f"Bearer {token}"
                    
                    response = self.session.get(
                        url,
                        headers=auth_headers,
                        timeout=self.timeout
                    )
                elif auth_type == 'api_key' and api_key:
                    auth_headers = headers.copy() if headers else {}
                    auth_headers['X-API-Key'] = api_key
                    
                    response = self.session.get(
                        url,
                        headers=auth_headers,
                        timeout=self.timeout
                    )
                else:
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout
                    )
                
                elapsed_time = time.time() - start_time
                
                # Check for rate limiting response
                if response.status_code == 429:
                    rate_limited = True
                
                # Extract rate limit headers
                rate_limit_headers = {}
                for header in response.headers:
                    if any(limit_header in header.lower() for limit_header in ['rate', 'limit', 'remaining', 'reset']):
                        rate_limit_headers[header] = response.headers[header]
                
                results.append({
                    'request_number': i + 1,
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'elapsed_time': elapsed_time,
                    'rate_limit_headers': rate_limit_headers
                })
                
                if rate_limited:
                    self.logger.info(f"Rate limited after {i + 1} requests")
                    break
                
                # Wait before next request
                if i < requests_count - 1:
                    time.sleep(interval)
                    
            except Exception as e:
                self.logger.error(f"Error in request {i + 1}: {str(e)}")
                results.append({
                    'request_number': i + 1,
                    'error': str(e)
                })
        
        # Analyze results
        response_times = [r.get('elapsed_time') for r in results if 'elapsed_time' in r]
        status_codes = [r.get('status_code') for r in results if 'status_code' in r]
        
        rate_limit_info = {}
        for result in results:
            if 'rate_limit_headers' in result:
                for header, value in result.get('rate_limit_headers', {}).items():
                    rate_limit_info[header] = value
        
        return {
            'url': url,
            'rate_limited': rate_limited,
            'requests_sent': len(results),
            'average_response_time': sum(response_times) / len(response_times) if response_times else None,
            'status_code_distribution': {code: status_codes.count(code) for code in set(status_codes)} if status_codes else {},
            'rate_limit_headers': rate_limit_info,
            'results': results
        }
    
    def test_http_methods(
        self,
        endpoint: str,
        methods: List[str] = None,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Test supported HTTP methods.
        
        Args:
            endpoint: API endpoint to test
            methods: List of HTTP methods to test
            auth: Authentication details (type, username, password, token, api_key)
            headers: Additional headers to include
            data: Request data for POST, PUT, PATCH methods
            
        Returns:
            Dict: Test results for each HTTP method
        """
        url = self._get_full_url(endpoint)
        
        if not methods:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        
        self.logger.info(f"Testing HTTP methods at {url}")
        
        results = {}
        
        # Prepare authentication
        auth_type = auth.get('type') if auth else None
        username = auth.get('username') if auth else None
        password = auth.get('password') if auth else None
        token = auth.get('token') if auth else None
        api_key = auth.get('api_key') if auth else None
        
        # Prepare headers with authentication
        request_headers = headers.copy() if headers else {}
        
        if auth_type == 'bearer' and token:
            request_headers['Authorization'] = f"Bearer {token}"
        elif auth_type == 'api_key' and api_key:
            request_headers['X-API-Key'] = api_key
        
        # Test each method
        for method in methods:
            self.logger.info(f"Testing {method} method")
            
            try:
                if auth_type == 'basic' and username and password:
                    auth_tuple = (username, password)
                else:
                    auth_tuple = None
                
                if method in ['POST', 'PUT', 'PATCH'] and data:
                    response = self.session.request(
                        method=method,
                        url=url,
                        auth=auth_tuple,
                        headers=request_headers,
                        json=data,
                        timeout=self.timeout
                    )
                else:
                    response = self.session.request(
                        method=method,
                        url=url,
                        auth=auth_tuple,
                        headers=request_headers,
                        timeout=self.timeout
                    )
                
                # Extract response headers
                response_headers = {}
                for header in response.headers:
                    response_headers[header] = response.headers[header]
                
                results[method] = {
                    'status_code': response.status_code,
                    'response_size': len(response.content),
                    'elapsed_time': response.elapsed.total_seconds(),
                    'allowed': response.status_code not in [404, 405, 501],
                    'response_headers': response_headers
                }
                
                if method == 'OPTIONS':
                    # Check for CORS headers
                    cors_headers = {}
                    for header in response.headers:
                        if 'access-control' in header.lower():
                            cors_headers[header] = response.headers[header]
                    
                    results[method]['cors_headers'] = cors_headers
                
            except Exception as e:
                self.logger.error(f"Error testing {method} method: {str(e)}")
                results[method] = {
                    'error': str(e)
                }
        
        # Check for allowed methods in OPTIONS response
        if 'OPTIONS' in results and 'response_headers' in results['OPTIONS']:
            allow_header = results['OPTIONS']['response_headers'].get('Allow')
            if allow_header:
                allowed_methods = [m.strip() for m in allow_header.split(',')]
                results['allowed_methods'] = allowed_methods
        
        return {
            'url': url,
            'results': results
        }
    
    def test_input_validation(
        self,
        endpoint: str,
        method: str = 'POST',
        test_cases: List[Dict[str, Any]] = None,
        auth: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test API input validation.
        
        Args:
            endpoint: API endpoint to test
            method: HTTP method to use
            test_cases: List of test cases with input data and expected results
            auth: Authentication details (type, username, password, token, api_key)
            headers: Additional headers to include
            
        Returns:
            Dict: Test results for each test case
        """
        url = self._get_full_url(endpoint)
        
        if not test_cases:
            test_cases = [
                {
                    'name': 'empty_data',
                    'data': {},
                    'expected_status': 400
                },
                {
                    'name': 'invalid_json',
                    'raw_data': '{invalid json',
                    'expected_status': 400
                },
                {
                    'name': 'sql_injection',
                    'data': {'id': "' OR 1=1 --"},
                    'expected_status': 400
                },
                {
                    'name': 'xss_payload',
                    'data': {'name': '<script>alert(1)</script>'},
                    'expected_status': 400
                }
            ]
        
        self.logger.info(f"Testing API input validation at {url}")
        
        results = []
        
        # Prepare authentication
        auth_type = auth.get('type') if auth else None
        username = auth.get('username') if auth else None
        password = auth.get('password') if auth else None
        token = auth.get('token') if auth else None
        api_key = auth.get('api_key') if auth else None
        
        # Prepare headers with authentication
        request_headers = headers.copy() if headers else {}
        
        if auth_type == 'bearer' and token:
            request_headers['Authorization'] = f"Bearer {token}"
        elif auth_type == 'api_key' and api_key:
            request_headers['X-API-Key'] = api_key
        
        # Test each case
        for test_case in test_cases:
            test_name = test_case.get('name', 'unnamed_test')
            expected_status = test_case.get('expected_status')
            
            self.logger.info(f"Running test case: {test_name}")
            
            try:
                if auth_type == 'basic' and username and password:
                    auth_tuple = (username, password)
                else:
                    auth_tuple = None
                
                # Check if raw data is provided
                if 'raw_data' in test_case:
                    # Send raw data
                    raw_data = test_case['raw_data']
                    request_headers['Content-Type'] = 'application/json'
                    
                    response = self.session.request(
                        method=method,
                        url=url,
                        auth=auth_tuple,
                        headers=request_headers,
                        data=raw_data,
                        timeout=self.timeout
                    )
                else:
                    # Send JSON data
                    data = test_case.get('data', {})
                    
                    response = self.session.request(
                        method=method,
                        url=url,
                        auth=auth_tuple,
                        headers=request_headers,
                        json=data,
                        timeout=self.timeout
                    )
                
                # Check if response is valid JSON
                try:
                    response_json = response.json()
                    is_json = True
                except:
                    response_json = None
                    is_json = False
                
                # Check if response contains error messages
                error_messages = []
                if is_json and isinstance(response_json, dict):
                    for key in ['error', 'errors', 'message', 'messages']:
                        if key in response_json:
                            error_value = response_json[key]
                            if isinstance(error_value, str):
                                error_messages.append(error_value)
                            elif isinstance(error_value, list):
                                error_messages.extend([str(e) for e in error_value])
                            elif isinstance(error_value, dict):
                                for field, msg in error_value.items():
                                    if isinstance(msg, str):
                                        error_messages.append(f"{field}: {msg}")
                                    elif isinstance(msg, list):
                                        error_messages.extend([f"{field}: {e}" for e in msg])
                
                # Determine if validation passed
                validation_passed = False
                if expected_status:
                    validation_passed = response.status_code == expected_status
                else:
                    validation_passed = response.status_code in [400, 422] or error_messages
                
                results.append({
                    'test_name': test_name,
                    'status_code': response.status_code,
                    'expected_status': expected_status,
                    'response_size': len(response.content),
                    'elapsed_time': response.elapsed.total_seconds(),
                    'is_json': is_json,
                    'error_messages': error_messages,
                    'validation_passed': validation_passed
                })
                
            except Exception as e:
                self.logger.error(f"Error in test case {test_name}: {str(e)}")
                results.append({
                    'test_name': test_name,
                    'error': str(e)
                })
        
        # Count passed and failed tests
        passed_tests = sum(1 for r in results if r.get('validation_passed', False))
        
        return {
            'url': url,
            'method': method,
            'tests_count': len(results),
            'passed_tests': passed_tests,
            'failed_tests': len(results) - passed_tests,
            'results': results
        }
    
    def _get_full_url(self, endpoint: str) -> str:
        """
        Get full URL by combining base URL and endpoint.
        
        Args:
            endpoint: API endpoint
            
        Returns:
            str: Full URL
        """
        if self.base_url and not endpoint.startswith(('http://', 'https://')):
            # Remove leading slash from endpoint if present
            if endpoint.startswith('/'):
                endpoint = endpoint[1:]
            
            # Ensure base URL ends with slash
            base = self.base_url
            if not base.endswith('/'):
                base += '/'
            
            return f"{base}{endpoint}"
        
        return endpoint
    
    def close(self):
        """Close the session."""
        self.session.close()
        self.logger.info("API security tester session closed")
