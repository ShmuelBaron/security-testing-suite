"""
Authentication tester for security testing.
"""
import logging
import requests
import time
from typing import Dict, Any, Optional, List, Union

class AuthTester:
    """Class for testing authentication mechanisms."""
    
    def __init__(self, base_url: str = None, timeout: int = 10):
        """
        Initialize the authentication tester.
        
        Args:
            base_url: Base URL for authentication endpoints
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
    
    def test_login(
        self, 
        endpoint: str, 
        username: str, 
        password: str, 
        method: str = 'POST',
        username_field: str = 'username',
        password_field: str = 'password',
        headers: Optional[Dict[str, str]] = None,
        expected_status: int = 200,
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Test login functionality.
        
        Args:
            endpoint: Login endpoint
            username: Username to test
            password: Password to test
            method: HTTP method (default: POST)
            username_field: Field name for username
            password_field: Field name for password
            headers: Request headers
            expected_status: Expected status code for successful login
            success_indicators: Strings that indicate successful login in response
            failure_indicators: Strings that indicate failed login in response
            
        Returns:
            Dict: Test result with success status and details
        """
        url = self._get_full_url(endpoint)
        
        # Prepare request data
        data = {
            username_field: username,
            password_field: password
        }
        
        self.logger.info(f"Testing login at {url} with username: {username}")
        
        try:
            # Send login request
            start_time = time.time()
            response = self.session.request(
                method=method,
                url=url,
                data=data,
                headers=headers,
                timeout=self.timeout
            )
            elapsed_time = time.time() - start_time
            
            # Check status code
            status_match = response.status_code == expected_status
            
            # Check response content
            content_check = True
            if status_match:
                if success_indicators:
                    content_check = any(indicator in response.text for indicator in success_indicators)
                if failure_indicators:
                    content_check = not any(indicator in response.text for indicator in failure_indicators)
            
            # Determine success
            success = status_match and content_check
            
            result = {
                'success': success,
                'url': url,
                'username': username,
                'status_code': response.status_code,
                'expected_status': expected_status,
                'elapsed_time': elapsed_time,
                'response_size': len(response.content)
            }
            
            if success:
                self.logger.info(f"Login successful: {username}")
                # Extract cookies and tokens if available
                if response.cookies:
                    result['cookies'] = {k: v for k, v in response.cookies.items()}
                
                # Try to extract tokens from response
                try:
                    json_response = response.json()
                    if 'token' in json_response:
                        result['token'] = json_response['token']
                    elif 'access_token' in json_response:
                        result['token'] = json_response['access_token']
                except:
                    pass
            else:
                self.logger.warning(f"Login failed: {username}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Login test failed with error: {str(e)}")
            return {
                'success': False,
                'url': url,
                'username': username,
                'error': str(e)
            }
    
    def test_brute_force_protection(
        self,
        endpoint: str,
        username: str,
        password: str,
        method: str = 'POST',
        username_field: str = 'username',
        password_field: str = 'password',
        headers: Optional[Dict[str, str]] = None,
        attempts: int = 5,
        delay: float = 0.5
    ) -> Dict[str, Any]:
        """
        Test brute force protection.
        
        Args:
            endpoint: Login endpoint
            username: Username to test
            password: Wrong password to test
            method: HTTP method (default: POST)
            username_field: Field name for username
            password_field: Field name for password
            headers: Request headers
            attempts: Number of login attempts
            delay: Delay between attempts in seconds
            
        Returns:
            Dict: Test result with protection status and details
        """
        url = self._get_full_url(endpoint)
        
        self.logger.info(f"Testing brute force protection at {url} with username: {username}")
        
        results = []
        blocked = False
        
        for i in range(attempts):
            # Prepare request data
            data = {
                username_field: username,
                password_field: f"{password}_{i}"  # Use different password each time
            }
            
            try:
                # Send login request
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout=self.timeout
                )
                
                results.append({
                    'attempt': i + 1,
                    'status_code': response.status_code,
                    'response_size': len(response.content)
                })
                
                # Check if blocked (status code 429 or 403)
                if response.status_code in [429, 403]:
                    blocked = True
                    self.logger.info(f"Blocked after {i + 1} attempts")
                    break
                
                # Wait before next attempt
                if i < attempts - 1:
                    time.sleep(delay)
                    
            except Exception as e:
                self.logger.error(f"Attempt {i + 1} failed with error: {str(e)}")
                results.append({
                    'attempt': i + 1,
                    'error': str(e)
                })
        
        return {
            'protection_detected': blocked,
            'url': url,
            'username': username,
            'attempts': len(results),
            'results': results
        }
    
    def test_multi_factor_auth(
        self,
        login_endpoint: str,
        mfa_endpoint: str,
        username: str,
        password: str,
        mfa_code: str = '123456',
        method: str = 'POST',
        username_field: str = 'username',
        password_field: str = 'password',
        mfa_field: str = 'code',
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Test multi-factor authentication.
        
        Args:
            login_endpoint: Login endpoint
            mfa_endpoint: MFA verification endpoint
            username: Username to test
            password: Password to test
            mfa_code: MFA code to test
            method: HTTP method (default: POST)
            username_field: Field name for username
            password_field: Field name for password
            mfa_field: Field name for MFA code
            headers: Request headers
            
        Returns:
            Dict: Test result with MFA status and details
        """
        # First, test login
        login_result = self.test_login(
            endpoint=login_endpoint,
            username=username,
            password=password,
            method=method,
            username_field=username_field,
            password_field=password_field,
            headers=headers
        )
        
        if not login_result['success']:
            return {
                'mfa_enabled': False,
                'login_successful': False,
                'login_result': login_result
            }
        
        # Check if MFA is required
        mfa_url = self._get_full_url(mfa_endpoint)
        
        self.logger.info(f"Testing MFA at {mfa_url} for username: {username}")
        
        try:
            # Prepare MFA request
            mfa_data = {
                mfa_field: mfa_code
            }
            
            # Use cookies from login
            cookies = self.session.cookies
            
            # Send MFA request
            response = self.session.request(
                method=method,
                url=mfa_url,
                data=mfa_data,
                headers=headers,
                timeout=self.timeout
            )
            
            return {
                'mfa_enabled': True,
                'login_successful': True,
                'mfa_status_code': response.status_code,
                'mfa_response_size': len(response.content),
                'login_result': login_result
            }
            
        except Exception as e:
            self.logger.error(f"MFA test failed with error: {str(e)}")
            return {
                'mfa_enabled': True,
                'login_successful': True,
                'mfa_error': str(e),
                'login_result': login_result
            }
    
    def test_password_policy(
        self,
        endpoint: str,
        username: str,
        passwords: List[str],
        method: str = 'POST',
        username_field: str = 'username',
        password_field: str = 'password',
        headers: Optional[Dict[str, str]] = None,
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Test password policy.
        
        Args:
            endpoint: Registration or password change endpoint
            username: Username to test
            passwords: List of passwords to test (varying complexity)
            method: HTTP method (default: POST)
            username_field: Field name for username
            password_field: Field name for password
            headers: Request headers
            success_indicators: Strings that indicate successful password acceptance
            failure_indicators: Strings that indicate password rejection
            
        Returns:
            Dict: Test result with policy details
        """
        url = self._get_full_url(endpoint)
        
        self.logger.info(f"Testing password policy at {url}")
        
        results = []
        
        for password in passwords:
            # Prepare request data
            data = {
                username_field: username,
                password_field: password
            }
            
            try:
                # Send request
                response = self.session.request(
                    method=method,
                    url=url,
                    data=data,
                    headers=headers,
                    timeout=self.timeout
                )
                
                # Determine if password was accepted
                accepted = True
                
                if success_indicators:
                    accepted = any(indicator in response.text for indicator in success_indicators)
                
                if failure_indicators:
                    accepted = not any(indicator in response.text for indicator in failure_indicators)
                
                results.append({
                    'password': password,
                    'accepted': accepted,
                    'status_code': response.status_code,
                    'length': len(password),
                    'has_uppercase': any(c.isupper() for c in password),
                    'has_lowercase': any(c.islower() for c in password),
                    'has_digit': any(c.isdigit() for c in password),
                    'has_special': any(not c.isalnum() for c in password)
                })
                
            except Exception as e:
                self.logger.error(f"Password test failed with error: {str(e)}")
                results.append({
                    'password': password,
                    'error': str(e)
                })
        
        # Analyze results to determine policy
        accepted_passwords = [r for r in results if r.get('accepted', False)]
        rejected_passwords = [r for r in results if not r.get('accepted', False) and 'error' not in r]
        
        policy = {}
        
        if accepted_passwords:
            policy['min_length'] = min(r['length'] for r in accepted_passwords)
            policy['requires_uppercase'] = all(r['has_uppercase'] for r in accepted_passwords)
            policy['requires_lowercase'] = all(r['has_lowercase'] for r in accepted_passwords)
            policy['requires_digit'] = all(r['has_digit'] for r in accepted_passwords)
            policy['requires_special'] = all(r['has_special'] for r in accepted_passwords)
        
        return {
            'url': url,
            'username': username,
            'policy': policy,
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
        self.logger.info("Authentication tester session closed")
