"""
Web security scanner for security testing.
"""
import logging
import requests
import time
import re
import urllib.parse
from typing import Dict, Any, Optional, List, Union, Set

class WebSecurityScanner:
    """Class for scanning web applications for security vulnerabilities."""
    
    def __init__(self, base_url: str = None, timeout: int = 10):
        """
        Initialize the web security scanner.
        
        Args:
            base_url: Base URL of the web application
            timeout: Request timeout in seconds
        """
        self.base_url = base_url
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.visited_urls = set()
        self.found_forms = []
        self.found_inputs = []
    
    def scan_xss_vulnerabilities(
        self,
        urls: List[str] = None,
        max_urls: int = 10,
        crawl: bool = False,
        payloads: List[str] = None
    ) -> Dict[str, Any]:
        """
        Scan for XSS vulnerabilities.
        
        Args:
            urls: List of URLs to scan (if None, uses base_url)
            max_urls: Maximum number of URLs to scan
            crawl: Whether to crawl the website for more URLs
            payloads: List of XSS payloads to test
            
        Returns:
            Dict: Scan results with vulnerabilities found
        """
        self.logger.info("Starting XSS vulnerability scan")
        
        # Use default payloads if none provided
        if not payloads:
            payloads = [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '"><svg/onload=alert(1)>',
                "';alert(1);//",
                '<img src=x onerror=alert(1)>',
                '<body onload=alert(1)>',
                '<svg onload=alert(1)>',
                '<iframe src="javascript:alert(1)"></iframe>'
            ]
        
        # Initialize URLs to scan
        urls_to_scan = []
        if urls:
            urls_to_scan = urls[:max_urls]
        elif self.base_url:
            urls_to_scan = [self.base_url]
        else:
            return {
                'success': False,
                'error': "No URLs provided and no base URL set"
            }
        
        # Crawl for more URLs if requested
        if crawl:
            discovered_urls = self._crawl_website(urls_to_scan[0], max_urls)
            urls_to_scan.extend(discovered_urls)
            urls_to_scan = list(set(urls_to_scan))[:max_urls]  # Remove duplicates and limit
        
        vulnerabilities = []
        
        # Scan each URL
        for url in urls_to_scan:
            self.logger.info(f"Scanning URL for XSS: {url}")
            
            # Get forms on the page
            forms = self._get_forms(url)
            
            # Test each form
            for form in forms:
                form_url = form.get('action', url)
                form_method = form.get('method', 'GET')
                
                # Test each input in the form
                for input_field in form.get('inputs', []):
                    input_name = input_field.get('name')
                    if not input_name:
                        continue
                    
                    # Test each payload
                    for payload in payloads:
                        # Create form data with payload
                        form_data = {}
                        for field in form.get('inputs', []):
                            field_name = field.get('name')
                            if field_name:
                                if field_name == input_name:
                                    form_data[field_name] = payload
                                else:
                                    form_data[field_name] = field.get('value', '')
                        
                        # Submit form
                        try:
                            if form_method.upper() == 'GET':
                                response = self.session.get(
                                    form_url,
                                    params=form_data,
                                    timeout=self.timeout,
                                    allow_redirects=True
                                )
                            else:
                                response = self.session.post(
                                    form_url,
                                    data=form_data,
                                    timeout=self.timeout,
                                    allow_redirects=True
                                )
                            
                            # Check if payload is reflected
                            if payload in response.text:
                                vulnerabilities.append({
                                    'url': url,
                                    'form_url': form_url,
                                    'form_method': form_method,
                                    'input_name': input_name,
                                    'payload': payload,
                                    'reflected': True
                                })
                                
                                self.logger.warning(f"Potential XSS vulnerability found: {url}, {input_name}, {payload}")
                                
                                # No need to test more payloads for this input
                                break
                                
                        except Exception as e:
                            self.logger.error(f"Error testing XSS payload: {str(e)}")
            
            # Also test URL parameters
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                for param_name, param_values in query_params.items():
                    # Test each payload
                    for payload in payloads:
                        # Create query parameters with payload
                        new_params = query_params.copy()
                        new_params[param_name] = [payload]
                        
                        # Build new query string
                        new_query = urllib.parse.urlencode(new_params, doseq=True)
                        
                        # Build new URL
                        new_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment
                        ))
                        
                        # Send request
                        try:
                            response = self.session.get(
                                new_url,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                            
                            # Check if payload is reflected
                            if payload in response.text:
                                vulnerabilities.append({
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'reflected': True
                                })
                                
                                self.logger.warning(f"Potential XSS vulnerability found: {url}, {param_name}, {payload}")
                                
                                # No need to test more payloads for this parameter
                                break
                                
                        except Exception as e:
                            self.logger.error(f"Error testing XSS payload: {str(e)}")
        
        return {
            'success': True,
            'vulnerabilities_found': len(vulnerabilities) > 0,
            'vulnerability_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'urls_scanned': len(urls_to_scan),
            'forms_tested': len(self.found_forms),
            'inputs_tested': len(self.found_inputs)
        }
    
    def scan_sql_injection(
        self,
        urls: List[str] = None,
        max_urls: int = 10,
        crawl: bool = False,
        payloads: List[str] = None
    ) -> Dict[str, Any]:
        """
        Scan for SQL injection vulnerabilities.
        
        Args:
            urls: List of URLs to scan (if None, uses base_url)
            max_urls: Maximum number of URLs to scan
            crawl: Whether to crawl the website for more URLs
            payloads: List of SQL injection payloads to test
            
        Returns:
            Dict: Scan results with vulnerabilities found
        """
        self.logger.info("Starting SQL injection vulnerability scan")
        
        # Use default payloads if none provided
        if not payloads:
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR 1=1 --",
                "' OR 1=1#",
                "' OR 1=1/*",
                "') OR ('1'='1",
                "')) OR (('1'='1",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' UNION SELECT 1,2,3 --",
                "' UNION SELECT 1,2,3#",
                "' UNION SELECT 1,2,3/*",
                "'; WAITFOR DELAY '0:0:5' --"
            ]
        
        # Initialize URLs to scan
        urls_to_scan = []
        if urls:
            urls_to_scan = urls[:max_urls]
        elif self.base_url:
            urls_to_scan = [self.base_url]
        else:
            return {
                'success': False,
                'error': "No URLs provided and no base URL set"
            }
        
        # Crawl for more URLs if requested
        if crawl:
            discovered_urls = self._crawl_website(urls_to_scan[0], max_urls)
            urls_to_scan.extend(discovered_urls)
            urls_to_scan = list(set(urls_to_scan))[:max_urls]  # Remove duplicates and limit
        
        vulnerabilities = []
        
        # Scan each URL
        for url in urls_to_scan:
            self.logger.info(f"Scanning URL for SQL injection: {url}")
            
            # Get forms on the page
            forms = self._get_forms(url)
            
            # Test each form
            for form in forms:
                form_url = form.get('action', url)
                form_method = form.get('method', 'GET')
                
                # Test each input in the form
                for input_field in form.get('inputs', []):
                    input_name = input_field.get('name')
                    if not input_name:
                        continue
                    
                    # Test each payload
                    for payload in payloads:
                        # Create form data with payload
                        form_data = {}
                        for field in form.get('inputs', []):
                            field_name = field.get('name')
                            if field_name:
                                if field_name == input_name:
                                    form_data[field_name] = payload
                                else:
                                    form_data[field_name] = field.get('value', '')
                        
                        # Submit form
                        try:
                            start_time = time.time()
                            
                            if form_method.upper() == 'GET':
                                response = self.session.get(
                                    form_url,
                                    params=form_data,
                                    timeout=self.timeout,
                                    allow_redirects=True
                                )
                            else:
                                response = self.session.post(
                                    form_url,
                                    data=form_data,
                                    timeout=self.timeout,
                                    allow_redirects=True
                                )
                            
                            elapsed_time = time.time() - start_time
                            
                            # Check for SQL error messages
                            sql_errors = self._check_sql_errors(response.text)
                            
                            if sql_errors:
                                vulnerabilities.append({
                                    'url': url,
                                    'form_url': form_url,
                                    'form_method': form_method,
                                    'input_name': input_name,
                                    'payload': payload,
                                    'error_messages': sql_errors,
                                    'response_time': elapsed_time
                                })
                                
                                self.logger.warning(f"Potential SQL injection vulnerability found: {url}, {input_name}, {payload}")
                                
                                # No need to test more payloads for this input
                                break
                                
                        except Exception as e:
                            self.logger.error(f"Error testing SQL injection payload: {str(e)}")
            
            # Also test URL parameters
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                query_params = urllib.parse.parse_qs(parsed_url.query)
                
                for param_name, param_values in query_params.items():
                    # Test each payload
                    for payload in payloads:
                        # Create query parameters with payload
                        new_params = query_params.copy()
                        new_params[param_name] = [payload]
                        
                        # Build new query string
                        new_query = urllib.parse.urlencode(new_params, doseq=True)
                        
                        # Build new URL
                        new_url = urllib.parse.urlunparse((
                            parsed_url.scheme,
                            parsed_url.netloc,
                            parsed_url.path,
                            parsed_url.params,
                            new_query,
                            parsed_url.fragment
                        ))
                        
                        # Send request
                        try:
                            start_time = time.time()
                            
                            response = self.session.get(
                                new_url,
                                timeout=self.timeout,
                                allow_redirects=True
                            )
                            
                            elapsed_time = time.time() - start_time
                            
                            # Check for SQL error messages
                            sql_errors = self._check_sql_errors(response.text)
                            
                            if sql_errors:
                                vulnerabilities.append({
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'error_messages': sql_errors,
                                    'response_time': elapsed_time
                                })
                                
                                self.logger.warning(f"Potential SQL injection vulnerability found: {url}, {param_name}, {payload}")
                                
                                # No need to test more payloads for this parameter
                                break
                                
                        except Exception as e:
                            self.logger.error(f"Error testing SQL injection payload: {str(e)}")
        
        return {
            'success': True,
            'vulnerabilities_found': len(vulnerabilities) > 0,
            'vulnerability_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'urls_scanned': len(urls_to_scan),
            'forms_tested': len(self.found_forms),
            'inputs_tested': len(self.found_inputs)
        }
    
    def scan_csrf_vulnerabilities(
        self,
        urls: List[str] = None,
        max_urls: int = 10,
        crawl: bool = False
    ) -> Dict[str, Any]:
        """
        Scan for CSRF vulnerabilities.
        
        Args:
            urls: List of URLs to scan (if None, uses base_url)
            max_urls: Maximum number of URLs to scan
            crawl: Whether to crawl the website for more URLs
            
        Returns:
            Dict: Scan results with vulnerabilities found
        """
        self.logger.info("Starting CSRF vulnerability scan")
        
        # Initialize URLs to scan
        urls_to_scan = []
        if urls:
            urls_to_scan = urls[:max_urls]
        elif self.base_url:
            urls_to_scan = [self.base_url]
        else:
            return {
                'success': False,
                'error': "No URLs provided and no base URL set"
            }
        
        # Crawl for more URLs if requested
        if crawl:
            discovered_urls = self._crawl_website(urls_to_scan[0], max_urls)
            urls_to_scan.extend(discovered_urls)
            urls_to_scan = list(set(urls_to_scan))[:max_urls]  # Remove duplicates and limit
        
        vulnerabilities = []
        
        # Scan each URL
        for url in urls_to_scan:
            self.logger.info(f"Scanning URL for CSRF: {url}")
            
            # Get forms on the page
            forms = self._get_forms(url)
            
            # Check each form for CSRF tokens
            for form in forms:
                form_url = form.get('action', url)
                form_method = form.get('method', 'GET')
                
                # Skip GET forms (CSRF is primarily an issue for state-changing operations)
                if form_method.upper() == 'GET':
                    continue
                
                # Check for CSRF token
                has_csrf_token = False
                
                for input_field in form.get('inputs', []):
                    input_name = input_field.get('name', '').lower()
                    input_value = input_field.get('value', '')
                    
                    # Check if input name suggests it's a CSRF token
                    if any(token_name in input_name for token_name in ['csrf', 'token', 'nonce', 'xsrf']):
                        # Check if it has a non-empty value
                        if input_value:
                            has_csrf_token = True
                            break
                
                if not has_csrf_token:
                    vulnerabilities.append({
                        'url': url,
                        'form_url': form_url,
                        'form_method': form_method,
                        'form_id': form.get('id', ''),
                        'form_name': form.get('name', '')
                    })
                    
                    self.logger.warning(f"Potential CSRF vulnerability found: {url}, {form_url}")
        
        return {
            'success': True,
            'vulnerabilities_found': len(vulnerabilities) > 0,
            'vulnerability_count': len(vulnerabilities),
            'vulnerabilities': vulnerabilities,
            'urls_scanned': len(urls_to_scan),
            'forms_tested': len(self.found_forms)
        }
    
    def _crawl_website(self, start_url: str, max_urls: int) -> List[str]:
        """
        Crawl website to discover URLs.
        
        Args:
            start_url: URL to start crawling from
            max_urls: Maximum number of URLs to discover
            
        Returns:
            List[str]: List of discovered URLs
        """
        self.logger.info(f"Crawling website starting from {start_url}")
        
        discovered_urls = []
        urls_to_visit = [start_url]
        
        while urls_to_visit and len(discovered_urls) < max_urls:
            url = urls_to_visit.pop(0)
            
            if url in self.visited_urls:
                continue
            
            self.visited_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Extract base URL for resolving relative URLs
                    parsed_url = urllib.parse.urlparse(url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    
                    # Find all links
                    links = re.findall(r'href=[\'"]?([^\'" >]+)', response.text)
                    
                    for link in links:
                        # Resolve relative URLs
                        if link.startswith('/'):
                            link = f"{base_url}{link}"
                        elif not link.startswith(('http://', 'https://')):
                            link = f"{url.rstrip('/')}/{link.lstrip('/')}"
                        
                        # Skip non-HTTP URLs
                        if not link.startswith(('http://', 'https://')):
                            continue
                        
                        # Skip URLs from different domains
                        if base_url not in link:
                            continue
                        
                        # Skip already visited URLs
                        if link in self.visited_urls:
                            continue
                        
                        # Skip URLs with fragments
                        link = link.split('#')[0]
                        
                        # Add to discovered URLs and URLs to visit
                        if link not in discovered_urls:
                            discovered_urls.append(link)
                            urls_to_visit.append(link)
                            
                            if len(discovered_urls) >= max_urls:
                                break
            
            except Exception as e:
                self.logger.error(f"Error crawling URL {url}: {str(e)}")
        
        self.logger.info(f"Crawling complete, discovered {len(discovered_urls)} URLs")
        return discovered_urls
    
    def _get_forms(self, url: str) -> List[Dict[str, Any]]:
        """
        Get forms from a web page.
        
        Args:
            url: URL of the web page
            
        Returns:
            List[Dict]: List of forms with their details
        """
        forms = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Extract forms
                form_regex = r'<form.*?</form>'
                form_matches = re.findall(form_regex, response.text, re.DOTALL)
                
                for form_html in form_matches:
                    form = {}
                    
                    # Extract form attributes
                    action_match = re.search(r'action=[\'"]?([^\'" >]+)', form_html)
                    method_match = re.search(r'method=[\'"]?([^\'" >]+)', form_html)
                    id_match = re.search(r'id=[\'"]?([^\'" >]+)', form_html)
                    name_match = re.search(r'name=[\'"]?([^\'" >]+)', form_html)
                    
                    if action_match:
                        form['action'] = action_match.group(1)
                        
                        # Resolve relative URLs
                        if not form['action'].startswith(('http://', 'https://')):
                            parsed_url = urllib.parse.urlparse(url)
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            
                            if form['action'].startswith('/'):
                                form['action'] = f"{base_url}{form['action']}"
                            else:
                                form['action'] = f"{url.rstrip('/')}/{form['action'].lstrip('/')}"
                    else:
                        form['action'] = url
                    
                    if method_match:
                        form['method'] = method_match.group(1)
                    else:
                        form['method'] = 'GET'
                    
                    if id_match:
                        form['id'] = id_match.group(1)
                    
                    if name_match:
                        form['name'] = name_match.group(1)
                    
                    # Extract inputs
                    inputs = []
                    
                    # Extract regular inputs
                    input_regex = r'<input.*?>'
                    input_matches = re.findall(input_regex, form_html)
                    
                    for input_html in input_matches:
                        input_field = {}
                        
                        name_match = re.search(r'name=[\'"]?([^\'" >]+)', input_html)
                        type_match = re.search(r'type=[\'"]?([^\'" >]+)', input_html)
                        value_match = re.search(r'value=[\'"]?([^\'" >]+)', input_html)
                        
                        if name_match:
                            input_field['name'] = name_match.group(1)
                        
                        if type_match:
                            input_field['type'] = type_match.group(1)
                        else:
                            input_field['type'] = 'text'
                        
                        if value_match:
                            input_field['value'] = value_match.group(1)
                        
                        inputs.append(input_field)
                        self.found_inputs.append(input_field)
                    
                    # Extract textareas
                    textarea_regex = r'<textarea.*?name=[\'"]?([^\'" >]+)'
                    textarea_matches = re.findall(textarea_regex, form_html)
                    
                    for textarea_name in textarea_matches:
                        inputs.append({
                            'name': textarea_name,
                            'type': 'textarea'
                        })
                        self.found_inputs.append({
                            'name': textarea_name,
                            'type': 'textarea'
                        })
                    
                    # Extract selects
                    select_regex = r'<select.*?name=[\'"]?([^\'" >]+)'
                    select_matches = re.findall(select_regex, form_html)
                    
                    for select_name in select_matches:
                        inputs.append({
                            'name': select_name,
                            'type': 'select'
                        })
                        self.found_inputs.append({
                            'name': select_name,
                            'type': 'select'
                        })
                    
                    form['inputs'] = inputs
                    forms.append(form)
                    self.found_forms.append(form)
        
        except Exception as e:
            self.logger.error(f"Error getting forms from {url}: {str(e)}")
        
        return forms
    
    def _check_sql_errors(self, response_text: str) -> List[str]:
        """
        Check for SQL error messages in response.
        
        Args:
            response_text: Response text to check
            
        Returns:
            List[str]: List of SQL error messages found
        """
        sql_errors = []
        
        # Common SQL error patterns
        error_patterns = [
            r"SQL syntax.*?MySQL",
            r"Warning.*?mysqli",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that corresponds to your (MySQL|MariaDB) server version",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*?Driver",
            r"Warning.*?oci_.*?",
            r"Microsoft OLE DB Provider for ODBC Drivers error",
            r"ODBC SQL Server Driver",
            r"ODBC Error",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark after the character string",
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*?sqlite_.*?",
            r"Warning.*?SQLite3::",
            r"PostgreSQL.*?ERROR",
            r"Warning.*?pg_.*?",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
            r"ERROR:\s+syntax error at or near"
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                sql_errors.extend(matches)
        
        return sql_errors
    
    def close(self):
        """Close the session."""
        self.session.close()
        self.logger.info("Web security scanner session closed")
