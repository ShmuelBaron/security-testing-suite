"""
VPN connection tester for security testing.
"""
import logging
import subprocess
import time
import os
import re
import platform
from typing import Dict, Any, Optional, List, Union

class VpnTester:
    """Class for testing VPN connections and security."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize the VPN tester.
        
        Args:
            config_dir: Directory containing VPN configuration files
        """
        self.config_dir = config_dir
        self.logger = logging.getLogger(__name__)
        self.current_connection = None
    
    def test_connection(
        self,
        vpn_type: str,
        server: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        config_file: Optional[str] = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Test VPN connection.
        
        Args:
            vpn_type: Type of VPN (openvpn, l2tp, pptp, wireguard)
            server: VPN server address
            username: VPN username (if required)
            password: VPN password (if required)
            config_file: Path to VPN configuration file
            timeout: Connection timeout in seconds
            
        Returns:
            Dict: Test result with connection status and details
        """
        self.logger.info(f"Testing {vpn_type} VPN connection to {server}")
        
        # Close any existing connection
        if self.current_connection:
            self.disconnect()
        
        # Resolve config file path
        if config_file and not os.path.isabs(config_file) and self.config_dir:
            config_file = os.path.join(self.config_dir, config_file)
        
        # Get pre-connection IP and DNS
        pre_ip = self._get_public_ip()
        pre_dns = self._get_dns_servers()
        
        # Connect to VPN based on type
        if vpn_type.lower() == 'openvpn':
            result = self._connect_openvpn(server, username, password, config_file, timeout)
        elif vpn_type.lower() == 'wireguard':
            result = self._connect_wireguard(config_file, timeout)
        elif vpn_type.lower() == 'l2tp':
            result = self._connect_l2tp(server, username, password, timeout)
        elif vpn_type.lower() == 'pptp':
            result = self._connect_pptp(server, username, password, timeout)
        else:
            return {
                'success': False,
                'error': f"Unsupported VPN type: {vpn_type}"
            }
        
        # If connection failed, return result
        if not result.get('success', False):
            return result
        
        # Get post-connection IP and DNS
        post_ip = self._get_public_ip()
        post_dns = self._get_dns_servers()
        
        # Update result with IP and DNS changes
        result.update({
            'ip_changed': pre_ip != post_ip,
            'pre_connection_ip': pre_ip,
            'post_connection_ip': post_ip,
            'dns_changed': pre_dns != post_dns,
            'pre_connection_dns': pre_dns,
            'post_connection_dns': post_dns
        })
        
        # Set current connection
        self.current_connection = {
            'vpn_type': vpn_type,
            'server': server,
            'process': result.get('process')
        }
        
        return result
    
    def test_dns_leak(self, queries: int = 5, timeout: int = 30) -> Dict[str, Any]:
        """
        Test for DNS leaks when connected to VPN.
        
        Args:
            queries: Number of DNS queries to perform
            timeout: Test timeout in seconds
            
        Returns:
            Dict: Test result with leak status and details
        """
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to VPN"
            }
        
        self.logger.info("Testing for DNS leaks")
        
        # List of DNS leak testing services
        dns_leak_services = [
            'dnsleaktest.com',
            'ipleak.net',
            'dnsleak.com',
            'perfect-privacy.com/dns-leaktest'
        ]
        
        results = []
        
        for _ in range(queries):
            # Choose a random service
            import random
            service = random.choice(dns_leak_services)
            
            # Perform DNS lookup
            try:
                import socket
                start_time = time.time()
                ip = socket.gethostbyname(service)
                elapsed_time = time.time() - start_time
                
                results.append({
                    'service': service,
                    'resolved_ip': ip,
                    'elapsed_time': elapsed_time
                })
                
                # Small delay between queries
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.error(f"DNS lookup failed: {str(e)}")
                results.append({
                    'service': service,
                    'error': str(e)
                })
        
        # Analyze results for potential leaks
        unique_ips = set(r.get('resolved_ip') for r in results if 'resolved_ip' in r)
        
        return {
            'success': True,
            'potential_leak': len(unique_ips) > 1,
            'unique_resolvers': len(unique_ips),
            'results': results
        }
    
    def test_ip_leak(self, websites: int = 3, timeout: int = 60) -> Dict[str, Any]:
        """
        Test for IP leaks when connected to VPN.
        
        Args:
            websites: Number of IP checking websites to use
            timeout: Test timeout in seconds
            
        Returns:
            Dict: Test result with leak status and details
        """
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to VPN"
            }
        
        self.logger.info("Testing for IP leaks")
        
        # List of IP checking services
        ip_check_services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://api.myip.com',
            'https://ipinfo.io/ip',
            'https://checkip.amazonaws.com'
        ]
        
        # Limit to requested number of services
        import random
        selected_services = random.sample(ip_check_services, min(websites, len(ip_check_services)))
        
        results = []
        
        for service in selected_services:
            try:
                import requests
                start_time = time.time()
                response = requests.get(service, timeout=10)
                elapsed_time = time.time() - start_time
                
                if response.status_code == 200:
                    ip = response.text.strip()
                    results.append({
                        'service': service,
                        'reported_ip': ip,
                        'elapsed_time': elapsed_time
                    })
                else:
                    results.append({
                        'service': service,
                        'error': f"HTTP {response.status_code}"
                    })
                
                # Small delay between requests
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"IP check failed: {str(e)}")
                results.append({
                    'service': service,
                    'error': str(e)
                })
        
        # Analyze results for potential leaks
        unique_ips = set(r.get('reported_ip') for r in results if 'reported_ip' in r)
        
        return {
            'success': True,
            'potential_leak': len(unique_ips) > 1,
            'unique_ips': len(unique_ips),
            'results': results
        }
    
    def test_kill_switch(self, disconnect_method: str = 'normal') -> Dict[str, Any]:
        """
        Test VPN kill switch functionality.
        
        Args:
            disconnect_method: Method to disconnect VPN ('normal', 'force', 'network')
            
        Returns:
            Dict: Test result with kill switch status and details
        """
        if not self.current_connection:
            return {
                'success': False,
                'error': "Not connected to VPN"
            }
        
        self.logger.info(f"Testing VPN kill switch using {disconnect_method} disconnect")
        
        # Get IP while connected
        vpn_ip = self._get_public_ip()
        
        # Disconnect VPN based on method
        if disconnect_method == 'normal':
            self.disconnect()
        elif disconnect_method == 'force':
            self._force_disconnect()
        elif disconnect_method == 'network':
            self._simulate_network_failure()
        else:
            return {
                'success': False,
                'error': f"Unsupported disconnect method: {disconnect_method}"
            }
        
        # Check if we can still access the internet
        internet_access = self._check_internet_access()
        
        # Get new IP if possible
        new_ip = None
        if internet_access:
            new_ip = self._get_public_ip()
        
        # Determine if kill switch is working
        kill_switch_active = not internet_access
        
        return {
            'success': True,
            'kill_switch_active': kill_switch_active,
            'internet_access_after_disconnect': internet_access,
            'vpn_ip': vpn_ip,
            'new_ip': new_ip,
            'ip_changed': vpn_ip != new_ip if new_ip else None,
            'disconnect_method': disconnect_method
        }
    
    def disconnect(self) -> Dict[str, Any]:
        """
        Disconnect from VPN.
        
        Returns:
            Dict: Result of disconnect operation
        """
        if not self.current_connection:
            return {
                'success': True,
                'message': "Not connected to VPN"
            }
        
        vpn_type = self.current_connection.get('vpn_type')
        process = self.current_connection.get('process')
        
        self.logger.info(f"Disconnecting from {vpn_type} VPN")
        
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        
        # Additional cleanup based on VPN type
        if vpn_type.lower() == 'openvpn':
            self._cleanup_openvpn()
        elif vpn_type.lower() == 'wireguard':
            self._cleanup_wireguard()
        elif vpn_type.lower() in ['l2tp', 'pptp']:
            self._cleanup_native_vpn()
        
        self.current_connection = None
        
        return {
            'success': True,
            'message': f"Disconnected from {vpn_type} VPN"
        }
    
    def _connect_openvpn(
        self,
        server: str,
        username: Optional[str],
        password: Optional[str],
        config_file: Optional[str],
        timeout: int
    ) -> Dict[str, Any]:
        """
        Connect to OpenVPN server.
        
        Args:
            server: OpenVPN server address
            username: OpenVPN username
            password: OpenVPN password
            config_file: Path to OpenVPN configuration file
            timeout: Connection timeout in seconds
            
        Returns:
            Dict: Connection result
        """
        # Check if OpenVPN is installed
        if not self._check_command('openvpn'):
            return {
                'success': False,
                'error': "OpenVPN not installed"
            }
        
        # Prepare command
        cmd = ['openvpn']
        
        if config_file:
            cmd.extend(['--config', config_file])
        else:
            cmd.extend(['--remote', server])
            cmd.extend(['--dev', 'tun'])
            cmd.extend(['--proto', 'udp'])
        
        # Add authentication if provided
        if username and password:
            auth_file = self._create_temp_auth_file(username, password)
            cmd.extend(['--auth-user-pass', auth_file])
        
        # Run OpenVPN
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for connection or timeout
            start_time = time.time()
            connected = False
            error = None
            
            while time.time() - start_time < timeout:
                if process.poll() is not None:
                    # Process exited
                    stdout, stderr = process.communicate()
                    error = stderr or stdout
                    break
                
                # Check if connected
                stdout = process.stdout.readline()
                if 'Initialization Sequence Completed' in stdout:
                    connected = True
                    break
                
                time.sleep(0.1)
            
            if connected:
                return {
                    'success': True,
                    'vpn_type': 'openvpn',
                    'server': server,
                    'process': process
                }
            else:
                if process.poll() is None:
                    process.terminate()
                
                return {
                    'success': False,
                    'error': error or "Connection timeout"
                }
                
        except Exception as e:
            self.logger.error(f"OpenVPN connection failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _connect_wireguard(self, config_file: str, timeout: int) -> Dict[str, Any]:
        """
        Connect to WireGuard server.
        
        Args:
            config_file: Path to WireGuard configuration file
            timeout: Connection timeout in seconds
            
        Returns:
            Dict: Connection result
        """
        # Check if WireGuard is installed
        if not self._check_command('wg-quick'):
            return {
                'success': False,
                'error': "WireGuard not installed"
            }
        
        if not config_file:
            return {
                'success': False,
                'error': "WireGuard configuration file required"
            }
        
        # Extract interface name from config
        interface = 'wg0'  # Default
        try:
            with open(config_file, 'r') as f:
                for line in f:
                    if line.strip().startswith('[Interface]'):
                        for i in range(10):  # Read next few lines
                            line = f.readline()
                            if line.startswith('Name ='):
                                interface = line.split('=')[1].strip()
                                break
        except Exception as e:
            self.logger.warning(f"Could not extract interface name: {str(e)}")
        
        # Run WireGuard
        try:
            process = subprocess.Popen(
                ['wg-quick', 'up', config_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for connection or timeout
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                # Create a dummy process to track connection
                dummy_process = subprocess.Popen(
                    ['sleep', '86400'],  # Sleep for a day
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                return {
                    'success': True,
                    'vpn_type': 'wireguard',
                    'interface': interface,
                    'process': dummy_process,
                    'config_file': config_file
                }
            else:
                return {
                    'success': False,
                    'error': stderr or "WireGuard connection failed"
                }
                
        except Exception as e:
            self.logger.error(f"WireGuard connection failed: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _connect_l2tp(
        self,
        server: str,
        username: Optional[str],
        password: Optional[str],
        timeout: int
    ) -> Dict[str, Any]:
        """
        Connect to L2TP/IPsec server.
        
        Args:
            server: L2TP server address
            username: L2TP username
            password: L2TP password
            timeout: Connection timeout in seconds
            
        Returns:
            Dict: Connection result
        """
        # This is a simplified implementation
        # In a real scenario, you would use platform-specific methods
        
        system = platform.system()
        
        if system == 'Linux':
            return self._connect_l2tp_linux(server, username, password, timeout)
        elif system == 'Darwin':  # macOS
            return self._connect_l2tp_macos(server, username, password, timeout)
        elif system == 'Windows':
            return self._connect_l2tp_windows(server, username, password, timeout)
        else:
            return {
                'success': False,
                'error': f"L2TP connection not implemented for {system}"
            }
    
    def _connect_pptp(
        self,
        server: str,
        username: Optional[str],
        password: Optional[str],
        timeout: int
    ) -> Dict[str, Any]:
        """
        Connect to PPTP server.
        
        Args:
            server: PPTP server address
            username: PPTP username
            password: PPTP password
            timeout: Connection timeout in seconds
            
        Returns:
            Dict: Connection result
        """
        # This is a simplified implementation
        # In a real scenario, you would use platform-specific methods
        
        system = platform.system()
        
        if system == 'Linux':
            return self._connect_pptp_linux(server, username, password, timeout)
        elif system == 'Darwin':  # macOS
            return self._connect_pptp_macos(server, username, password, timeout)
        elif system == 'Windows':
            return self._connect_pptp_windows(server, username, password, timeout)
        else:
            return {
                'success': False,
                'error': f"PPTP connection not implemented for {system}"
            }
    
    def _get_public_ip(self) -> Optional[str]:
        """
        Get public IP address.
        
        Returns:
            str or None: Public IP address or None if failed
        """
        try:
            import requests
            response = requests.get('https://api.ipify.org', timeout=10)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        
        try:
            response = requests.get('https://ifconfig.me/ip', timeout=10)
            if response.status_code == 200:
                return response.text.strip()
        except:
            pass
        
        return None
    
    def _get_dns_servers(self) -> List[str]:
        """
        Get current DNS servers.
        
        Returns:
            List[str]: List of DNS server IP addresses
        """
        dns_servers = []
        system = platform.system()
        
        if system == 'Linux':
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            dns_servers.append(line.split()[1])
            except:
                pass
        elif system == 'Darwin':  # macOS
            try:
                output = subprocess.check_output(['scutil', '--dns'], text=True)
                for line in output.splitlines():
                    if 'nameserver' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            dns_servers.append(parts[1].strip())
            except:
                pass
        elif system == 'Windows':
            try:
                output = subprocess.check_output(['ipconfig', '/all'], text=True)
                for line in output.splitlines():
                    if 'DNS Servers' in line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            dns_servers.append(parts[1].strip())
            except:
                pass
        
        return dns_servers
    
    def _check_internet_access(self) -> bool:
        """
        Check if internet is accessible.
        
        Returns:
            bool: True if internet is accessible, False otherwise
        """
        try:
            import requests
            response = requests.get('https://www.google.com', timeout=5)
            return response.status_code == 200
        except:
            pass
        
        try:
            response = requests.get('https://www.cloudflare.com', timeout=5)
            return response.status_code == 200
        except:
            pass
        
        return False
    
    def _force_disconnect(self) -> None:
        """Force disconnect VPN by killing the process."""
        if not self.current_connection:
            return
        
        process = self.current_connection.get('process')
        if process:
            try:
                process.kill()
            except:
                pass
    
    def _simulate_network_failure(self) -> None:
        """Simulate network failure by temporarily disabling network interface."""
        # This is a simplified implementation
        # In a real scenario, you would use platform-specific methods to disable networking
        
        system = platform.system()
        
        if system == 'Linux':
            try:
                # Find the main interface
                output = subprocess.check_output(['ip', 'route', 'get', '8.8.8.8'], text=True)
                match = re.search(r'dev\s+(\w+)', output)
                if match:
                    interface = match.group(1)
                    # Disable interface
                    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'down'])
                    time.sleep(2)
                    # Enable interface
                    subprocess.run(['sudo', 'ip', 'link', 'set', interface, 'up'])
            except:
                pass
        elif system == 'Darwin':  # macOS
            try:
                # Find the main interface
                output = subprocess.check_output(['route', '-n', 'get', '8.8.8.8'], text=True)
                match = re.search(r'interface:\s+(\w+)', output)
                if match:
                    interface = match.group(1)
                    # Disable interface
                    subprocess.run(['sudo', 'ifconfig', interface, 'down'])
                    time.sleep(2)
                    # Enable interface
                    subprocess.run(['sudo', 'ifconfig', interface, 'up'])
            except:
                pass
        elif system == 'Windows':
            try:
                # Find the main interface
                output = subprocess.check_output(['netsh', 'interface', 'show', 'interface'], text=True)
                lines = output.splitlines()
                for line in lines:
                    if 'Connected' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            interface = parts[3]
                            # Disable interface
                            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'disable'])
                            time.sleep(2)
                            # Enable interface
                            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'enable'])
                            break
            except:
                pass
    
    def _cleanup_openvpn(self) -> None:
        """Clean up OpenVPN connection."""
        try:
            # Kill any remaining OpenVPN processes
            subprocess.run(['pkill', '-f', 'openvpn'], stderr=subprocess.DEVNULL)
        except:
            pass
    
    def _cleanup_wireguard(self) -> None:
        """Clean up WireGuard connection."""
        if not self.current_connection:
            return
        
        config_file = self.current_connection.get('config_file')
        if config_file:
            try:
                subprocess.run(['wg-quick', 'down', config_file], stderr=subprocess.DEVNULL)
            except:
                pass
    
    def _cleanup_native_vpn(self) -> None:
        """Clean up native VPN connection."""
        # This is a simplified implementation
        # In a real scenario, you would use platform-specific methods
        
        system = platform.system()
        
        if system == 'Linux':
            try:
                subprocess.run(['sudo', 'pkill', '-f', 'pppd'], stderr=subprocess.DEVNULL)
            except:
                pass
        elif system == 'Darwin':  # macOS
            try:
                # Find and disconnect VPN service
                output = subprocess.check_output(['networksetup', '-listallnetworkservices'], text=True)
                for line in output.splitlines():
                    if 'VPN' in line:
                        subprocess.run(['networksetup', '-disconnectpppoeservice', line.strip()], stderr=subprocess.DEVNULL)
            except:
                pass
        elif system == 'Windows':
            try:
                subprocess.run(['rasdial', '/disconnect'], stderr=subprocess.DEVNULL)
            except:
                pass
    
    def _create_temp_auth_file(self, username: str, password: str) -> str:
        """
        Create temporary file with VPN credentials.
        
        Args:
            username: VPN username
            password: VPN password
            
        Returns:
            str: Path to temporary auth file
        """
        import tempfile
        
        fd, path = tempfile.mkstemp(text=True)
        with os.fdopen(fd, 'w') as f:
            f.write(f"{username}\n{password}\n")
        
        return path
    
    def _check_command(self, command: str) -> bool:
        """
        Check if command is available.
        
        Args:
            command: Command to check
            
        Returns:
            bool: True if command is available, False otherwise
        """
        try:
            subprocess.run(['which', command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False
    
    # Platform-specific connection methods (simplified)
    
    def _connect_l2tp_linux(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "L2TP connection on Linux requires specific configuration"
        }
    
    def _connect_l2tp_macos(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "L2TP connection on macOS requires specific configuration"
        }
    
    def _connect_l2tp_windows(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "L2TP connection on Windows requires specific configuration"
        }
    
    def _connect_pptp_linux(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "PPTP connection on Linux requires specific configuration"
        }
    
    def _connect_pptp_macos(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "PPTP connection on macOS requires specific configuration"
        }
    
    def _connect_pptp_windows(self, server, username, password, timeout):
        return {
            'success': False,
            'error': "PPTP connection on Windows requires specific configuration"
        }
