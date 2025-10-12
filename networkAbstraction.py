import os
import httpx
import base64
import asyncio
import asyncssh
from typing import List, Dict, Union, Optional, Any, Literal
from dotenv import load_dotenv


# Load dotenv variables
load_dotenv()

class SSHCredentials:
    """Manage SSH credentials loaded from a .env file.

    Attributes:
        credentials (List[Dict]): List of credential dicts with keys 'username',
            'password' and 'key_file'.

    Notes:
        This class reads up to 3 credential sets from environment variables:
        SSH_USER_1/SSH_PASS_1/SSH_KEY_1 ... SSH_USER_3/SSH_PASS_3/SSH_KEY_3.
    """
    
    def __init__(self):
        self.credentials = []
        
        # Load up to 3 sets of credentials
        for i in range(1, 4):
            username = os.getenv(f'SSH_USER_{i}')
            password = os.getenv(f'SSH_PASS_{i}')
            key_file = os.getenv(f'SSH_KEY_{i}')
            
            if username and (password or key_file):
                self.credentials.append({
                    'username': username,
                    'password': password,
                    'key_file': key_file
                })
        
        if not self.credentials:
            raise ValueError("No SSH credentials found in .env file")
    
    def get_credentials(self):
        """Return the list of credentials.

        Returns:
            List[Dict]: The list of credential dictionaries.
        """
        return self.credentials

async def _try_ssh_connection(
    host: str,
    port: int,
    credentials_list: List[Dict],
    timeout: int    
) -> Union[asyncssh.SSHClientConnection, Dict]:
    """Attempt SSH connection iterating over provided credentials.

    Tries each credential set until a connection succeeds or all fail.

    Args:
        host (str): Remote host IP or hostname.
        port (int): SSH port.
        credentials_list (List[Dict]): List of credential dicts to try.
        timeout (int): Connection timeout in seconds.

    Returns:
        Tuple[asyncssh.SSHClientConnection, Dict]: Established connection and the
        credential dict that succeeded.

    Raises:
        Exception: If all credential attempts fail (raises last encountered error).
    """
    last_error = None
    for creds in credentials_list:
        try:
            conn = await asyncssh.connect(
                host,
                port=port,
                username=creds['username'],
                password=creds['password'],
                client_keys=[creds['key_file']] if creds['key_file'] else None,
                known_hosts=None,
                connect_timeout=timeout
            )
            return conn, creds
        except Exception as e:
            last_error = e
            continue
    raise Exception(f"Last error: {str(last_error)}")

async def ssh_exec_single(
    host: str,
    command: str,
    port: int = 22,
    timeout: int = 30
) -> Dict[str, Union[str, dict]]:
    """Execute a single SSH command with automatic credential discovery.

    The function will automatically load credentials from .env file and attempt
    to connect using each credential set until one succeeds.

    Args:
        host (str): Target host IP or hostname.
        command (str): Command to execute on the remote host.
        port (int, optional): SSH port. Defaults to 22.
        timeout (int, optional): Command and connection timeout in seconds.
            Defaults to 30.

    Returns:
        Dict[str, Union[str, dict]]: Dictionary with keys:
            'output' (str): Command stdout or stderr.
            'credentials_used' (dict): The credential info used (username and auth method).

    Raises:
        Exception: If SSH connection or execution fails.
    """
    credentials = SSHCredentials()

    try:
        conn, creds_used = await _try_ssh_connection(
            host, port, credentials.get_credentials(), timeout
        )
        
        async with conn:
            result = await conn.run(command, check=False, timeout=timeout)
            output = result.stdout if result.stdout else result.stderr
            
            return {
                'output': output,
                'credentials_used': {
                    'username': creds_used['username'],
                    'auth_method': 'key' if creds_used['key_file'] else 'password'
                }
            }
    except Exception as e:
        raise Exception(f"SSH Error: {str(e)}")

async def ssh_exec_multiple(
    host: str,
    commands: List[str],
    port: int = 22,
    timeout: int = 30,
    return_type: str = 'dict'
) -> Dict[str, Union[Dict, List, dict]]:
    """Execute multiple SSH commands in the same session with automatic credential discovery.

    Opens one SSH session, runs each command sequentially and collects outputs.
    Credentials are automatically loaded from .env file.

    Args:
        host (str): Target host IP or hostname.
        commands (List[str]): List of commands to execute.
        port (int, optional): SSH port. Defaults to 22.
        timeout (int, optional): Timeout per command in seconds. Defaults to 30.
        return_type (str, optional): 'dict' to return {command: output} or 'list'
            to return a list of outputs in order. Defaults to 'dict'.

    Returns:
        Dict[str, Union[Dict, List, dict]]: {
            'outputs': dict or list with outputs,
            'credentials_used': credential summary that worked
        }

    Raises:
        Exception: If all connection attempts fail or command execution errors.
    """
    credentials = SSHCredentials()
    
    try:
        conn, creds_used = await _try_ssh_connection(
            host, port, credentials.get_credentials(), timeout
        )
        
        async with conn:
            outputs = {}
            outputs_list = []
            
            for cmd in commands:
                result = await conn.run(cmd, check=False, timeout=timeout)
                output = result.stdout if result.stdout else result.stderr
                
                outputs[cmd] = output
                outputs_list.append(output)
            
            return {
                'outputs': outputs if return_type == 'dict' else outputs_list,
                'credentials_used': {
                    'username': creds_used['username'],
                    'auth_method': 'key' if creds_used['key_file'] else 'password'
                }
            }
    except Exception as e:
        raise Exception(f"SSH Error: {str(e)}")

# Synchronous wrapper functions
def wrapper_async_ssh_single_command(
    host: str,
    command: str,
    port: int = 22,
    timeout: int = 30
) -> Dict[str, Union[str, dict]]:
    """Synchronous wrapper for ssh_exec_single.

    Args:
        host (str): Target host IP or hostname.
        command (str): Command to execute.
        port (int, optional): SSH port. Defaults to 22.
        timeout (int, optional): Timeout in seconds. Defaults to 30.

    Returns:
        Dict[str, Union[str, dict]]: Result returned by ssh_exec_single.
    """
    return asyncio.run(ssh_exec_single(host, command, port, timeout))

def wrapper_async_ssh_multiple_commands(
    host: str,
    commands: List[str],
    port: int = 22,
    timeout: int = 30,
    return_type: str = 'dict'
) -> Dict[str, Union[Dict, List, dict]]:
    """Synchronous wrapper for ssh_exec_multiple.

    Args:
        host (str): Target host IP or hostname.
        commands (List[str]): Commands to execute.
        port (int, optional): SSH port. Defaults to 22.
        timeout (int, optional): Timeout per command in seconds. Defaults to 30.
        return_type (str, optional): 'dict' or 'list' for output format.

    Returns:
        Dict[str, Union[Dict, List, dict]]: Result returned by ssh_exec_multiple.
    """
    return asyncio.run(ssh_exec_multiple(host, commands, port, timeout, return_type))



class HTTPCredentials:
    """Manage HTTP credentials loaded from a .env file.

    Attributes:
        token (Optional[str]): Bearer token.
        username (Optional[str]): Username for basic/digest auth.
        password (Optional[str]): Password for basic/digest auth.
        api_key (Optional[str]): API key for api_key auth.
    """
    
    def __init__(self):
        
        self.credential = []
        for i in range(1, 4):
            self.token = os.getenv(f'HTTP_TOKEN_{i}')
            self.username = os.getenv(f'HTTP_USERNAME_{i}')
            self.password = os.getenv(f'HTTP_PASSWORD_{i}')
            self.api_key = os.getenv(f'HTTP_API_KEY_{i}')
            
            if self.token or (self.username and self.password) or self.api_key:
                self.credential.append({
                    'token': self.token,
                    'username': self.username,
                    'password': self.password,
                    'api_key': self.api_key
                })
        if not self.credential:
            raise ValueError("No HTTP credentials found in .env file")

    def get_credentials(self) -> Dict[str, Optional[str]]:
        """Return the credentials as a dictionary.

        Returns:
            Dict[str, Optional[str]]: Dictionary with keys 'token', 'username',
                'password', and 'api_key'.
        """
        return {
            'token': self.token,
            'username': self.username,
            'password': self.password,
            'api_key': self.api_key
        }

class RouterHTTPClient:
    """HTTP client helpers for router APIs supporting multiple auth methods.

    Attributes:
        timeout (httpx.Timeout): Default timeout configuration for HTTP requests.
    """
    
    def __init__(self):
        self.timeout = httpx.Timeout(30.0, connect=10.0)
        
    def _get_auth_headers(
        self,
        auth_type: str,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_header: str = "X-API-Key"
    ) -> Dict[str, str]:
        """Generate authentication headers according to the requested auth type.

        Args:
            auth_type (str): One of 'bearer', 'basic', 'api_key', 'digest', 'none'.
            token (Optional[str]): Bearer token when auth_type == 'bearer'.
            username (Optional[str]): Username for basic/digest auth.
            password (Optional[str]): Password for basic/digest auth.
            api_key (Optional[str]): API key for api_key auth.
            api_key_header (str): Header name to place the API key in.

        Returns:
            Dict[str, str]: Headers required for the selected authentication.

        Raises:
            ValueError: If required auth parameters are missing for the chosen type.
        """
        headers = {}
        
        if auth_type == 'bearer':
            if not token:
                raise ValueError("Token required for Bearer authentication")
            headers['Authorization'] = f'Bearer {token}'
            
        elif auth_type == 'basic':
            if not username or not password:
                raise ValueError("Username and password required for Basic authentication")
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers['Authorization'] = f'Basic {credentials}'
            
        elif auth_type == 'api_key':
            if not api_key:
                raise ValueError("API Key required for API Key authentication")
            headers[api_key_header] = api_key
            
        elif auth_type == 'digest':
            # Digest is handled automatically by httpx.DigestAuth
            pass
            
        elif auth_type == 'none':
            pass
            
        else:
            raise ValueError(f"Authentication type not supported: {auth_type}")
        
        return headers
    
    async def _make_request(
        self,
        method: str,
        url: str,
        auth_type: str = 'none',
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        token: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_key: Optional[str] = None,
        api_key_header: str = "X-API-Key",
        verify_ssl: bool = False,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Perform an HTTP request with selected auth and parameters.

        Args:
            method (str): HTTP method to use ('GET','POST',...).
            url (str): Full URL to request.
            auth_type (str, optional): Authentication type. Defaults to 'none'.
            headers (Optional[Dict[str, str]], optional): Additional headers.
            params (Optional[Dict[str, Any]], optional): Query parameters.
            data (Optional[Dict[str, Any]], optional): Form data.
            json (Optional[Dict[str, Any]], optional): JSON body to send.
            token (Optional[str], optional): Bearer token for 'bearer' auth.
            username (Optional[str], optional): Username for basic/digest auth.
            password (Optional[str], optional): Password for basic/digest auth.
            api_key (Optional[str], optional): API key for 'api_key' auth.
            api_key_header (str, optional): Header name for API key.
            verify_ssl (bool, optional): Whether to verify SSL certificates.
            timeout (int, optional): Timeout in seconds for the request.

        Returns:
            Dict[str, Any]: {
                'status_code': HTTP status code,
                'success': bool indicating success,
                'data': parsed JSON or response text,
                'headers': response headers as dict,
                'url': final URL string
            }

        Raises:
            Exception: For timeout, connection or other request errors.
        """
        # Prepare headers
        auth_headers = self._get_auth_headers(
            auth_type, token, username, password, api_key, api_key_header
        )
        
        final_headers = {**auth_headers, **(headers or {})}
        
        # Prepare Digest authentication if applicable
        auth = None
        if auth_type == 'digest' and username and password:
            auth = httpx.DigestAuth(username, password)
        
        try:
            async with httpx.AsyncClient(
                verify=verify_ssl,
                timeout=httpx.Timeout(timeout, connect=10.0),
                follow_redirects=True
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=final_headers,
                    params=params,
                    data=data,
                    json=json,
                    auth=auth
                )
                
                # Try to parse as JSON, otherwise return text
                try:
                    response_data = response.json()
                except ValueError:
                    response_data = response.text
                
                return {
                    'status_code': response.status_code,
                    'success': response.is_success,
                    'data': response_data,
                    'headers': dict(response.headers),
                    'url': str(response.url)
                }
                
        except httpx.TimeoutException:
            raise Exception(f"Timeout connecting to {url}")
        except httpx.ConnectError:
            raise Exception(f"Could not connect to {url}")
        except Exception as e:
            raise Exception(f"HTTP request error: {str(e)}")

async def _try_http_connection(
    url: str,
    method: str = 'GET',
    auth_type: str = 'basic',
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30
) -> Dict[str, Optional[str]]:
    """Try different credentials until finding working ones.
    
    Args:
        url: Target URL to test
        method: HTTP method
        auth_type: Authentication type (basic, bearer, api_key, digest)
        verify_ssl: Whether to verify SSL
        timeout: Request timeout

    Returns:
        Dict with working credentials: {
            'username': str or None,
            'password': str or None,
            'token': str or None,
            'api_key': str or None
        }
    """
    credentials_list = []
    
    # Load up to 3 sets of credentials from environment variables
    for i in range(1, 4):
        cred = {}
        
        if auth_type in ['basic', 'digest']:
            env_user = os.getenv(f'HTTP_USER_{i}')
            env_pass = os.getenv(f'HTTP_PASS_{i}')
            if env_user and env_pass:
                cred['username'] = env_user
                cred['password'] = env_pass

        if cred:
            credentials_list.append(cred)

    if not credentials_list:
        raise ValueError(f"No credentials found for auth_type: {auth_type}")    
    last_error = None

    # Test every set of credentials
    for idx, creds in enumerate(credentials_list):
        try:
            async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
                auth = None
                headers = {}
                
                # Configure authentication according to type
                if auth_type == 'basic' and 'username' in creds:
                    auth = httpx.BasicAuth(creds['username'], creds['password'])
                    
                elif auth_type == 'digest' and 'username' in creds:
                    auth = httpx.DigestAuth(creds['username'], creds['password'])
                    
                response = await client.request(
                    method, 
                    url, 
                    auth=auth,
                    headers=headers
                )

                if response.status_code < 400:
                    # Return with all possible keys
                    return {
                        'username': creds.get('username'),
                        'password': creds.get('password'),
                        'auth_type': auth_type
                    }
                else:
                    last_error = f"HTTP {response.status_code}"
                    continue

        except Exception as e:
            last_error = e
            continue
    
    return {
        "error": True,
        "description": f"No valid credentials found. Last error: {str(last_error)}"
    }

async def http_router_request(
    url: str,
    method: Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] = 'GET',
    auth_type: Literal['bearer', 'basic', 'api_key', 'digest', 'none'] = 'basic',
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
    api_key_header: str = "X-API-Key",
    verify_ssl: bool = False,
    timeout: int = 30
) -> Dict[str, Any]:
    """Perform HTTP requests to routers with automatic credential discovery.
    
    Credentials are automatically searched in the .env file using _try_http_connection().
    User does not need to provide credentials.

    Args:
        url (str): Full endpoint URL (e.g. http://192.168.1.1/api/status).
        method (Literal, optional): HTTP method. Defaults to 'GET'.
        auth_type (Literal, optional): Authentication type. Defaults to 'basic'.
        headers (Optional[Dict[str, str]], optional): Additional headers.
        params (Optional[Dict[str, Any]], optional): Query parameters.
        data (Optional[Dict[str, Any]], optional): Form data to send.
        json (Optional[Dict[str, Any]], optional): JSON body to send.
        api_key_header (str, optional): Header name for API key. Defaults to "X-API-Key".
        verify_ssl (bool, optional): Whether to verify SSL certs. Defaults to False.
        timeout (int, optional): Request timeout in seconds. Defaults to 30.

    Returns:
        Dict[str, Any]: {
            'status_code': int,
            'success': bool,
            'data': parsed JSON or text,
            'headers': response headers dict,
            'url': final URL string,
            'credentials_used': {'username': str, 'auth_type': str}
        }
    
    Raises:
        ValueError: If no credentials found in .env for the auth_type.
        Exception: If connection or HTTP request fails
    """

    working_creds = await _try_http_connection(
        url=url,
        method=method,
        auth_type=auth_type,
        verify_ssl=verify_ssl,
        timeout=timeout
    )
    
    if "error" in working_creds:
        print('Error finding credentials:', working_creds['description'])
        working_creds['url'] = url
        return working_creds

    username = working_creds.get('username')
    password = working_creds.get('password')
    auth_type = working_creds.get('auth_type', 'none')

    client = RouterHTTPClient()
    result = await client._make_request(
        method=method,
        url=url,
        auth_type=auth_type,
        headers=headers,
        params=params,
        data=data,
        json=json,
        username=username,
        password=password,
        verify_ssl=verify_ssl,
        timeout=timeout
    )
    
    # Add basic information about credentials used
    result['credentials_used'] = {
        'username': username,
        'auth_type': auth_type
    }

    return result

async def http_router_request_batch(
    requests: List[Dict[str, Any]],
    return_exceptions: bool = True
) -> List[Union[Dict[str, Any], Exception]]:
    """Execute multiple HTTP requests concurrently using asyncio.gather.
    
    This function allows you to make many HTTP requests simultaneously, taking
    full advantage of async capabilities.

    Args:
        requests (List[Dict[str, Any]]): List of request dictionaries. Each dict
            should contain parameters for http_router_request:
            - url (str): Required. The target URL.
            - method (str): Optional. HTTP method. Defaults to 'GET'.
            - auth_type (str): Optional. Authentication type. Defaults to 'basic'.
            - headers (dict): Optional. Additional headers.
            - params (dict): Optional. Query parameters.
            - data (dict): Optional. Form data.
            - json (dict): Optional. JSON body.
            - verify_ssl (bool): Optional. Defaults to False.
            - timeout (int): Optional. Defaults to 30.
        return_exceptions (bool, optional): If True, exceptions are returned as results
            instead of raising. Defaults to True.

    Returns:
        List[Union[Dict[str, Any], Exception]]: List of results in the same order as
            the input requests. Each element is either a response dict or an Exception
            if return_exceptions=True.

    Example:
        requests = [
            {'url': 'http://router1.com/api/status', 'method': 'GET'},
            {'url': 'http://router2.com/api/config', 'method': 'POST', 'json': {'key': 'value'}},
            {'url': 'http://router3.com/api/info', 'auth_type': 'bearer'}
        ]
        results = await http_router_request_batch(requests)
    """
    tasks = []
    
    for req in requests:
        # Extract parameters with defaults
        url = req.get('url')
        if not url:
            raise ValueError("Each request must contain a 'url' key")
        
        method = req.get('method', 'GET')
        auth_type = req.get('auth_type', 'basic')
        headers = req.get('headers')
        params = req.get('params')
        data = req.get('data')
        json_data = req.get('json')
        api_key_header = req.get('api_key_header', 'X-API-Key')
        verify_ssl = req.get('verify_ssl', False)
        timeout = req.get('timeout', 30)
        
        # Create task for each request
        task = http_router_request(
            url=url,
            method=method,
            auth_type=auth_type,
            headers=headers,
            params=params,
            data=data,
            json=json_data,
            api_key_header=api_key_header,
            verify_ssl=verify_ssl,
            timeout=timeout
        )
        tasks.append(task)
    
    # Execute all requests concurrently
    results = await asyncio.gather(*tasks, return_exceptions=return_exceptions)
    
    return results


def wrapper_http_router_request(
    url: str,
    method: Literal['GET', 'POST', 'PUT', 'DELETE', 'PATCH'] = 'GET',
    auth_type: Literal['bearer', 'basic', 'api_key', 'digest', 'none'] = 'basic',
    headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Synchronous wrapper for http_router_request.

    Args:
        url (str): Full endpoint URL.
        method (Literal, optional): HTTP method. Defaults to 'GET'.
        auth_type (Literal, optional): Authentication type. Defaults to 'basic'.
        headers (Optional[Dict[str, str]], optional): Additional headers.

    Returns:
        Dict[str, Any]: Result from http_router_request.
    """
    return asyncio.run(http_router_request(url, method, auth_type, headers))

def wrapper_http_router_request_batch(
    requests: List[Dict[str, Any]],
    return_exceptions: bool = True
) -> List[Union[Dict[str, Any], Exception]]:
    """Synchronous wrapper for http_router_request_batch.

    Args:
        requests (List[Dict[str, Any]]): List of request dictionaries 
        Example ->
            {
                'url': 'http://router1.com/api/status',
                'method': 'GET',
                'auth_type': 'basic',
                'headers': {'Custom-Header': 'value'},    
            }.
        return_exceptions (bool, optional): If True, return exceptions instead of raising.

    Returns:
        List[Union[Dict[str, Any], Exception]]: List of results or exceptions.
    """
    return asyncio.run(http_router_request_batch(requests, return_exceptions))


"""
Manual and example for using these classes

#### 1) Create a .env file in the same directory with:
        Note: The script reads up to 3 sets of credentials and attempts to use them in order.
        SSH_USER_1=admin
        SSH_PASS_1=password123
        SSH_USER_2=root
        SSH_PASS_2=rootpass456
        SSH_USER_3=operator
        SSH_PASS_3=operpass789

        # HTTP credentials
        HTTP_USER_1=admin
        HTTP_PASS_1=adminpass
        HTTP_USER_2=user
        HTTP_PASS_2=userpass
        HTTP_USER_3=operator
        HTTP_PASS_3=operpass789

#### 2) Example of using SSH classes:

        # Single command
        result = wrapper_async_ssh_single_command(host='192.168.1.1', command='ls -l')
        print(result)

        # Multiple commands
        commands = ['uname -a', 'df -h', 'uptime']
        result = wrapper_async_ssh_multiple_commands(host='192.168.1.1', commands=commands)
        print(result)


#### 3) Example of using HTTP classes:

        # Single request
        url = 'http://192.168.1.1/api/v1/resource'
        result = wrapper_http_router_request(url, method='GET', auth_type='basic')
        print(result)
        
        # Batch requests (multiple routers concurrently)
        requests = [
            {'url': 'http://192.168.1.1/api/status'},
            {'url': 'http://192.168.1.2/api/status'},
            {'url': 'http://192.168.1.3/api/config', 'method': 'POST', 'json': {'setting': 'value'}}
        ]
        results = wrapper_http_router_request_batch(requests)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Request {i+1} failed: {result}")
            else:
                print(f"Request {i+1} status: {result['status_code']}")

Note: You don't need to specify credentials. The script reads them from the local .env file.
      Only 3 credential sets are allowed per authentication type.


#### 4) Example of using HTTP batch with the requests defined in app.py:

        from test import wrapper_http_router_request_batch
        from pprint import pprint
        request = [
            # S600 -> This device is a special model that use BASIC-AUTH, btw is a chinese device
            {
                'url': 'https://100.65.52.9/protected/macTable.do',
                'method': 'GET',
                'verify_ssl': False,
                'auth_type': 'basic',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept': '*/*',
                }      
            },
            # 610 -> This device is a special model that use DIGEST-AUTH
            {
                'url': 'http://100.69.47.9/!dhost.b',
                'method': 'GET',
                'verify_ssl': False,
                'auth_type': 'digest',  <- using digest for auth
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept': '*/*',
                }  
            }
        ]
        result = wrapper_http_router_request_batch(requests=request, return_exceptions=True)
        print(len(result), type(result))
        for i in result:
            pprint(i, width=150, compact=True, sort_dicts=True)
            print('=== DONE \n\n')

#### 5) Example output of the above code:
    
        2 <class 'list'>
        {'credentials_used': {'auth_type': 'basic', 'username': 'admin'},
        'data': '<html><head><title>MAC Address Table</title></head><body>...</body></html>',
        'headers': {'Content-Length': '1234', 'Content-Type': 'text/html; charset=UTF-8', ...},
        'status_code': 200,
        'success': True,
        'url': 'https://100.65.52.9/protected/macTable.do'
        }
        === DONE

"""

