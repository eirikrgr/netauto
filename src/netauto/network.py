# Author: Eirikgr
# License: MIT

import os
import httpx
import base64
import asyncio
import asyncssh
from typing import List, Dict, Union, Optional, Any, Literal
from dotenv import load_dotenv


TIMEOUT: int = 3 # Default timeout for connections in seconds
PORT: int = 22

class Credentials:
    """Manage SSH credentials loaded from a .env file.

    Attributes:
        credentials (List[Dict]): List of credential dicts with keys 'username',
            'password' and 'key_file'.

    Notes:
        This class reads up to 3 credential sets from environment variables:
        SSH_USER_1/SSH_PASS_1/SSH_KEY_1 ... SSH_USER_3/SSH_PASS_3/SSH_KEY_3.
    """

    def __init__(self):

        SVC_ENV_PATH = '../.env'
        LOCAL_ENV_PATH = os.path.join(os.getcwd(), '.env')
        if os.path.exists(SVC_ENV_PATH):
            load_dotenv(SVC_ENV_PATH)
        elif os.path.exists(LOCAL_ENV_PATH):
            load_dotenv(LOCAL_ENV_PATH)
        else:
            load_dotenv()

        if not self.credentials:
            raise ValueError("No SSH credentials found in .env file")
    
    def get_credentials_ssh(self):
        credentials = [] 
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

        return self.credentials

    def get_credentials_http(self):
        credentials: list = []
        for i in range(1, 4):
            self.token = os.getenv(f'HTTP_TOKEN_{i}')
            self.username = os.getenv(f'HTTP_USERNAME_{i}')
            self.password = os.getenv(f'HTTP_PASSWORD_{i}')
            self.api_key = os.getenv(f'HTTP_API_KEY_{i}')
            
            if self.token or (self.username and self.password) or self.api_key:
                credential.append({
                    'token': self.token,
                    'username': self.username,
                    'password': self.password,
                    'api_key': self.api_key
                })
        
        return credentials


async def _try_ssh_connection(host: str, port: int = PORT, credentials_list: List[Dict], timeout: int = TIMEOUT) -> object:
    """Attempt SSH connection iterating over provided credentials.
    Tries each credential set until a connection succeeds or all fail.

    Args:
        host (str): Remote host IP or hostname.
        port (int): SSH port.
        credentials_list (List[Dict]): List of credential dicts to try.
        timeout (int): Connection timeout in seconds.

    Returns:
        Tuple[asyncssh.SSHClientConnection, Dict]: Established connection and the credential dict that succeeded.
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

    if last_error:
        return f"Last error: {str(last_error)}"

    return None

async def ssh_single_command(host: str, command: str, port: int = PORT, timeout: int = TIMEOUT) -> str:
    credentials = Credentials()

    try:
        conn, creds_used = await _try_ssh_connection(
            host, port, credentials.get_credentials_ssh(), timeout
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

async def ssh_multiples_command(host: str, commands: List[str], port: int = PORT, timeout: int = TIMEOUT, return_type: str = 'dict') -> list:
    credentials = Credentials()
    
    try:
        conn, creds_used = await _try_ssh_connection(
            host, port, credentials.get_credentials_ssh(), timeout
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

def ssh_single_wrap(host: str, command: str, port: int = PORT, timeout: int = TIMEOUT) -> str:
    return asyncio.run(ssh_single_command(host, command, port, timeout))

def ssh_multiples_wrap(host: str, commands: List[str], port: int = PORT, timeout: int = TIMEOUT, return_type: str = 'dict') -> str: 
    return asyncio.run(ssh_multiples_command(host, commands, port, timeout, return_type))


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
        timeout: int = TIMEOUT
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

        auth_headers = self._get_auth_headers(
            auth_type, token, username, password, api_key, api_key_header
        )
        final_headers = {**auth_headers, **(headers or {})}
        
        auth = None
        if auth_type == 'digest' and username and password:
            auth = httpx.DigestAuth(username, password)
        
        # Create an httpx.Timeout object for more granular control
        httpx_timeout = httpx.Timeout(timeout, connect=min(10.0, timeout))

        try:
            async with httpx.AsyncClient(
                verify=verify_ssl,
                timeout=httpx_timeout,
                follow_redirects=True
            ) as client:

                try:
                    response = await asyncio.wait_for(
                        client.request(
                            method=method,
                            url=url,
                            headers=final_headers,
                            params=params,
                            data=data,
                            json=json,
                            auth=auth
                        ),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    raise Exception(f"Timeout connecting to {url} (asyncio.wait_for)")

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

        except asyncio.TimeoutError:
            # This may be raised by httpx internals as well
            raise Exception(f"Timeout connecting to {url} (asyncio)")
        except httpx.ReadTimeout:
            raise Exception(f"Read timeout while connecting to {url}")
        except httpx.ConnectTimeout:
            raise Exception(f"Connect timeout while connecting to {url}")
        except httpx.ConnectError:
            raise Exception(f"Could not connect to {url}")
        except httpx.HTTPError as e:
            raise Exception(f"HTTP request error: {str(e)}")
        except Exception as e:
            raise Exception(f"HTTP request error: {str(e)}")

async def _try_http_connection(
    url: str,
    method: str = 'GET',
    auth_type: str = 'basic',
    verify_ssl: bool = False,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = TIMEOUT
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
    credentials_list = Credentials().get_credentials_http()

    if not credentials_list:
        raise ValueError(f"No credentials found for auth_type: {auth_type}")    
    
    last_error = None
    for idx, creds in enumerate(credentials_list):
        try:
            httpx_timeout = httpx.Timeout(timeout, connect=min(10.0, timeout))
            async with httpx.AsyncClient(verify=verify_ssl, timeout=httpx_timeout) as client:
                auth = None
                headers = {}

                if auth_type == 'basic' and 'username' in creds:
                    auth = httpx.BasicAuth(creds['username'], creds['password'])

                elif auth_type == 'digest' and 'username' in creds:
                    auth = httpx.DigestAuth(creds['username'], creds['password'])

                try:
                    response = await asyncio.wait_for(
                        client.request(
                            method,
                            url,
                            auth=auth,
                            headers=headers
                        ),
                        timeout=timeout
                    )
                except asyncio.TimeoutError:
                    last_error = f"Timeout connecting to {url} (asyncio.wait_for)"
                    continue

                if response.status_code < 400:
                    return {
                        'username': creds.get('username'),
                        'password': creds.get('password'),
                        'auth_type': auth_type
                    }
                else:
                    last_error = f"HTTP {response.status_code}"
                    continue

        except asyncio.TimeoutError:
            last_error = f"Timeout connecting to {url}"
            continue
        except httpx.ReadTimeout:
            last_error = f"Read timeout while connecting to {url}"
            continue
        except httpx.ConnectTimeout:
            last_error = f"Connect timeout while connecting to {url}"
            continue
        except httpx.ConnectError:
            last_error = f"Could not connect to {url}"
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
    timeout: int = TIMEOUT
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
