# Author: Eirikgr
# License: MIT

from typing import Dict, Any, Optional, List
from helpers.files import load_json
import asyncio
from filters.mikrotik import mikrotik
from network import ssh_exec_single, http_router_request


DEVICE_CONF: List[dict] = load_json('vendors.json')
FILTER_AVAILABLES: Dict[str, Any] = {
    'mikrotik': mikrotik,
}


class DeviceManager:
    """Manages device configurations and command execution for different vendors."""
    
    def __init__(self):
        self.parser = OutputParser()

    def _detect_model(self, device_name: str) -> Optional[dict]:
        """
        Match device name to vendor configuration.
        
        Args:
            device_name: Device name from monitoring system
            
        Returns:
            Vendor configuration dict or None
        """
        device_normalized = device_name.strip()
        
        for vendor in DEVICE_CONF:
            if any(device_normalized in model for model in vendor['models']):
                return vendor
        
        return None

    def list_supported_models(self) -> List[tuple]:
        """List all supported vendors and their models."""
        return [(vendor['vendor'], vendor['models']) for vendor in DEVICE_CONF]

    def get_device_config(self, model: str) -> Optional[dict]:
        """
        Get device configuration for a specific model.
        
        Args:
            model: Device model name
            
        Returns:
            Configuration dict or None
        """
        return self._detect_model(model)

    async def execute_command(
        self,
        ip: str,
        model: str,
        command: str,
        timeout: int = 30,
        parse_output: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a command on a device.

        Args:
            ip: Device IP address
            model: Device model
            command: Command to execute
            timeout: Command timeout in seconds
            parse_output: Whether to apply output parsing
            
        Returns:
            Dict containing execution results
        """

        config = self.get_device_config(model)
        if not config:
            raise ValueError(f"Model '{model}' not supported. Available: {self.list_supported_models()}")
        
        if config.get('protocol') == 'ssh':
            return await self._execute_ssh_command(ip, config, command, timeout, parse_output)
        else:
            return await self._execute_http_command(ip, config, command, timeout, parse_output)

    async def _execute_ssh_command(
        self,
        ip: str,
        config: dict,
        command: str,
        timeout: int = 5,
        parse_output: bool = True
    ) -> Dict[str, Any]:
        """Execute SSH command on device."""
        selected_command_from_json = None
        exec_conf = config.get('exec', {})
        
        if '/' in command:
            splitcommand = command.split('/')
            selected_command_from_json = exec_conf.get(splitcommand[0]).get(splitcommand[1])
        else:
            selected_command_from_json = exec_conf.get(command['default'])

        if not selected_command_from_json:
            return {
                'success': False,
                'error': f'Command "{command}" not available for this device',
                'device': {'ip': ip, 'model': config.get('models'), 'vendor': config.get('vendor')}
            }
        
        try:
            result = await ssh_exec_single(host = ip, command = selected_command_from_json, port = 22, timeout = timeout)

            parsed = None
            if parse_output and config.get('parser'):
                parsed = FILTER_AVAILABLES[config.get('vendor')](command, result['output'])

            return {
                'success': True,
                'device': {
                    'ip': ip,
                    'vendor': config.get('vendor'),
                    'protocol': 'ssh',
                    'command': command
                },
                'raw': result['output'],
                'parsed': parsed
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'device': {'ip': ip, 'model': config.get('models'), 'vendor': config.get('vendor'), 'command': command}
            }

    async def _execute_http_command(
        self,
        ip: str,
        config: dict,
        command: str,
        timeout: int,
        parse_output: bool
    ) -> Dict[str, Any]:
        """Execute HTTP/HTTPS command on device."""
        exec_conf = config.get('exec', {})
        if '/' in command:
            splitcommand = command.split('/')
            endpoint_config = exec_conf.get(splitcommand[0]).get(splitcommand[1])
        else:
            endpoint_config = exec_conf.get(command)['default']
        
        print(endpoint_config)

        if not endpoint_config or not isinstance(endpoint_config, dict):
            return {
                'success': False,
                'error': f'Command "{command}" not available via HTTP',
                'device': {'ip': ip, 'model': config.get('models'), 'vendor': config.get('vendor')}
            }

        url_path = endpoint_config.get('url') or endpoint_config.get('resource')
        full_url = f"{config.get('protocol')}://{ip}:{config.get('port', 80)}{url_path or ''}"

        try:
            result = await http_router_request(
                url=full_url,
                method=endpoint_config.get('method', 'GET'),
                auth_type=config.get('auth_type', 'basic'),
                headers=endpoint_config.get('headers'),
                verify_ssl=False,
                timeout=timeout
            )

            parsed = None
            if parse_output and config.get('parser') and result.get('success'):
                output = result.get('data', '')
                if isinstance(output, dict):
                    output = str(output)
                
                parsed = parsed = FILTER_AVAILABLES[config.get('vendor')](command, result['output'])

            return {
                'success': result.get('success', False),
                'device': {
                    'ip': ip,
                    'vendor': config.get('vendor'),
                    'protocol': config.get('protocol'),
                    'command': command
                },
                'raw': result.get('data'),
                'parsed': parsed,
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__,
                'device': {'ip': ip, 'vendor': config.get('vendor'), 'command': command}
            }

    async def execute_batch(
        self,
        devices: List[Dict[str, Any]],
        parse_output: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Execute commands on multiple devices concurrently.
        
        Args:
            devices: List of dicts with 'ip', 'model', 'command', and optionally 'timeout'
            parse_output: Whether to parse outputs
            
        Returns:
            List of execution results
        """
        tasks = [
            self.execute_command(
                ip=device['ip'],
                model=device['model'],
                command=device['command'],
                timeout=device.get('timeout', 30),
                parse_output=parse_output
            )
            for device in devices
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        formatted_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                formatted_results.append({
                    'success': False,
                    'device': devices[i],
                    'error': str(result),
                    'error_type': type(result).__name__
                })
            else:
                formatted_results.append(result)
        
        return formatted_results

class OutputParser:
    """Parses command outputs from different vendors."""

    @staticmethod
    def parse_model_s600(output: str, command_type: str) -> Dict[str, Any]:
        parsed = {'success': False}
        
        try:
            if command_type == 'get_mactable':
                parsed['data'] = parse_s600_mac_table(output)
                parsed['success'] = True
            elif command_type == 'get_version':
                parsed['data'] = parse_s600_version(output)
                parsed['success'] = True
        except Exception as e:
            parsed['error'] = f'Parser error: {str(e)}'
        
        return parsed
    
    @staticmethod
    def parse_model_610(output: str, command_type: str) -> Dict[str, Any]:
        parsed = {'success': False}
        
        try:
            if command_type == 'get_mactable':
                parsed['data'] = parse_css610_mac_table(output)
                parsed['success'] = True
            elif command_type == 'get_version':
                parsed['data'] = parse_css610_version(output)
                parsed['success'] = True
        except Exception as e:
            parsed['error'] = f'Parser error: {str(e)}'
        
        return parsed

    @staticmethod
    def parse_model_310(output: str, command_type: str) -> Dict[str, Any]:
        parsed = {'success': False}
        
        try:
            if command_type == 'get_mactable':
                parsed['data'] = parse_mikrotik_mac_table(output=output)
                parsed['success'] = True
            elif command_type == 'get_version':
                parsed['data'] = parse_mikrotik_version(output)
                parsed['success'] = True
            elif command_type == 'get_interface_vlan':
                interfaces_vlan = filter_output_using_textfsm(output=output, template_name='interface_vlan_print_detail')
                parsed['data'] = interfaces_vlan
                parsed['success'] = True
            elif command_type == 'get_ipaddress':
                ipaddress = filter_output_using_textfsm(output=output, template_name='ip_address_print_detail')
                parsed['data'] = ipaddress
                parsed['success'] = True
        except Exception as e:
            parsed['error'] = f'Parser error: {str(e)}'
            
        return parsed


def execute_command_sync(
    ip: str,
    model: str,
    command: str,
    timeout: int = 30,
    parse_output: bool = True
) -> Dict[str, Any]:
    """Synchronous version of execute_command."""
    manager = DeviceManager()
    return asyncio.run(manager.execute_command(ip, model, command, timeout, parse_output))

def execute_batch_sync(
    devices: List[Dict[str, Any]],
    parse_output: bool = True
) -> List[Dict[str, Any]]:
    """Synchronous version of execute_batch."""
    manager = DeviceManager()
    return asyncio.run(manager.execute_batch(devices, parse_output))


if __name__ == "__main__":
    manager = DeviceManager()

    async def test():
        req = await manager.execute_command(
            ip='100.127.4.14',
            model='RB4011',
            command='interface/vlan',
            parse_output = True
        )
        print(req)

    asyncio.run(test())