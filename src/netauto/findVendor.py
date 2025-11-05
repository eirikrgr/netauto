from typing import List, Optional
from helpers.files import load_json


class DeviceManager:
    """Manages device configurations and command execution for different vendors."""
  
    def __init__(self):
        self.vendors: list = load_json('vendors.json')

    def _detect_model(self, device_name: str) -> Optional[dict]:
        device_normalized = device_name.strip()
        
        for vendor in self.vendors:
            if any(device_normalized in model for model in vendor['model']):
                return vendor
        
        return None

    def list_supported_models(self) -> List[tuple]:
        return [(vendor['vendor'], vendor['model']) for vendor in self.vendors]

    def get_device_config(self, model: str) -> Optional[dict]:
        return self._detect_model(model)

    def get_device_config_by_version(self, model: str, version: str) -> Optional[dict]:
        vendor: dict = self._detect_model(model)['version']
        
        if vendor:
            FLAG_FOUND = False
            all_available_ver: list = vendor.get('allowed', None) # List of allowed versions ['6.48.6', '6.48.5', .... any version]
            complete_version = any(ver for ver in all_available_ver if version == ver)

            # Example version: 5.25.x, 5.25.6
            if complete_version:
                FLAG_FOUND = True
                return vendor
        
            # Look for the first two digits match: 5.25
            major_version = '.'.join(version.split('.')[:2])
            for ver in all_available_ver:
                if ver == major_version:
                    FLAG_FOUND = True
                    return vendor
            
            # Look if exist one version starting with only the major: 5
            if not FLAG_FOUND:
                major = version.split('.')[0]
                for ver in all_available_ver:
                    if major in ver and len(ver) == len(major):
                        FLAG_FOUND = True
                        return vendor

            # If no match found, return None
            return None



# Example usage

# manager = DeviceManager()
# a: list = manager.list_supported_models()
# b: dict = manager.get_device_config('RB4011') # Use a private method indirectly
# c: dict = manager._detect_model('RB4011') # Method use in get_device_config
# d: dict = manager.get_device_config_by_version('RB4011', '6')
# e: dict = manager.get_device_config_by_version('RB4011', '6.48')
# f: dict = manager.get_device_config_by_version('RB4011', '6.49.2.1.2')
# print(a)
# print(b)
# print(c)
# print(d)
# print(e)
# print(f)