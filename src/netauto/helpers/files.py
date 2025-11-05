# Author: Eirikgr
# License: MIT

import json
from typing import Any

def load_json(filepath: str) -> Any:
    """
    Load data from a JSON file.
    
    Args:
        filepath: Path to the JSON file
        
    Returns:
        The parsed JSON data
        
    Raises:
        FileNotFoundError: If the file doesn't exist
        JSONDecodeError: If the file contains invalid JSON
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)