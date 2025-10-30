#!/usr/bin/env python3
# core/utils.py

import random
import string
import hashlib
import os

def generate_random_string(length=10):
    """Generates a random string of a given length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_canonical_response(content):
    """Creates a canonical hash of a response to detect duplicates."""
    # Remove dynamic content like timestamps, nonces, etc.
    content = re.sub(r'value="[^"]*[0-9]{10,}[^"]*"', 'value="TIMESTAMP"', content)
    content = re.sub(r'[0-9a-f]{8,}', 'HASH', content) # Simple hash replacement
    return hashlib.md5(content.encode('utf-8')).hexdigest()

def setup_session():
    """Sets up a robust requests session."""
    session = requests.Session()
    
    # Use a custom adapter with retry logic
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def load_payloads(file_path):
    """Loads payloads from a file, ignoring comments and empty lines."""
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]
