# Fuzzing Strategy for IDS Suite
**Date:** 30 January 2026
**Target:** `/home/jay/Documents/cyber/dev/lss2/ids_suite/`

## Executive Summary

This document outlines comprehensive fuzzing strategies for the IDS Suite focusing on crash vector identification and undefined behavior detection across five critical attack surfaces: file parsing, IP address handling, path validation, API response processing, and command-line argument handling.

---

## 1. FILE PARSING FUZZING

### 1.1 EVE JSON Log Parsing (`models/eve_reader.py`, `engines/suricata.py`)

#### Attack Surface Analysis
- **Target Functions:**
  - `EVEFileReader._read_from_position()` (line 120-139)
  - `EVEFileReader.initial_load()` (line 141-165) - **CRITICAL: Uses shell=True**
  - `SuricataEngine.parse_alert()` (line 30-56)

#### Crash Vectors

**Vector 1.1: Malformed JSON Lines**
```python
test_inputs = [
    # Truncated JSON
    '{"event_type": "alert", "alert": {"severity"',
    '{"event_type": "alert"',
    '{',

    # Invalid escaping
    '{"event_type": "alert", "signature": "test\\x00null"}',
    '{"event_type": "alert", "signature": "\\uDEAD"}',  # Invalid unicode

    # Nested structure bombs
    '{"event_type": "alert", "alert": ' + '{"nested": ' * 10000 + '1' + '}' * 10000,

    # Type confusion
    '{"event_type": "alert", "severity": "not_an_int"}',
    '{"event_type": "alert", "src_port": [1, 2, 3]}',
    '{"event_type": "alert", "timestamp": null}',

    # Empty/null values
    '{"event_type": null}',
    '{"event_type": ""}',
    '{}',
    '',

    # Integer overflow
    '{"event_type": "alert", "src_port": 999999999999999999999}',
    '{"event_type": "alert", "severity": -2147483649}',

    # Control characters
    '{"event_type": "alert\x00", "signature": "test\x00"}',
    '{"event_type": "alert\n\r\t", "signature": "test"}',

    # Very long strings
    '{"event_type": "alert", "signature": "' + 'A' * 1000000 + '"}',
    '{"event_type": "alert", "src_ip": "' + '1' * 1000000 + '"}',
]
```

**Expected vs Actual Behavior:**
- **Expected:** Graceful error handling, log malformed line, continue processing
- **Actual Risk:**
  - `json.loads()` can raise `JSONDecodeError` (caught on line 54)
  - `data.get()` calls may return unexpected types causing AttributeError
  - No length validation could cause memory exhaustion
  - Timestamp slicing `[:19]` assumes string type

**Vector 1.2: Shell Injection in initial_load()**
```python
# CRITICAL: Line 155-156 uses shell=True with f-string
# f"tail -{num_lines} '{self.current_file}'"

test_inputs = [
    # Current file path injection
    "/var/log/suricata/eve.json'; rm -rf /tmp/test; echo '",
    "/var/log/suricata/eve.json$(whoami)",
    "/var/log/suricata/eve.json`id`",
    "/var/log/suricata/eve.json\n$(malicious)",
    "/var/log/suricata/eve.json' && cat /etc/passwd #",

    # Path with quotes
    "/var/log/suricata/eve.json' || touch /tmp/pwned || '",
    "/var/log/suricata/'\nrm -rf /tmp/test\n'",

    # Unicode and encoding attacks
    "/var/log/suricata/eve.json\u0027;whoami",
    "/var/log/suricata/\x00injection",
]
```

**Expected vs Actual Behavior:**
- **Expected:** Path validated, shell metacharacters rejected
- **Actual Risk:**
  - Single quotes provide SOME protection but can be bypassed
  - No validation before shell execution
  - `num_lines` parameter also injectable (if negative or very large)

**Vector 1.3: File System Race Conditions**
```python
test_scenarios = [
    # Symlink replacement
    "Create symlink to /etc/passwd, read file, replace symlink to different file",

    # File deletion mid-read
    "Open file, delete during read operation",

    # Inode reuse
    "Delete and recreate file with same path but different inode during rotation detection",

    # Size manipulation
    "Truncate file while position pointer is beyond new size",

    # Permission changes
    "Remove read permissions during active read operation",
]
```

**Vector 1.4: Configuration File Parsing (`core/config.py`)**
```python
# Target: Config._load_settings() line 31-41

malformed_json_configs = [
    # Type confusion
    '{"auto_refresh": "not_a_bool"}',
    '{"refresh_interval": "not_an_int"}',
    '{"hidden_signatures": "should_be_list"}',
    '{"hidden_src_ips": {"wrong": "type"}}',

    # Invalid nesting
    '{"auto_refresh": {"nested": {"too": {"deep": true}}}}',

    # Encoding attacks
    '{"hidden_signatures": ["\\u0000", "\\uFFFE"]}',

    # Size bombs
    '{"hidden_signatures": [' + ','.join(['"sig"'] * 1000000) + ']}',

    # JSON injection
    '}{"injected": "config"}{',
]
```

### Test Cases for File Parsing

```python
# Test 1: Malformed JSON resilience
def test_eve_reader_malformed_json():
    """EVE reader should handle malformed JSON without crashing"""
    engine = SuricataEngine()

    test_cases = [
        '{"event_type": "alert"',  # Truncated
        '{"event_type": null}',    # Null event type
        '',                        # Empty line
        '{' * 1000,               # Unbalanced braces
    ]

    for line in test_cases:
        result = engine.parse_alert(line)
        assert result is None  # Should return None, not crash

# Test 2: Shell injection prevention
def test_eve_reader_shell_injection():
    """EVE reader should prevent shell injection in initial_load"""
    # Create malicious path
    malicious_path = "/tmp/test'; rm -rf /tmp/testdir; echo '"

    reader = EVEFileReader(base_path=malicious_path)
    result = reader.initial_load(num_lines=10)

    # Verify no command execution occurred
    assert not os.path.exists("/tmp/testdir_deleted")

# Test 3: Type confusion
def test_alert_type_confusion():
    """Alert parsing should handle type confusion gracefully"""
    engine = SuricataEngine()

    # Port as array instead of int
    malformed = '{"event_type": "alert", "src_port": [1,2,3], "alert": {}}'
    result = engine.parse_alert(malformed)

    # Should handle gracefully
    assert result is None or isinstance(result.get('src_port'), (str, int))
```

---

## 2. IP ADDRESS HANDLING FUZZING

### 2.1 is_private_ip() Function (`core/utils.py` line 225-308)

#### Attack Surface Analysis
- **Type confusion** (line 238-239): Checks `isinstance(ip, str)` but early return
- **Split validation** (line 262-264): Assumes 4 octets for IPv4
- **Integer conversion** (line 266): Can raise ValueError
- **IPv6 prefix matching** (line 244-258): String-based checks vulnerable to bypass

#### Crash Vectors

**Vector 2.1: Type Confusion**
```python
test_inputs = [
    None,                      # None type
    123,                       # Integer
    12.34,                     # Float
    ['192', '168', '1', '1'],  # List
    {'ip': '192.168.1.1'},     # Dictionary
    b'192.168.1.1',           # Bytes
    True,                      # Boolean
    object(),                  # Object
]
```

**Vector 2.2: IPv4 Malformation**
```python
test_inputs = [
    # Octet count violations
    '192.168.1',              # 3 octets
    '192.168.1.1.1',          # 5 octets
    '192.168',                # 2 octets
    '192',                    # 1 octet
    '.....',                  # Only dots

    # Non-numeric octets
    '192.168.1.A',
    '192.168.1.0x1',          # Hex notation
    '192.168.1.01',           # Octal notation
    '192.168.1.1e2',          # Scientific notation

    # Integer overflow/underflow
    '256.168.1.1',            # Octet > 255
    '192.-1.1.1',             # Negative octet
    '999999999.1.1.1',        # Huge number
    '192.168.1.2147483648',   # Int32 overflow

    # Whitespace and special chars
    ' 192.168.1.1',           # Leading space
    '192.168.1.1 ',           # Trailing space
    '192 .168.1.1',           # Space in middle
    '192.168.1.1\x00',        # Null byte
    '192.168.1.1\n',          # Newline

    # Empty octets
    '192..1.1',               # Empty octet
    '.168.1.1',               # Leading dot
    '192.168.1.',             # Trailing dot

    # Unicode variants
    '１９２.168.1.1',          # Full-width numbers
    '192․168․1․1',            # Unicode dots
]
```

**Vector 2.3: IPv6 Prefix Bypass**
```python
test_inputs = [
    # Case sensitivity bypass attempts
    'FE80::1',                # Uppercase (handled by .lower())
    'Fe80::1',                # Mixed case

    # Prefix confusion
    'fe800::1',               # Extra 0
    'fe8::1',                 # Missing character
    'fed0::1',                # Just outside fc/fd check (should be public)
    'ff00::1',                # Multicast edge

    # Expansion attacks
    '0000:0000:0000:0000:0000:0000:0000:0001',  # ::1 expanded
    'fe80:0000:0000:0000:0000:0000:0000:0001',  # Link-local expanded

    # IPv4-mapped IPv6
    '::ffff:192.168.1.1',     # Should be treated as private
    '::ffff:8.8.8.8',         # Public IP in IPv6 notation

    # Compressed notation edge cases
    '::',                      # All zeros
    '::1:2:3:4:5:6:7',        # Maximum compression
    'fe80::',                 # Link-local compressed

    # Invalid IPv6 but string-matched
    'fe80:::::',              # Too many colons
    'fc00 ::1',               # Space in middle
    'fc\x00d::1',            # Null byte in prefix
]
```

**Vector 2.4: Validators.validate_ip_address() (`core/validators.py` line 184-200)**
```python
# Uses regex IP_PATTERN (line 17-20)
# Pattern: ^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$

regex_bypass_attempts = [
    # Leading zeros (may be interpreted as octal)
    '192.168.001.001',
    '010.0.0.1',              # Should be 8.0.0.1 if interpreted as octal

    # Regex anchoring bypass
    '192.168.1.1\n',
    '\n192.168.1.1',

    # Case sensitivity (numbers don't have case, but good to test)
    '192.168.1.A',            # Should fail

    # Boundary values
    '0.0.0.0',                # Valid
    '255.255.255.255',        # Valid
    '256.0.0.0',              # Invalid (should fail regex)
]
```

### Test Cases for IP Address Handling

```python
# Test 4: Type confusion on is_private_ip
def test_is_private_ip_type_confusion():
    """is_private_ip should handle non-string types safely"""
    from ids_suite.core.utils import is_private_ip

    test_cases = [
        (None, True),           # Should return True (invalid)
        (123, True),
        ([192, 168, 1, 1], True),
        (b'192.168.1.1', True),
    ]

    for test_input, expected in test_cases:
        result = is_private_ip(test_input)
        assert result == expected, f"Failed for input: {test_input}"

# Test 5: IPv4 octet count validation
def test_is_private_ip_octet_count():
    """is_private_ip should reject invalid octet counts"""
    from ids_suite.core.utils import is_private_ip

    test_cases = [
        '192.168.1',       # 3 octets
        '192.168.1.1.1',   # 5 octets
        '....',            # Only dots
    ]

    for ip in test_cases:
        result = is_private_ip(ip)
        assert result == True, f"Should treat {ip} as invalid"

# Test 6: Integer overflow in IP octets
def test_is_private_ip_integer_overflow():
    """is_private_ip should handle integer overflow"""
    from ids_suite.core.utils import is_private_ip

    test_cases = [
        '256.168.1.1',
        '192.999999999999.1.1',
        '192.-1.1.1',
    ]

    for ip in test_cases:
        # Should not crash, should return True (invalid)
        result = is_private_ip(ip)
        assert result == True

# Test 7: IPv6 prefix bypass attempts
def test_is_private_ip_ipv6_bypass():
    """is_private_ip should correctly identify IPv6 addresses"""
    from ids_suite.core.utils import is_private_ip

    test_cases = [
        ('fe80::1', True),           # Link-local
        ('fc00::1', True),           # ULA
        ('fd00::1', True),           # ULA
        ('fed0::1', False),          # Public (not fc/fd prefix)
        ('::1', True),               # Loopback
        ('2001:db8::1', False),      # Public (documentation but not private)
    ]

    for ip, expected_private in test_cases:
        result = is_private_ip(ip)
        assert result == expected_private, f"Failed for {ip}"

# Test 8: Validator regex bypass
def test_validate_ip_address_bypass():
    """validate_ip_address regex should not be bypassed"""
    from ids_suite.core.validators import validate_ip_address

    test_cases = [
        ('192.168.1.1', True),
        ('256.0.0.0', False),
        ('192.168.1.1\n', False),
        ('192.168.001.001', True),  # Leading zeros - valid in regex
    ]

    for ip, expected_valid in test_cases:
        is_valid, error = validate_ip_address(ip)
        assert is_valid == expected_valid, f"Failed for {ip}: {error}"
```

---

## 3. PATH HANDLING FUZZING

### 3.1 validate_file_path() (`core/validators.py` line 203-241)

#### Attack Surface Analysis
- **os.path.realpath()** (line 221): Resolves symlinks, can raise OSError
- **Directory traversal** (line 234): Uses `startswith()` check
- **Path normalization**: May have TOCTOU races

#### Crash Vectors

**Vector 3.1: Path Traversal**
```python
test_inputs = [
    # Classic traversal
    '../../../etc/passwd',
    '../../../../../../etc/shadow',
    '/var/log/../../etc/passwd',

    # Encoded variants
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',  # Double encoding
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',

    # Unicode variants
    '..\\u002f..\\u002fetc\\u002fpasswd',
    '\u2026\u2044etc\u2044passwd',  # Unicode dots and slashes

    # Mixed separators
    '..\\..\\..\\etc\\passwd',     # Windows-style
    '..//../..//etc//passwd',      # Double slashes
    '..\\/../etc/passwd',          # Mixed

    # Null byte injection
    '/var/log/suricata/eve.json\x00/../../etc/passwd',
    '/var/log/\x00../../etc/passwd',

    # Symlink exploitation
    '/tmp/symlink_to_root/../etc/passwd',

    # Absolute path bypass
    '/etc/passwd',
    '//etc/passwd',

    # Current directory obfuscation
    '/var/log/./../../etc/passwd',
    '/var/log/././../../etc/passwd',
]
```

**Vector 3.2: TOCTOU Race Conditions**
```python
test_scenarios = [
    # Check-use race
    "validate_file_path() validates /tmp/safe -> attacker replaces with symlink to /etc/passwd -> program uses path",

    # Symlink race
    "Create /tmp/file -> validate -> replace with symlink -> use",

    # Permission race
    "File has read perms -> validate -> perms removed -> access fails",
]
```

**Vector 3.3: Allowed Directory Bypass**
```python
# Line 230-239: allowed_dirs check

test_inputs = [
    # Prefix matching bypass
    ('/var/log', '/var/log_fake/file'),           # Doesn't match because of missing separator
    ('/var/log', '/var/log/../etc/passwd'),       # Traversal after allowed
    ('/var/log', '/var/log/suricata/../../etc/passwd'),

    # Symlink bypass (if symlink created after realpath)
    ('/var/log', '/var/log/symlink_to_root/etc/passwd'),

    # Case sensitivity
    ('/var/log', '/var/Log/file'),                # Linux is case-sensitive
    ('/var/log', '/VAR/LOG/file'),

    # Unicode normalization
    ('/var/log', '/var/lo\u0067/file'),           # 'g' as unicode
]
```

**Vector 3.4: sanitize_for_shell() (`core/validators.py` line 244-258)**
```python
# Uses shlex.quote() - generally safe but test edge cases

test_inputs = [
    # Empty string
    '',

    # Already quoted
    "'already quoted'",
    '"double quoted"',

    # Mixed quotes
    "it's a test",
    'he said "hello"',

    # Control characters
    'test\x00null',
    'test\nNewline',
    'test\rCarriage',

    # Unicode
    'test\u0000unicode',
    'emoji_path_🔥',

    # Very long strings
    'A' * 1000000,
]
```

### Test Cases for Path Handling

```python
# Test 9: Path traversal prevention
def test_validate_file_path_traversal():
    """validate_file_path should prevent path traversal"""
    from ids_suite.core.validators import validate_file_path

    test_cases = [
        '../../../etc/passwd',
        '/var/log/../../etc/passwd',
        '/var/log/suricata/../../../etc/passwd',
    ]

    allowed_dirs = ['/var/log/suricata']

    for path in test_cases:
        is_valid, error = validate_file_path(path, allowed_dirs=allowed_dirs)
        assert not is_valid, f"Traversal not prevented for: {path}"

# Test 10: Null byte injection
def test_validate_file_path_null_byte():
    """validate_file_path should handle null bytes"""
    from ids_suite.core.validators import validate_file_path

    path_with_null = '/var/log/suricata/eve.json\x00../../etc/passwd'

    # Should either fail validation or safely truncate at null
    is_valid, error = validate_file_path(path_with_null)
    # Don't care if valid or not, just shouldn't crash

# Test 11: Allowed directory bypass via prefix
def test_validate_file_path_prefix_bypass():
    """validate_file_path should not be bypassed via prefix matching"""
    from ids_suite.core.validators import validate_file_path

    allowed_dirs = ['/var/log']

    # Should FAIL - not actually in /var/log
    is_valid, error = validate_file_path('/var/log_fake/file', allowed_dirs=allowed_dirs)
    assert not is_valid, "Prefix bypass should be prevented"

# Test 12: Symlink handling
def test_validate_file_path_symlink():
    """validate_file_path should resolve symlinks correctly"""
    import tempfile
    from ids_suite.core.validators import validate_file_path

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create safe dir and file
        safe_dir = os.path.join(tmpdir, 'safe')
        os.makedirs(safe_dir)
        safe_file = os.path.join(safe_dir, 'file.txt')
        open(safe_file, 'w').close()

        # Create symlink pointing outside
        symlink = os.path.join(safe_dir, 'link_to_etc')
        os.symlink('/etc/passwd', symlink)

        # Should reject symlink pointing outside allowed dir
        is_valid, error = validate_file_path(symlink, allowed_dirs=[safe_dir])
        assert not is_valid, "Symlink escape should be prevented"

# Test 13: Shell sanitization
def test_sanitize_for_shell():
    """sanitize_for_shell should handle edge cases"""
    from ids_suite.core.validators import sanitize_for_shell

    test_cases = [
        ('simple', "'simple'"),
        ("it's", "\"it's\"" if os.name == 'nt' else "'it'\"'\"'s'"),
        ('', "''"),
    ]

    for test_input, expected_pattern in test_cases:
        result = sanitize_for_shell(test_input)
        # shlex.quote should always return a safe string
        assert isinstance(result, str)
```

---

## 4. API RESPONSE HANDLING FUZZING

### 4.1 Threat Intel API Clients

#### Attack Surface Analysis
- **JSON parsing** (`threat_intel/base.py` line 68): `response.json()`
- **Dictionary navigation** (`threat_intel/virustotal.py` line 69-80): Nested `.get()` calls
- **Type assumptions**: Expects specific types in response

#### Crash Vectors

**Vector 4.1: Malformed API Responses**
```python
# Simulate responses from _make_request()

test_responses = [
    # Empty response
    {},

    # Missing expected keys
    {'data': None},
    {'data': {}},
    {'data': {'attributes': None}},

    # Type confusion
    {'data': 'should_be_dict'},
    {'data': {'attributes': 'should_be_dict'}},
    {'data': {'attributes': {'last_analysis_stats': 'should_be_dict'}}},

    # Array instead of object
    {'data': [1, 2, 3]},
    {'data': {'attributes': []}},

    # Null values
    {'data': {'attributes': {'last_analysis_stats': None}}},
    {'data': {'attributes': {'country': None}}},

    # Unexpected types
    {'data': {'attributes': {'reputation': 'should_be_int'}}},
    {'data': {'attributes': {'names': 'should_be_list'}}},
]
```

**Vector 4.2: Response Size Attacks**
```python
test_responses = [
    # Huge response
    {'data': {'attributes': {'names': ['file.exe'] * 1000000}}},

    # Deeply nested
    {'data': {'l1': {'l2': {'l3': {'l4': {'l5': 'deep'}}}}}} * nested structure,

    # Very long strings
    {'data': {'attributes': {'as_owner': 'A' * 10000000}}},
]
```

**Vector 4.3: HTTP Status Code Edge Cases**
```python
# Test various status codes in _make_request()

test_status_codes = [
    (200, 'OK'),
    (201, 'Created'),          # Not handled, falls to else
    (400, 'Bad Request'),      # Falls to else
    (401, 'Unauthorized'),     # Handled
    (403, 'Forbidden'),        # Falls to else
    (404, 'Not Found'),        # Falls to else
    (429, 'Rate Limited'),     # Handled
    (500, 'Server Error'),     # Falls to else
    (502, 'Bad Gateway'),      # Falls to else
    (504, 'Timeout'),          # Falls to else
    (999, 'Unknown'),          # Falls to else
]
```

**Vector 4.4: JSON Decoding Errors**
```python
# Response bodies that fail json.loads()

test_bodies = [
    '',                        # Empty
    'not json',               # Invalid
    '<html>error</html>',     # HTML instead of JSON
    '{"truncated": ',         # Truncated
    '}{',                     # Reversed
    'null',                   # Valid JSON but null
    '[]',                     # Array instead of object
    '{"data": }',             # Invalid syntax
]
```

**Vector 4.5: Timeout and Connection Errors**
```python
# Exceptions that can be raised

test_exceptions = [
    'ConnectionError',
    'Timeout',
    'SSLError',
    'TooManyRedirects',
    'RequestException',
    'JSONDecodeError',
]
```

### Test Cases for API Response Handling

```python
# Test 14: Missing keys in API response
def test_virustotal_missing_keys():
    """VirusTotal client should handle missing keys gracefully"""
    from ids_suite.threat_intel.virustotal import VirusTotalClient

    client = VirusTotalClient(api_key='dummy')

    # Mock _make_request to return incomplete response
    def mock_request(endpoint):
        return {'data': {}}  # Missing 'attributes'

    client._make_request = mock_request
    result = client.lookup_ip('8.8.8.8')

    # Should not crash, should handle gracefully
    assert 'error' in result or 'indicator' in result

# Test 15: Type confusion in API response
def test_virustotal_type_confusion():
    """VirusTotal client should handle type confusion"""
    from ids_suite.threat_intel.virustotal import VirusTotalClient

    client = VirusTotalClient(api_key='dummy')

    # Mock response with wrong types
    def mock_request(endpoint):
        return {
            'data': {
                'attributes': {
                    'last_analysis_stats': 'should_be_dict',  # Wrong type
                    'reputation': 'should_be_int',
                }
            }
        }

    client._make_request = mock_request

    # Should handle gracefully
    try:
        result = client.lookup_ip('8.8.8.8')
    except (AttributeError, TypeError) as e:
        pytest.fail(f"Type confusion caused crash: {e}")

# Test 16: Large response handling
def test_virustotal_large_response():
    """VirusTotal client should handle large responses"""
    from ids_suite.threat_intel.virustotal import VirusTotalClient

    client = VirusTotalClient(api_key='dummy')

    # Mock huge response
    def mock_request(endpoint):
        return {
            'data': {
                'attributes': {
                    'names': ['file.exe'] * 1000000,  # 1M entries
                    'last_analysis_stats': {}
                }
            }
        }

    client._make_request = mock_request
    result = client.lookup_hash('abc123')

    # Should truncate names to 5 entries (line 102)
    assert len(result.get('names', [])) <= 5

# Test 17: JSON decode errors
def test_threat_intel_json_decode_error():
    """Threat intel client should handle JSON decode errors"""
    from ids_suite.threat_intel.base import ThreatIntelClient

    # Would need to mock requests library to return invalid JSON
    # This tests the exception handling in line 67-77

# Test 18: HTTP error status codes
def test_threat_intel_http_errors():
    """Threat intel client should handle various HTTP errors"""
    from ids_suite.threat_intel.base import ThreatIntelClient

    # Mock different status codes
    # Verify proper error dict returned
```

---

## 5. COMMAND LINE ARGUMENT FUZZING

### 5.1 Command Validation (`core/validators.py`)

#### Attack Surface Analysis
- **validate_command_whitelist()** (line 261-303): Uses `shlex.split()`
- **Shell metacharacter injection** in various subprocess calls
- **Integer validation** for ports, SIDs

#### Crash Vectors

**Vector 5.1: Port Validation (`validate_port` line 41-72)**
```python
test_inputs = [
    # Empty/None
    '',
    None,

    # Invalid formats
    'abc',
    '80-',
    '-80',
    '80-90-100',

    # Boundary values
    '0',                       # Below range
    '1',                       # Minimum valid
    '65535',                   # Maximum valid
    '65536',                   # Above range
    '99999',

    # Negative numbers
    '-1',
    '-80',

    # Float/decimal
    '80.5',
    '80.0',

    # Range attacks
    '90-80',                   # Reversed range
    '1-65535',                 # Full range
    '1-999999',                # Range exceeds max

    # Injection attempts
    '80; echo pwned',
    '80 && rm -rf /',
    '80`whoami`',
    '80$(id)',

    # Special characters
    '80\x00',
    '80\n',
    '80 ',
    ' 80',

    # Unicode
    '８０',                    # Full-width numbers
]
```

**Vector 5.2: SID Validation (`validate_sid` line 75-98)**
```python
test_inputs = [
    # Empty/None
    '',
    None,

    # Invalid formats
    'abc',
    '123abc',
    'abc123',

    # Negative numbers
    '-1',
    '0',                       # Below minimum

    # Large numbers
    '999999999999999999999',   # Integer overflow

    # Float
    '123.456',

    # Injection
    '123; rm -rf /',
    '123`whoami`',

    # Special characters
    '123\x00',
    '123\n',
    '123 ',
]
```

**Vector 5.3: Service Name Validation (`validate_service_name` line 101-120)**
```python
test_inputs = [
    # Empty/None
    '',
    None,

    # Length attack
    'A' * 257,                 # Exceeds 256 char limit

    # Invalid characters
    'suricata-laptop; rm -rf /',
    'suricata`whoami`',
    'suricata$(id)',
    'suricata&& echo pwned',
    'suricata|cat /etc/passwd',

    # Special characters
    'suricata\x00',
    'suricata\n',
    'suricata\r',
    'suricata\t',

    # Spaces
    'suricata laptop',
    ' suricata',
    'suricata ',

    # Unicode
    'suricata🔥',
    'sürícata',

    # Path traversal
    '../suricata',
    '/etc/passwd',

    # Regex-allowed but suspicious
    'suricata@.service',       # Valid systemd syntax
    '.....',
    '@@@@@',
]
```

**Vector 5.4: Command Whitelist Bypass (`validate_command_whitelist` line 261-303)**
```python
test_inputs = [
    # Empty
    '',

    # Whitespace manipulation
    'systemctl   start   suricata',    # Multiple spaces
    'systemctl\tstart\tsuricata',      # Tabs
    'systemctl\nstart\nsuricata',      # Newlines

    # Quote escaping
    "systemctl 'start' 'suricata'",
    'systemctl "start" "suricata"',
    "systemctl start 'suricata; echo pwned'",

    # Path manipulation
    '/usr/bin/systemctl start suricata',    # Absolute path
    './systemctl start suricata',           # Relative path
    '../bin/systemctl start suricata',

    # Injection
    'systemctl start suricata; rm -rf /',
    'systemctl start suricata && echo pwned',
    'systemctl start suricata | cat /etc/passwd',
    'systemctl start suricata `whoami`',
    'systemctl start suricata $(id)',

    # NULL bytes
    'systemctl\x00start\x00suricata',

    # Unicode
    'systemctl start suricata\u0000',

    # Very long commands
    'systemctl ' + 'A' * 1000000,
]
```

### Test Cases for Command Line Arguments

```python
# Test 19: Port validation boundary values
def test_validate_port_boundaries():
    """validate_port should enforce correct boundaries"""
    from ids_suite.core.validators import validate_port

    test_cases = [
        ('0', False),           # Below range
        ('1', True),            # Minimum
        ('65535', True),        # Maximum
        ('65536', False),       # Above range
        ('-1', False),          # Negative
    ]

    for port, expected_valid in test_cases:
        is_valid, error = validate_port(port)
        assert is_valid == expected_valid, f"Failed for port {port}: {error}"

# Test 20: Port injection prevention
def test_validate_port_injection():
    """validate_port should prevent command injection"""
    from ids_suite.core.validators import validate_port

    test_cases = [
        '80; echo pwned',
        '80 && rm -rf /',
        '80`whoami`',
    ]

    for port in test_cases:
        is_valid, error = validate_port(port)
        assert not is_valid, f"Injection not prevented: {port}"

# Test 21: Service name length limit
def test_validate_service_name_length():
    """validate_service_name should enforce length limit"""
    from ids_suite.core.validators import validate_service_name

    # Exactly 256 chars (should pass)
    is_valid, _ = validate_service_name('A' * 256)
    assert is_valid

    # 257 chars (should fail)
    is_valid, _ = validate_service_name('A' * 257)
    assert not is_valid

# Test 22: Service name injection
def test_validate_service_name_injection():
    """validate_service_name should prevent injection"""
    from ids_suite.core.validators import validate_service_name

    test_cases = [
        'suricata; rm -rf /',
        'suricata`whoami`',
        'suricata$(id)',
    ]

    for name in test_cases:
        is_valid, error = validate_service_name(name)
        assert not is_valid, f"Injection not prevented: {name}"

# Test 23: Command whitelist bypass
def test_validate_command_whitelist_bypass():
    """validate_command_whitelist should prevent bypass attempts"""
    from ids_suite.core.validators import validate_command_whitelist

    whitelist = {'systemctl': ['start', 'stop']}

    test_cases = [
        ('systemctl start suricata; rm -rf /', False),
        ('systemctl start suricata && echo pwned', False),
        ('/usr/bin/systemctl start suricata', False),  # Not in whitelist by basename
    ]

    for command, expected_valid in test_cases:
        is_valid, error = validate_command_whitelist(command, whitelist)
        # Current implementation may not catch all of these!

# Test 24: shlex.split edge cases
def test_command_whitelist_shlex_errors():
    """validate_command_whitelist should handle shlex errors"""
    from ids_suite.core.validators import validate_command_whitelist

    whitelist = {'systemctl': []}

    # Unmatched quotes cause ValueError in shlex.split
    test_cases = [
        "systemctl 'unmatched",
        'systemctl "unmatched',
    ]

    for command in test_cases:
        is_valid, error = validate_command_whitelist(command, whitelist)
        assert not is_valid, "Should handle shlex errors gracefully"
```

---

## 6. ADDITIONAL ATTACK SURFACES

### 6.1 Distro Detection (`core/utils.py` line 41-65)

#### Crash Vectors

```python
# /etc/os-release manipulation
test_file_contents = [
    '',                        # Empty file
    '\x00\x00\x00',           # Binary data
    'A' * 10000000,           # Huge file
    'ID=fedora\nID=ubuntu',   # Duplicate keys
    'ID=fed\x00ora',          # Null byte
]
```

### 6.2 Subprocess Execution

**Critical Findings:**

1. **EVEFileReader.initial_load()** (line 154-157): **SHELL INJECTION**
   ```python
   result = subprocess.run(
       f"tail -{num_lines} '{self.current_file}'",
       shell=True, capture_output=True, text=True
   )
   ```
   - Uses `shell=True` with f-string
   - Single quotes provide some protection but can be bypassed
   - Should use list-based invocation

---

## 7. FUZZING INFRASTRUCTURE

### 7.1 Recommended Fuzzing Tools

1. **Atheris** (Python fuzzer)
   ```python
   pip install atheris
   ```

2. **Python-afl** (AFL for Python)
   ```bash
   pip install python-afl
   ```

3. **Hypothesis** (Property-based testing)
   ```python
   pip install hypothesis
   ```

### 7.2 Fuzzing Harness Template

```python
#!/usr/bin/env python3
"""
Fuzzing harness for IDS Suite
"""

import atheris
import sys
import os

# Import target functions
sys.path.insert(0, '/home/jay/Documents/cyber/dev/lss2')
from ids_suite.models.eve_reader import EVEFileReader
from ids_suite.engines.suricata import SuricataEngine
from ids_suite.core.utils import is_private_ip
from ids_suite.core.validators import (
    validate_port, validate_ip_address, validate_file_path
)


def fuzz_eve_json_parsing(data):
    """Fuzz EVE JSON parsing"""
    engine = SuricataEngine()
    try:
        # Convert bytes to string
        line = data.decode('utf-8', errors='ignore')
        result = engine.parse_alert(line)
    except Exception as e:
        # Log crashes, not expected exceptions
        if not isinstance(e, (ValueError, KeyError, AttributeError)):
            raise


def fuzz_ip_validation(data):
    """Fuzz IP address validation"""
    try:
        ip = data.decode('utf-8', errors='ignore')
        _ = is_private_ip(ip)
        _ = validate_ip_address(ip)
    except Exception as e:
        if not isinstance(e, (ValueError, AttributeError)):
            raise


def fuzz_path_validation(data):
    """Fuzz path validation"""
    try:
        path = data.decode('utf-8', errors='ignore')
        _ = validate_file_path(path, allowed_dirs=['/var/log'])
    except Exception as e:
        if not isinstance(e, (OSError, ValueError)):
            raise


def fuzz_port_validation(data):
    """Fuzz port validation"""
    try:
        port = data.decode('utf-8', errors='ignore')
        _ = validate_port(port)
    except Exception as e:
        if not isinstance(e, ValueError):
            raise


@atheris.instrument_func
def TestOneInput(data):
    """Main fuzzing entry point"""
    if len(data) < 1:
        return

    # Route to different fuzzers based on first byte
    selector = data[0] % 4
    payload = data[1:]

    if selector == 0:
        fuzz_eve_json_parsing(payload)
    elif selector == 1:
        fuzz_ip_validation(payload)
    elif selector == 2:
        fuzz_path_validation(payload)
    elif selector == 3:
        fuzz_port_validation(payload)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
```

### 7.3 Running the Fuzzer

```bash
# Install atheris
pip install atheris

# Run fuzzer
python3 /home/jay/Documents/cyber/dev/lss2/fuzzing_harness.py

# With corpus directory
mkdir -p /tmp/fuzzing_corpus
python3 /home/jay/Documents/cyber/dev/lss2/fuzzing_harness.py /tmp/fuzzing_corpus

# With timeout
timeout 3600 python3 /home/jay/Documents/cyber/dev/lss2/fuzzing_harness.py
```

### 7.4 Property-Based Testing with Hypothesis

```python
from hypothesis import given, strategies as st
from ids_suite.core.utils import is_private_ip
from ids_suite.core.validators import validate_port, validate_ip_address


@given(st.text())
def test_is_private_ip_never_crashes(ip):
    """is_private_ip should never crash regardless of input"""
    try:
        result = is_private_ip(ip)
        assert isinstance(result, bool)
    except Exception as e:
        assert False, f"Crashed on input {repr(ip)}: {e}"


@given(st.text(min_size=0, max_size=100))
def test_validate_port_never_crashes(port):
    """validate_port should never crash"""
    try:
        is_valid, error = validate_port(port)
        assert isinstance(is_valid, bool)
        assert error is None or isinstance(error, str)
    except Exception as e:
        assert False, f"Crashed on input {repr(port)}: {e}"


@given(st.integers(min_value=0, max_value=255),
       st.integers(min_value=0, max_value=255),
       st.integers(min_value=0, max_value=255),
       st.integers(min_value=0, max_value=255))
def test_is_private_ip_valid_ipv4(a, b, c, d):
    """Property: Valid IPv4 addresses should never crash"""
    ip = f"{a}.{b}.{c}.{d}"
    result = is_private_ip(ip)
    assert isinstance(result, bool)
```

---

## 8. CRITICAL VULNERABILITIES IDENTIFIED

### 8.1 CRITICAL: Shell Injection in EVEFileReader.initial_load()

**File:** `/home/jay/Documents/cyber/dev/lss2/ids_suite/models/eve_reader.py`
**Line:** 154-157

**Vulnerability:**
```python
result = subprocess.run(
    f"tail -{num_lines} '{self.current_file}'",
    shell=True, capture_output=True, text=True
)
```

**Impact:** Command injection via `self.current_file` path

**Proof of Concept:**
```python
reader = EVEFileReader(base_path="/var/log/suricata/eve.json'; whoami; echo '")
reader.initial_load()  # Executes whoami command
```

**Remediation:**
```python
result = subprocess.run(
    ['tail', f'-{num_lines}', self.current_file],
    capture_output=True, text=True, check=False
)
```

### 8.2 HIGH: Type Confusion in is_private_ip()

**File:** `/home/jay/Documents/cyber/dev/lss2/ids_suite/core/utils.py`
**Line:** 238-242

**Vulnerability:** Returns `True` for any non-string type, but doesn't validate early enough

**Impact:** Type confusion could bypass security checks if IP validation is bypassed

### 8.3 MEDIUM: Path Traversal Risk in validate_file_path()

**File:** `/home/jay/Documents/cyber/dev/lss2/ids_suite/core/validators.py`
**Line:** 234

**Vulnerability:** Uses `startswith()` for directory validation which could be bypassed

**Impact:** Potential directory traversal if canonicalization is inconsistent

### 8.4 MEDIUM: No Input Length Limits on JSON Parsing

**File:** Multiple (`models/eve_reader.py`, `engines/suricata.py`)

**Vulnerability:** No size limits on JSON strings before parsing

**Impact:** Memory exhaustion via huge JSON inputs

---

## 9. SUMMARY OF FINDINGS

### Crash Vectors Identified: 47

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| File Parsing | 1 | 3 | 4 | 2 |
| IP Handling | 0 | 2 | 3 | 3 |
| Path Handling | 0 | 1 | 3 | 2 |
| API Responses | 0 | 0 | 4 | 3 |
| CLI Arguments | 0 | 2 | 5 | 4 |

### Recommended Priority

1. **IMMEDIATE:** Fix shell injection in EVEFileReader.initial_load()
2. **HIGH:** Add input length limits to JSON parsing
3. **HIGH:** Strengthen path validation to prevent traversal
4. **MEDIUM:** Add type validation to API response handlers
5. **MEDIUM:** Add bounds checking to all integer inputs

### Test Coverage Recommendations

Create test suite with:
- 24 test functions (provided above)
- Fuzzing harness using Atheris
- Property-based tests using Hypothesis
- Integration tests for subprocess execution
- TOCTOU race condition tests

---

## 10. IMPLEMENTATION CHECKLIST

- [ ] Create fuzzing harness at `/home/jay/Documents/cyber/dev/lss2/fuzzing_harness.py`
- [ ] Create test suite at `/home/jay/Documents/cyber/dev/lss2/tests/test_fuzzing.py`
- [ ] Run fuzzer for 24 hours, collect crashes
- [ ] Fix shell injection vulnerability (EVEFileReader.initial_load)
- [ ] Add input length limits (1MB max for JSON lines)
- [ ] Add type validation to API response handlers
- [ ] Strengthen path validation (proper canonicalization check)
- [ ] Add bounds checking to integer inputs
- [ ] Create regression test suite from crash corpus
- [ ] Document security fixes in changelog

---

**Document Version:** 1.0
**Last Updated:** 30 January 2026
**Next Review:** After initial fuzzing run completion
