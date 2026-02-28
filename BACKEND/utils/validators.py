"""
Input validation utilities for user inputs and data validation
"""

import re
import logging
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, date
from typing import Tuple, Union, List, Optional
import html
import bleach

# Configure logging
logger = logging.getLogger(__name__)

# Constants for validation
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 80
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
EMAIL_MAX_LENGTH = 120
NAME_MAX_LENGTH = 100
TEXT_MAX_LENGTH = 5000
SUBJECT_MAX_LENGTH = 200

# Regex patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')
PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]')
PHONE_PATTERN = re.compile(r'^\+?1?\d{9,15}$')
IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
URL_PATTERN = re.compile(r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$')
HEX_COLOR_PATTERN = re.compile(r'^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$')
ALPHA_PATTERN = re.compile(r'^[a-zA-Z\s]+$')
ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9\s]+$')

def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format and length
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not username or not isinstance(username, str):
        return False, "Username is required"
    
    username = username.strip()
    
    if len(username) < USERNAME_MIN_LENGTH:
        return False, f"Username must be at least {USERNAME_MIN_LENGTH} characters long"
    
    if len(username) > USERNAME_MAX_LENGTH:
        return False, f"Username must be less than {USERNAME_MAX_LENGTH} characters"
    
    if not USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, and underscores"
    
    return True, "Username is valid"

def validate_email_address(email: str) -> Tuple[bool, Union[str, dict]]:
    """
    Validate email address format
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple of (is_valid, message or normalized_email)
    """
    if not email or not isinstance(email, str):
        return False, "Email is required"
    
    email = email.strip().lower()
    
    if len(email) > EMAIL_MAX_LENGTH:
        return False, f"Email must be less than {EMAIL_MAX_LENGTH} characters"
    
    try:
        # Validate and get normalized email
        valid = validate_email(email)
        normalized_email = valid.email
        return True, normalized_email
    except EmailNotValidError as e:
        return False, str(e)

def validate_password(password: str, check_strength: bool = True) -> Tuple[bool, str]:
    """
    Validate password strength and format
    
    Args:
        password: Password to validate
        check_strength: Whether to check password strength
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not password or not isinstance(password, str):
        return False, "Password is required"
    
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters long"
    
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f"Password must be less than {PASSWORD_MAX_LENGTH} characters"
    
    if check_strength:
        # Check for at least one lowercase letter
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for at least one uppercase letter
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for at least one digit
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        
        # Check for at least one special character
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return False, "Password must contain at least one special character"
        
        # Check for common patterns
        common_patterns = ['password', '123456', 'qwerty', 'abc123']
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns that are easy to guess"
    
    return True, "Password is valid"

def validate_full_name(name: str) -> Tuple[bool, str]:
    """
    Validate full name
    
    Args:
        name: Full name to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not name or not isinstance(name, str):
        return False, "Full name is required"
    
    name = name.strip()
    
    if len(name) < 2:
        return False, "Full name must be at least 2 characters long"
    
    if len(name) > NAME_MAX_LENGTH:
        return False, f"Full name must be less than {NAME_MAX_LENGTH} characters"
    
    if not ALPHA_PATTERN.match(name):
        return False, "Full name can only contain letters and spaces"
    
    return True, "Full name is valid"

def validate_phone(phone: str) -> Tuple[bool, str]:
    """
    Validate phone number
    
    Args:
        phone: Phone number to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not phone:
        return True, "Phone number is optional"  # Phone is optional
    
    phone = phone.strip()
    
    if PHONE_PATTERN.match(phone):
        return True, "Phone number is valid"
    else:
        return False, "Invalid phone number format"

def validate_email_content(subject: str, content: str) -> Tuple[bool, str]:
    """
    Validate email subject and content
    
    Args:
        subject: Email subject
        content: Email content
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not content or not isinstance(content, str):
        return False, "Email content is required"
    
    content = content.strip()
    
    if len(content) < 1:
        return False, "Email content cannot be empty"
    
    if len(content) > TEXT_MAX_LENGTH:
        return False, f"Email content must be less than {TEXT_MAX_LENGTH} characters"
    
    if subject and len(subject) > SUBJECT_MAX_LENGTH:
        return False, f"Email subject must be less than {SUBJECT_MAX_LENGTH} characters"
    
    return True, "Email content is valid"

def validate_ip_address(ip: str) -> Tuple[bool, str]:
    """
    Validate IP address
    
    Args:
        ip: IP address to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not ip:
        return False, "IP address is required"
    
    if IP_PATTERN.match(ip):
        return True, "IP address is valid"
    else:
        return False, "Invalid IP address format"

def validate_url(url: str) -> Tuple[bool, str]:
    """
    Validate URL
    
    Args:
        url: URL to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not url:
        return False, "URL is required"
    
    if URL_PATTERN.match(url):
        return True, "URL is valid"
    else:
        return False, "Invalid URL format"

def validate_date(date_str: str, formats: List[str] = None) -> Tuple[bool, Union[str, date]]:
    """
    Validate date string
    
    Args:
        date_str: Date string to validate
        formats: List of expected date formats
        
    Returns:
        Tuple of (is_valid, message or parsed_date)
    """
    if not date_str:
        return False, "Date is required"
    
    if formats is None:
        formats = ['%Y-%m-%d', '%d/%m/%Y', '%m/%d/%Y', '%Y/%m/%d']
    
    for fmt in formats:
        try:
            parsed_date = datetime.strptime(date_str, fmt).date()
            return True, parsed_date
        except ValueError:
            continue
    
    return False, f"Invalid date format. Expected one of: {', '.join(formats)}"

def validate_hex_color(color: str) -> Tuple[bool, str]:
    """
    Validate hex color code
    
    Args:
        color: Hex color code to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not color:
        return False, "Color is required"
    
    if HEX_COLOR_PATTERN.match(color):
        return True, "Color is valid"
    else:
        return False, "Invalid hex color format. Use #RRGGBB or #RGB"

def validate_numeric_range(value: Union[int, float], min_val: float, max_val: float, 
                           field_name: str = "Value") -> Tuple[bool, str]:
    """
    Validate numeric value within range
    
    Args:
        value: Numeric value to validate
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        field_name: Name of the field for error message
        
    Returns:
        Tuple of (is_valid, message)
    """
    try:
        value = float(value)
    except (TypeError, ValueError):
        return False, f"{field_name} must be a number"
    
    if value < min_val:
        return False, f"{field_name} must be at least {min_val}"
    
    if value > max_val:
        return False, f"{field_name} must be at most {max_val}"
    
    return True, f"{field_name} is valid"

def validate_required_fields(data: dict, required_fields: List[str]) -> Tuple[bool, List[str]]:
    """
    Validate that all required fields are present
    
    Args:
        data: Dictionary of data to validate
        required_fields: List of required field names
        
    Returns:
        Tuple of (is_valid, missing_fields)
    """
    if not data:
        return False, required_fields
    
    missing = [field for field in required_fields if field not in data or not data[field]]
    
    if missing:
        return False, missing
    else:
        return True, []

def sanitize_input(text: str, allowed_tags: List[str] = None) -> str:
    """
    Sanitize user input to prevent XSS attacks
    
    Args:
        text: Input text to sanitize
        allowed_tags: List of allowed HTML tags
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Convert to string
    text = str(text)
    
    # Escape HTML
    text = html.escape(text)
    
    # If allowed tags specified, use bleach to allow them
    if allowed_tags:
        text = bleach.clean(text, tags=allowed_tags, strip=True)
    
    return text

def validate_json_structure(data: dict, expected_structure: dict) -> Tuple[bool, str]:
    """
    Validate JSON data structure
    
    Args:
        data: JSON data to validate
        expected_structure: Expected structure with types
        
    Returns:
        Tuple of (is_valid, message)
    
    Example:
        expected = {
            'name': str,
            'age': int,
            'email': str,
            'optional_field': (str, None)  # Optional field
        }
    """
    if not isinstance(data, dict):
        return False, "Data must be a dictionary"
    
    for field, expected_type in expected_structure.items():
        # Check if field exists
        if field not in data:
            # Check if field is optional (tuple with None as second element)
            if isinstance(expected_type, tuple) and len(expected_type) == 2 and expected_type[1] is None:
                continue
            return False, f"Missing required field: {field}"
        
        # Check field type
        value = data[field]
        
        # Handle optional fields with type
        if isinstance(expected_type, tuple):
            expected_type = expected_type[0]
        
        if not isinstance(value, expected_type):
            return False, f"Field '{field}' must be of type {expected_type.__name__}"
    
    return True, "JSON structure is valid"

def validate_password_match(password: str, confirm_password: str) -> Tuple[bool, str]:
    """
    Validate that password and confirmation match
    
    Args:
        password: Password
        confirm_password: Password confirmation
        
    Returns:
        Tuple of (is_valid, message)
    """
    if password != confirm_password:
        return False, "Passwords do not match"
    
    return True, "Passwords match"

def validate_age(birth_date: date, min_age: int = 13) -> Tuple[bool, str]:
    """
    Validate age based on birth date
    
    Args:
        birth_date: Birth date
        min_age: Minimum age required
        
    Returns:
        Tuple of (is_valid, message)
    """
    today = date.today()
    age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
    
    if age < min_age:
        return False, f"You must be at least {min_age} years old"
    
    return True, "Age is valid"

def validate_file_extension(filename: str, allowed_extensions: List[str]) -> Tuple[bool, str]:
    """
    Validate file extension
    
    Args:
        filename: Name of the file
        allowed_extensions: List of allowed extensions
        
    Returns:
        Tuple of (is_valid, message)
    """
    if not filename or '.' not in filename:
        return False, "Invalid filename"
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if ext not in allowed_extensions:
        return False, f"File extension '{ext}' not allowed. Allowed: {', '.join(allowed_extensions)}"
    
    return True, "File extension is valid"

def validate_uuid(uuid_str: str) -> Tuple[bool, str]:
    """
    Validate UUID format
    
    Args:
        uuid_str: UUID string to validate
        
    Returns:
        Tuple of (is_valid, message)
    """
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
    
    if uuid_pattern.match(uuid_str):
        return True, "UUID is valid"
    else:
        return False, "Invalid UUID format"

def validate_boolean(value: any) -> Tuple[bool, bool]:
    """
    Convert and validate boolean values
    
    Args:
        value: Value to convert to boolean
        
    Returns:
        Tuple of (is_valid, boolean_value)
    """
    if isinstance(value, bool):
        return True, value
    
    if isinstance(value, str):
        value_lower = value.lower()
        if value_lower in ('true', 'yes', '1', 'on'):
            return True, True
        elif value_lower in ('false', 'no', '0', 'off'):
            return True, False
    
    if isinstance(value, (int, float)):
        return True, bool(value)
    
    return False, False

# Convenience function for full user registration validation
def validate_user_registration(data: dict) -> Tuple[bool, dict]:
    """
    Validate all user registration fields
    
    Args:
        data: Dictionary with user registration data
        
    Returns:
        Tuple of (is_valid, errors_dict)
    """
    errors = {}
    
    # Check required fields
    required = ['username', 'email', 'password', 'confirm_password', 'full_name']
    is_valid, missing = validate_required_fields(data, required)
    if not is_valid:
        errors['missing'] = f"Missing required fields: {', '.join(missing)}"
        return False, errors
    
    # Validate username
    is_valid, msg = validate_username(data['username'])
    if not is_valid:
        errors['username'] = msg
    
    # Validate email
    is_valid, result = validate_email_address(data['email'])
    if not is_valid:
        errors['email'] = result
    else:
        data['email'] = result  # Use normalized email
    
    # Validate password
    is_valid, msg = validate_password(data['password'])
    if not is_valid:
        errors['password'] = msg
    
    # Validate password match
    is_valid, msg = validate_password_match(data['password'], data['confirm_password'])
    if not is_valid:
        errors['confirm_password'] = msg
    
    # Validate full name
    is_valid, msg = validate_full_name(data['full_name'])
    if not is_valid:
        errors['full_name'] = msg
    
    # Validate phone if provided
    if data.get('phone'):
        is_valid, msg = validate_phone(data['phone'])
        if not is_valid:
            errors['phone'] = msg
    
    return len(errors) == 0, errors

# Convenience function for email analysis validation
def validate_email_analysis_request(data: dict) -> Tuple[bool, dict]:
    """
    Validate email analysis request
    
    Args:
        data: Dictionary with email analysis data
        
    Returns:
        Tuple of (is_valid, errors_dict)
    """
    errors = {}
    
    # Check required fields
    if 'content' not in data or not data['content']:
        errors['content'] = "Email content is required"
        return False, errors
    
    # Validate content
    subject = data.get('subject', '')
    content = data['content']
    
    is_valid, msg = validate_email_content(subject, content)
    if not is_valid:
        errors['content'] = msg
    
    return len(errors) == 0, errors

# Test function
def test_validators():
    """
    Test all validators with sample data
    """
    print("=" * 60)
    print("TESTING INPUT VALIDATORS")
    print("=" * 60)
    
    test_cases = [
        ("Username", validate_username, ["john_doe", "jo", "john@doe", "a" * 100]),
        ("Email", validate_email_address, ["test@example.com", "invalid-email", "test@.com"]),
        ("Password", validate_password, ["Test123!@#", "weak", "NoSpecial1", "nouppercase1!"]),
        ("Full Name", validate_full_name, ["John Doe", "J", "John123"]),
        ("Phone", validate_phone, ["+1234567890", "12345", "abc123"]),
        ("IP Address", validate_ip_address, ["192.168.1.1", "256.1.2.3", "abc.def.ghi.jkl"]),
        ("URL", validate_url, ["https://example.com", "not-a-url", "http://"]),
    ]
    
    for validator_name, validator_func, test_inputs in test_cases:
        print(f"\n📋 Testing {validator_name}:")
        print("-" * 40)
        
        for test_input in test_inputs:
            is_valid, result = validator_func(test_input)
            status = "✅ VALID" if is_valid else "❌ INVALID"
            result_msg = result if isinstance(result, str) else "Valid"
            print(f"   Input: '{test_input}'\n   → {status}: {result_msg}\n")
    
    # Test user registration
    print("\n📋 Testing User Registration:")
    print("-" * 40)
    
    valid_user = {
        'username': 'john_doe',
        'email': 'john@example.com',
        'password': 'Test123!@#',
        'confirm_password': 'Test123!@#',
        'full_name': 'John Doe',
        'phone': '+1234567890'
    }
    
    is_valid, errors = validate_user_registration(valid_user)
    print(f"   Valid user: {'✅ PASS' if is_valid else '❌ FAIL'}")
    if not is_valid:
        print(f"   Errors: {errors}")
    
    invalid_user = {
        'username': 'jo',
        'email': 'invalid-email',
        'password': 'weak',
        'confirm_password': 'different',
        'full_name': 'John123'
    }
    
    is_valid, errors = validate_user_registration(invalid_user)
    print(f"\n   Invalid user: {'✅ PASS' if is_valid else '❌ FAIL'}")
    if not is_valid:
        print(f"   Errors: {errors}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    # Run tests if script is executed directly
    test_validators()