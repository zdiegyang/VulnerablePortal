import os 
import re
import magic 

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf"}
ALLOWED_MIME_TYPES = {"image/png", "image/jpeg", "application/pdf"}


def allowed_file(filename):
    """Checks if a file is allowed given the specified allowed extensions. 
    Used as initial filtering before inital scans take place."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def is_safe_scan(filepath):
    """Scans a file to determine if it is safe. Deletes dangerous files. Lightweight approach."""
    
    if os.path.exists(filepath) and (is_executable(filepath) or not is_safe_file(filepath)):
        try:
            os.remove(filepath)
            print(f"Removed unsafe file: {filepath}")
        except Exception as e:
            print(f"Failed to remove {filepath}: {e}")
        return False
    
    return True


def is_safe_file(filepath):
    """Checks if a file is safe using MIME type detection (magic + libmagic)."""
    
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(filepath)
    
    # Block known dangerous types
    dangerous_types = {
        "application/x-msdownload",    # Windows EXE
        "application/x-dosexec",       # Windows EXE
        "application/x-executable",    # Generic binary executable
        "application/x-mach-binary",   # macOS Mach-O binary
        "application/x-sharedlib",     # Shared libraries (.so)
        "application/x-pie-executable",# Position-independent executable
        "application/x-shellscript",   # Shell scripts (.sh)
        "text/x-python",               # Python scripts (.py)
        "application/javascript",      # JavaScript files (.js)
        "application/x-powershell",    # PowerShell scripts (.ps1)
        "text/html",                   # HTML files 
    }

    if file_type in dangerous_types:
        if file_type == "text/html":
            return not contains_malicious_html(filepath)
        return False  # Block all other dangerous types
        
    return True


def is_executable(filepath):
    """Checks if a file is an executable using extension, magic numbers, and Unix permissions."""
    
    # Step 1: Check file extension
    EXECUTABLE_EXTENSIONS = {".exe", ".bat", ".cmd", ".sh", ".bin", ".msi", ".dll", ".app", ".py", ".js", ".ps1"}
    _, ext = os.path.splitext(filepath)
    if ext.lower() in EXECUTABLE_EXTENSIONS:
        return True

    # Step 2: Check magic numbers (file headers)
    try:
        with open(filepath, "rb") as f:
            header = f.read(4)

            # Windows EXE (MZ header)
            if header[:2] == b"MZ":
                return True

            # Linux/macOS ELF (ELF header)
            if header == b"\x7fELF":
                return True

            # macOS Mach-O binaries
            mach_o_signatures = {b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCA\xFE\xBA\xBE"}
            if header in mach_o_signatures:
                return True

    except Exception:
        return False  # Fail-safe if we can't read the file

    # Step 3: Check execute permissions (Unix)
    if os.name != "nt" and os.access(filepath, os.X_OK):
        return True

    return False  # Not an executable



def contains_malicious_html(filepath):
    """Scans an HTML file for suspicious JavaScript, obfuscation, or iframe injections."""
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Look for suspicious JavaScript patterns
        js_patterns = [
            r"<script.*?>",            # Inline JavaScript
            r"eval\(",                 # Executing strings as code
            r"document\.write\(",      # Writing dynamic content
            r"window\.location\s*=",   # Redirects
            r"onload\s*=",             # Auto-executing scripts
            r"setTimeout\s*\(",        # Delayed execution (often obfuscation)
            r"unescape\(",             # Decoding hidden data
            r"atob\(",                 # Base64 decoding
        ]

        # Look for suspicious iframes (malicious redirects)
        iframe_patterns = [
            r"<iframe.*?src=['\"]?http",  # External iframe loading
            r"frameborder=['\"]?0",      # Hidden iframe (phishing)
        ]

        # Check for encoded JavaScript or Base64 payloads
        encoded_patterns = [
            r"base64,",         # Base64-encoded payload
            r"fromCharCode\(",  # JS string obfuscation
        ]

        # Combine patterns and search
        all_patterns = js_patterns + iframe_patterns + encoded_patterns
        for pattern in all_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                print(f"Suspicious HTML detected in {filepath}")
                return True  # File contains suspicious content

    except Exception:
        return False  # Fail-safe if we can't read the file

    return False  # No malicious patterns detected