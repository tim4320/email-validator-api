from flask import Flask, request, jsonify, abort
from email_validator import validate_email, EmailNotValidError
import dns.resolver
import smtplib
import os
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from difflib import get_close_matches

# Load environment variables
load_dotenv()
API_KEY = os.getenv("API_KEY", None)

app = Flask(__name__)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per minute"]
)

# Load disposable domains
with open("disposable_domains.txt") as f:
    DISPOSABLE_DOMAINS = set([line.strip() for line in f])

# Common free providers
FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "aol.com", "protonmail.com"
}

# Common role accounts
ROLE_ACCOUNTS = {
    "admin", "support", "info", "sales", "help", "billing",
    "contact", "webmaster", "jobs"
}

# Used for suggested correction
KNOWN_DOMAINS = list(FREE_PROVIDERS.union(DISPOSABLE_DOMAINS))

# API key middleware
def require_api_key(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if API_KEY:
            supplied = request.headers.get("X-API-Key")
            if supplied != API_KEY:
                abort(401)
        return f(*args, **kwargs)
    return wrapper

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name": "Email Validator API",
        "status": "running",
        "endpoints": {
            "POST /validate": {"body": {"email": "user@example.com"}}
        }
    })

@app.route("/health", methods=["GET"])
def health():
    return "OK", 200

@app.route("/validate", methods=["POST"])
@require_api_key
@limiter.limit("10/second;1000/day")
def validate():
    data = request.get_json()
    email = data.get("email", "")
    result = {
        "email": email,
        "valid_format": False,
        "disposable": False,
        "mx_found": False,
        "smtp_check": False,
        "domain": None,
        "is_role_account": False,
        "is_free_provider": False,
        "suggested_correction": None
    }

    try:
        v = validate_email(email)
        normalized_email = v.normalized
        result["email"] = normalized_email
        result["valid_format"] = True
    except EmailNotValidError:
        return jsonify(result)

    local_part, domain = normalized_email.split("@")
    domain = domain.lower()
    result["domain"] = domain

    if domain in DISPOSABLE_DOMAINS:
        result["disposable"] = True

    if domain in FREE_PROVIDERS:
        result["is_free_provider"] = True

    if local_part.lower() in ROLE_ACCOUNTS:
        result["is_role_account"] = True

    close_matches = get_close_matches(domain, KNOWN_DOMAINS, n=1, cutoff=0.8)
    if close_matches and close_matches[0] != domain:
        result["suggested_correction"] = f"{local_part}@{close_matches[0]}"

    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        result["mx_found"] = True
    except:
        return jsonify(result)

    try:
        smtp = smtplib.SMTP(timeout=5)
        smtp.connect(str(mx_records[0].exchange))
        smtp.helo()
        smtp.mail("you@yourdomain.com")
        code, _ = smtp.rcpt(normalized_email)
        smtp.quit()
        result["smtp_check"] = (code == 250 or code == 251)
    except:
        pass

    return jsonify(result)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
