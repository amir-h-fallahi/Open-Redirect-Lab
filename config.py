
TRUSTED_SCHEMES = {
    "default": ["http","https"],
    "urlparse_compatible": ["http:","https:"],
    "trailing_slash": ["http://","https://"]
}
TRUSTED_DOMAINS =  ["securityflaws.net","google.com"]
TRUSTED_URLS = ["http://securityflaws.net","https://google.com"]
CSP = False
USERNAME = "admin"
PASSWORD = "admin"
HMAC_SECRET = "sEcRet"
DEV_TOKEN = "5c43f86a-0eee-44ff-8787-d1e230c55c58"
ROUTES = {
	"HOME": "/",
	"AUTH_LOGIN": "/auth/login/",
    "AUTH_LOGOUT": "/auth/logout/",
	"CHECKOUT": "/checkout/",
	"REDIRECT": "/redirect/",
	"DASHBOARD": "/dashboard/",
	"DASHBOARD_PROFILE": "/dashboard/profile/",
	"DASHBOARD_USERS": "/dashboard/users/"
}
ERRORS = {
    "domain_forbidden": "Destination domain is forbidden",
    "scheme_forbiden": "Destination scheme is forbidden",
    "signature_invalid": "Signature is invalid"
}