from flask import Flask, request, redirect, render_template, make_response, url_for
from urllib.parse import urlparse
import validators
import hashlib, hmac


app = Flask(__name__)
app.config.from_pyfile("config.py")


@app.errorhandler(500)
def handleInternalError(error):
    return render_template("error.html", text="500 | Internal Server Error"), 500

@app.errorhandler(404)
def handleNotFoundError(error):
	return render_template("error.html", text=f"404 | Not Found"), 404

def forbiddenRequest(message: str = "Request was forbidden", code: int = 403):
	return render_template("error.html", text=f"{code} | {message}"), code

def badRequest(message: str = "Bad request", code: int = 400):
	return render_template("error.html", text=f"{code} | {message}"), code

ROUTES = app.config["ROUTES"]


@app.route(ROUTES["HOME"], methods=["GET"])
def home():
    return render_template("index.html")


@app.route(ROUTES["AUTH_LOGIN"], methods=["GET","POST"])
def login():

	if request.method == "GET":

		if request.cookies.get("dev_token"):
			return redirect(url_for("dashboard"))
		returnUrl = request.args.get("returnUrl")
		if returnUrl:
			return render_template("login.html", returnUrl=returnUrl)
		else:
			return render_template("login.html")

	elif request.method == "POST":
		
		username = request.form.get("username")
		password = request.form.get("password")
		returnUrl = request.form.get("returnUrl")

		if username and password:
			if username == app.config["USERNAME"] and password == app.config["PASSWORD"]:
				# login was successful
				if returnUrl:
					response = make_response(redirect(url_for("dashboard", returnUrl=returnUrl)))
				else:
					response = make_response(redirect(url_for("dashboard")))

				response.set_cookie("dev_token", app.config["DEV_TOKEN"], samesite="Lax")
				return response
			else:
				if returnUrl:
					return render_template("login.html", message="Login failed",  returnUrl=returnUrl)
				else:
					return render_template("login.html", message="Login failed")
		else:
			return render_template("login.html", message="Login failed")


@app.route(ROUTES["AUTH_LOGOUT"], methods=["GET"])
def logout():

	response = make_response(redirect(url_for("login")))
	response.set_cookie("dev_token", "", samesite="Lax")
	return response


@app.route(ROUTES["CHECKOUT"])
def checkout():

	response = make_response(render_template("checkout.html"))
	if app.config["CSP"]:
		response.headers["Content-Security-Policy"] = "script-src 'self' https://ajax.googleapis.com"
	return response


@app.route(ROUTES["DASHBOARD_PROFILE"], methods=["GET"])
@app.route(ROUTES["DASHBOARD_USERS"], methods=["GET"])
@app.route(ROUTES["DASHBOARD"], methods=["GET"])
def dashboard():

	dev_token = request.cookies.get("dev_token")
	if dev_token:
		if dev_token == app.config["DEV_TOKEN"]:
			if request.path == ROUTES["DASHBOARD"]:
				response = make_response(render_template("admin.html", text="Welcome Admin | Admin Dashboard"))
			elif request.path == ROUTES["DASHBOARD_PROFILE"]:
				response = make_response(render_template("admin.html", text="Admin Profile"))
			elif request.path == ROUTES["DASHBOARD_USERS"]:
				response = make_response(render_template("admin.html", text="Users list"))
			return response
		else:
			# Token tampered
			return redirect(url_for("logout"))
	else:
		# Token not sent
		return redirect(url_for("login", returnUrl=request.path))


@app.route(ROUTES["REDIRECT"], methods=["GET"])
def redirection():

	dest = request.args.get("dest")
	if dest is None:
		return badRequest("missing 'dest' parameter")
	level = request.args.get("level")
	if level is None:
		return badRequest("missing 'level' parameter")
	else:
		if request.args.get("level").isnumeric():
			level = int(level)
		else:
			# Deafult level
			level = 0

	TRUSTED_SCHEMES = app.config["TRUSTED_SCHEMES"]
	TRUSTED_DOMAINS = app.config["TRUSTED_DOMAINS"]
	TRUSTED_URLS = app.config["TRUSTED_URLS"]
	dest_scheme = urlparse(dest).netloc
	dest_domain = urlparse(dest).scheme
	ERRORS = app.config["ERRORS"]

	if level == 0:
	
		return redirect(dest)

	elif level == 1:
		# Deny External Redirect: Bypass=> dest=//evil.com

		if dest.startswith("/"):
			return redirect(dest)
		else:
			return forbiddenRequest("External URL Detected")

	elif level == 2:
		# Allow subdomains to redirect: Bypass => dest=https://evil.com/google.com

		for index,trusted_domain in enumerate(TRUSTED_DOMAINS):
			if trusted_domain in dest:
				return redirect(dest)
			else:
				if index == len(TRUSTED_DOMAINS) - 1:
					return forbiddenRequest(ERRORS["domain_forbidden"])

	elif level == 3:
		# Allow subdomains to redirect: Bypass => dest=https://google.com.evil.com

		for index,trusted_domain in enumerate(TRUSTED_DOMAINS):
			if trusted_domain in dest_domain:
				return redirect(dest)
			else:
				if index == len(TRUSTED_DOMAINS) - 1:
					return forbiddenRequest(ERRORS["domain_forbidden"])

	elif level == 4:
		# Allow subdomains to redirect: It is Safe.

		for index,trusted_domain in enumerate(TRUSTED_DOMAINS):
			if trusted_domain == dest_domain:
				return redirect(dest)
			else:
				if index == len(TRUSTED_DOMAINS) - 1:
					return forbiddenRequest(ERRORS["domain_forbidden"])

	elif level == 5:
		# Check URL starts with canonical URLs: Bypass => dest=https://securityflaws.net@evil.com/

		for index,trusted_url in enumerate(TRUSTED_URLS):
			if dest.startswith(trusted_url):
				return redirect(dest)
			else:
				if index == len(TRUSTED_URLS) - 1:
					return forbiddenRequest(ERRORS["domain_forbidden"])

	elif level == 6:
		# Allow whitelist and subdomains redirection: It is Safe.

		# Scheme validation: validation with urlparse
		if dest_scheme not in TRUSTED_SCHEMES["urlparse_compatible"]:
			return forbiddenRequest(ERRORS["scheme_forbidden"])

		# Scheme validation: Don't process malformed schemes | check trailing slashes
		if dest[0:7] not in TRUSTED_SCHEMES["trailing_slash"] and dest[0:8] not in TRUSTED_SCHEMES["trailing_slash"]:
			return forbiddenRequest(ERRORS["scheme_forbidden"])

		# Validate the domain: Don't allow malformed domains like securityflaws.net@evil.com
		try:
			validators.domain(dest_domain)
		except validators.ValidationFailure:
			return forbiddenRequest(ERRORS["domain_forbidden"])

		for index,trusted_domain in enumerate(TRUSTED_DOMAINS):
			if dest_domain.endswith(trusted_domain):
				return redirect(dest)
			else:
				if index == len(TRUSTED_DOMAINS) - 1:
					return forbiddenRequest(ERRORS["domain_forbidden"])

	elif level == 10:
		# Hash Protection: Can be calculated in client side

		signature = request.args.get("sig")
		if signature:
			if signature == hashlib.sha512(dest.encode('utf-8')).hexdigest():
				return redirect(dest)
			else:
				return forbiddenRequest(ERRORS["signature_invalid"])
		else:
			return badRequest("Missing 'sig' parameter")

	elif level == 11:
		# HMAC protection

		hmac_secret = app.config["HMAC_SECRET"]
		signature = request.args.get("sig")
		if signature:
			if signature == hmac.new(hmac_secret.encode(), dest.encode(), hashlib.sha512).hexdigest():
				return redirect(dest)
			else:
				return forbiddenRequest(ERRORS["signature_invalid"])

		else:
			dest = TRUSTED_URLS[1] # https://google.com

			signature = hmac.new(hmac_secret.encode(), dest.encode(), hashlib.sha512).hexdigest()
			return redirect(url_for("redirection",dest=dest, level=11, sig=signature))
			# try to redirect to https://evil.com
			# local.securityflaws.net:5000/redirect/?dest=https://evil.com&level=11&sig=1af20f50fb66acb226bf381b57327e6c4e9628a9ec3be4fffc0ba4346ba7de69bccd18c3e193e65b8697e29bcac1df37abcac130a1b2ecfb76dd65451f493dfb


if __name__ == "__main__":
	app.run(debug=True)
