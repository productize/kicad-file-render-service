
import json
from flask import Flask, request, Response, render_template, send_file
import jwt
from datetime import timezone, datetime, timedelta
import urllib.parse
from os import environ, path, makedirs
import os
from hashlib import sha256
import requests
from redis import StrictRedis
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from kicad_automation_scripts.eeschema.export_schematic import export_schematic
try:
	from secrets import token_hex as secret_token
except ImportError:
	from os import urandom
	def secret_token(nbytes=None):
		return urandom(nbytes).hex()

ADDRESS="https://blue.productize.be"
BASE_INPUT_DIR="/input"
INPUT_DIR = BASE_INPUT_DIR+"/{cset}/{path}"
BASE_OUTPUT_DIR = "./output"
OUTPUT_DIR = BASE_OUTPUT_DIR+"/{cset}/{path}"

import logging
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S')

app = Flask(__name__)
base = "/bitbucket-fileviewer"
connections_db = StrictRedis(host="connections-db")

if "FILE_RENDERER_KEY" not in environ:
	print("No FILE_RENDERER_KEY set")
	exit(1);

# File viewer modules. See https://developer.atlassian.com/cloud/bitbucket/modules/file-viewer/
# Examples:
#  - https://bitbucket.org/tpettersen/run-bucket-run/src/master/connect-account.json?at=master
#  - https://github.com/noamt/bitbucket-asciidoctor-addon/blob/master/atlassian-connect.json

schematic_viewer_pdf = {
	"key" : "kicad-schematic-pdf",
	"name": {
		"i18n": "en",
		"value": "Full schematic PDF"
	},
	"file_matches": {"extensions": ["sch"]},
	"url": "/schematic-pdf?repo_path={repo_path}&cset={file_cset}&file_path={file_path}"
}

schematic_sheet_viewer_svg = {
	"key" : "kicad-schematic-sheet-svg",
	"name": {
		"i18n": "en",
		"value": "Schematic sheet"
	},
	"file_matches": {"extensions": ["sch"]},
	"url": "/schematic-sheet-svg?repo_path={repo_path}&cset={file_cset}&file_path={file_path}"
}

# TODO: Create file viewers for kicad_pcbs, symbols and modules

# App descriptor. See https://developer.atlassian.com/cloud/bitbucket/app-descriptor/
descriptor = {
	"key": "kicad-file-viewer",
	"name": "KiCad file viewer",
	"description": "View and download KiCad schematic and layout files in the Bitbucket file viewer",
	"vendor": {
		"name": "Productize",
		"url": "https://productize.be",
	},
	"baseUrl": ADDRESS+base,
	"authentication": {
		"type": "jwt"
	},
	"lifecycle": {
		"installed": "/installed",
		"uninstalled": "/uninstalled",
	},
	"scopes": ["repository"],
	"contexts": ["account"],
	"modules": {
		"fileViews": [
			schematic_viewer_pdf,
			schematic_sheet_viewer_svg
		]
	}
}

@app.route(base+"/install", methods=['GET'])
def install():
	return json.dumps(descriptor)

def get_connection(username):
	return "/bitbucket.org/{}".format(username)

@app.route(base+descriptor["lifecycle"]["installed"], methods=['POST'])
def installed():
	print(request.data)

	cipher = AES.new(b64decode(environ["FILE_RENDERER_KEY"]), AES.MODE_GCM)

	connection = get_connection(request.json["user"]["username"])
	connections_db.set(
		connection+"/client_key",
		request.json["clientKey"]
	)
	connections_db.set(
		connection+"/secret",
		cipher.encrypt(request.json["sharedSecret"].encode("utf-8"))
	)
	connections_db.set(
		connection+"/nonce",
		b64encode(cipher.nonce)
	)
	connections_db.set(
		connection+"/api_url",
		request.json["baseApiUrl"]
	)
	access_token = secret_token(16)
	# Create an initial acces token for the Bitbucket fileviewer in the list of access tokens for quick lookup
	connections_db.sadd(
		connection+"/access_tokens",
		access_token
	)
	# Store the token in a hash so we can retrieve it
	connections_db.hset(
		connection+"/access_token_names",
		"bitbucket",
		secret_token(16),
	)
	return "Installation succesfull"

def get_username(repo_path):
	return urllib.parse.quote(repo_path.split("/")[0])

def validate_jwt(username, encoded_token):
	connection = get_connection(username)

	client_key = connections_db.get(connection+"/client_key").decode("utf-8")
	if client_key is None:
		# TODO: create a more specific exception
		raise Exception("Connection not found")

	print(client_key)
	nonce = b64decode(connections_db.get(connection+"/nonce"))
	cipher = AES.new(b64decode(environ["FILE_RENDERER_KEY"]), AES.MODE_GCM, nonce=nonce)
	secret = connections_db.get(connection+"/secret")
	secret = cipher.decrypt(secret).decode("utf-8")
	jwt.decode(encoded_token, secret, audience=client_key)
	# TODO: verify claims and validity of JWT

class Unauthorized(Exception):
    status_code = 402

    def __init__(self, message):
        Exception.__init__(self)
        self.message = message

    def to_dict(self):
        rv['message'] = self.message
        return rv

def validate_access_token(username, access_token):
	connection = get_connection(username)
	print(access_token)
	# if not connections_db.sismember(connection+"/access_tokens", access_token):
		# raise Unauthorized("Invalid access token")


@app.route(base+descriptor["lifecycle"]["uninstalled"], methods=['POST'])
def uninstalled():
	auth = request.headers["Authorization"].split(" ")
	if auth[0].upper() != "JWT":
		return "No auth"

	try:
		connection, secret = get_connection(auth[1])
	except jwt.InvalidSignatureError:
		return "JWT verification failed"
	keys = connections_db.keys("/bitbucket/{}/*".format(connection))
	connections_db.delete(keys)

	return "Uninstallation succesfull"


def create_jwt(connection, secret, endpoint, params = {}, validity=timedelta(seconds=120)):
	# See https://developer.atlassian.com/cloud/bitbucket/query-string-hash/
	canonical_request = "GET&"+endpoint+"&"
	# Adding params does not seem required, but is in spec...
	i = 0
	for p_key, p_value in params.items():
		canonical_request += "{}={}".format(p_key, urllib.parse.quote(p_value))
		i += 1
		if i < len(params)-1:
			canonical_request += "&"
	qsh = sha256(canonical_request.encode('utf-8')).hexdigest()

	# Create JWT. See https://developer.atlassian.com/cloud/bitbucket/understanding-jwt-for-apps/#claims
	now = datetime.now(tz=timezone.utc)
	return jwt.encode({
		"iss": descriptor["key"],
		"iat": int(now.timestamp()),
		"exp": int((now + validity).timestamp()),
		"qsh": qsh,
		"sub": connection
	}, secret, algorithm='HS256')

def list_files(session, client_key, base_url, secret, repo_path, path, extensions=[]):
	# TODO: fetch next instead of using big pagelen
	params = {"pagelen": "50"}

	if len(extensions) > 0:
		params["q"] = "path~\"{}\"".format(extensions[0])
		for i in range(1, len(extensions)-1):
			params["q"] += " or path~\"{}\"".format(extensions[i])
	
	endpoint = "/2.0/repositories/{repo_path}/src/{node}/{path}".format(
		repo_path = repo_path,
		node = request.args.get("cset"),
		path = path
	)

	encoded_jwt = create_jwt(client_key, secret, endpoint, params)

	print(encoded_jwt)

	r = session.get(base_url+endpoint, params=params, headers={
		'Authorization': "JWT "+encoded_jwt.decode('utf-8'),
	})

	if r.status_code != requests.codes.ok:
		print("Failed to list files")
		return []

	return r.json()["values"]

def get_and_save_file(session, client_key, base_url, secret, repo_path, cset, file_path):
	endpoint = "/2.0/repositories/{repo_path}/src/{node}/{file_path}".format(
		repo_path = repo_path,
		node = cset,
		file_path = file_path
	)

	encoded_jwt = create_jwt(client_key, secret, endpoint)

	r = session.get(base_url+endpoint, headers={
		'Authorization': "JWT "+encoded_jwt.decode('utf-8'),
	})

	if r.status_code != requests.codes.ok:
		print("Failed get file")
		return False

	full_file_path = INPUT_DIR.format(cset=cset, path=file_path)
	directory = path.dirname(full_file_path)
	if not path.exists(directory):
		makedirs(directory)

	with open(full_file_path, "w+") as f:
		f.write(r.content.decode("utf-8"))

	return True

def pdf_page(pdf):
	return

@app.route(base+"/schematic-pdf", methods=['GET'])
def schematic_pdf():
	return
	# try:
	# 	connection, secret = get_connection(request.args.get("jwt"))
	# except jwt.InvalidSignatureError:
	# 	return "JWT verification failed"

	# # TODO: verify claims and validity of JWT

	# print(request.data)

	# connection = get_connection(request.json["user"]["username"])
	# base_url = connections_db.get("/bitbucket/{}/api_url".format(connection)).decode("utf-8")
	# file_path = request.args.get("file_path")
	# client_key = 

	# with requests.Session() as s:
	# 	files = list_files(s, connection, base_url, secret, path.dirname(file_path), [".sch", ".lib", ".pro"])
	# 	print(files)
	# 	for file in files:
	# 		# TODO: check if file already exists
	# 		get_and_save_file(s, client_key, base_url, secret, file["path"])

	# cset = request.args.get("cset")
	# # TODO: check if output file exists
	# export_schematic(
	# 	path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
	# 	path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
	# 	"PDF"
	# )

	# TODO: mmap the file so KiCad can load it quicker and we don't
	# wait for the file to be flushed?
	# Also, maybe it's possible to already start opening the files before they
	# are fully downloaded (making sure they are all created)?

	# TODO: Store PDF in cache and link to cached PDF
	# This is prabably also required to use the browser's cache...

	pdf_file = path.abspath(OUTPUT_DIR.format(cset=cset, path=file_path.split(".")[0]+".pdf"))
	print(pdf_file)

	return Response(pdf_page(pdf_file))

@app.route(base+"/render/<service>/<username>/<repo_name>/<path:file_path>/", methods=['GET'])
def render_file(service, username, repo_name, file_path):
	cset = request.args.get("cset")
	print("Request to render %s for %s on %s".format(file_path, username, service))
	# TODO: fail early if no access token provided
	validate_access_token(username, request.args.get("access_token"))

	connection = get_connection(username)
	client_key = connections_db.get(connection+"/client_key".format(username)).decode("utf-8")
	base_url = connections_db.get(connection+"/api_url".format(username)).decode("utf-8")

	nonce = b64decode(connections_db.get(connection+"/nonce"))
	cipher = AES.new(b64decode(environ["FILE_RENDERER_KEY"]), AES.MODE_GCM, nonce=nonce)
	secret = connections_db.get(connection+"/secret")
	secret = cipher.decrypt(secret).decode("utf-8")

	file_path, extension = os.path.splitext(file_path)
	repo = username+"/"+repo_name
	with requests.Session() as s:
		# TODO: check if file already exists
		get_and_save_file(s, client_key, base_url, secret, repo, cset, file_path)
		files = list_files(s, client_key, base_url, secret, repo, path.dirname(file_path), [".lib", ".pro"])
		for file in files:
			# TODO: check if file already exists
			# get_and_save_file(session, client_key, base_url, secret, repo_path, cset, file_path):
			get_and_save_file(s, client_key, base_url, secret, repo, cset, file["path"])

	# TODO: only plot one sheet
	export_schematic(
		path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
		path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
		"SVG"
	)

	svg_file = OUTPUT_DIR.format(cset=cset, path=file_path.split(".")[0]+".svg")
	res = send_file(svg_file)
	return res

@app.route(base+"/schematic-sheet-svg", methods=['GET'])
def schematic_sheet_svg():
	print(request.args)
	repo_path = urllib.parse.unquote(request.args.get("repo_path"))
	username = get_username(repo_path)
	try:
		validate_jwt(username, request.args.get("jwt"))
	except jwt.InvalidSignatureError:
		return "JWT verification failed"

	cset = request.args.get("cset")
	file_path = request.args.get("file_path")

	access_token = connections_db.hget("/bitbucket.org/{}/access_token_names".format(username), "bitbucket").decode("utf-8")
	svg_data = ADDRESS+base+"/render/{}/{}/{}.svg?cset={}&access_token={}".format(
		"bitbucket.org",
		repo_path,
		file_path,
		cset,
		access_token
	)

	return render_template('svg.html', svg_data=svg_data)

if __name__ == '__main__':
	app.run('localhost', 5000, ssl_context='adhoc')
