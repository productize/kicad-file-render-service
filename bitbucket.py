import json
from flask import Flask, request, Response, render_template, send_file, abort
import jwt
from time import time
from urllib import quote, unquote
from os import environ, path, makedirs
from shutil import copyfile
from hashlib import sha256
import requests
from redis import StrictRedis
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
# TODO: clean this up
from kicad_automation_scripts.eeschema.export_schematic import export_schematic
from kicad_automation_scripts._pcbnew import pcb_util
from pcbnew import PLOT_FORMAT_SVG
try:
	from secrets import token_hex as secret_token
except ImportError:
	from os import urandom
	def secret_token(nbytes=None):
		return urandom(nbytes).hex()

BASE_INPUT_DIR="./input"
INPUT_DIR = BASE_INPUT_DIR+"/{cset}/{path}"
BASE_OUTPUT_DIR = "./output"
OUTPUT_DIR = BASE_OUTPUT_DIR+"/{cset}/{path}"

import logging
formatter = logging.Formatter(fmt='%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%Y-%m-%d %H:%M:%S')

app = Flask(__name__)
if "BASE_PATH" in environ:
	base = environ["BASE_PATH"]
else:
	base = ""

connections_db = StrictRedis(host="connections-db")

if "KICAD_FILE_RENDERER_KEY" in environ:
	connections_db_key = environ["KICAD_FILE_RENDERER_KEY"]
elif path.exists('/connections_db_key'):
	with open('/connections_db_key', "r") as f:
		connections_db_key = f.readline()
else:
	print("No KICAD_FILE_RENDERER_KEY set and no connections_db_key file found")
	exit(1);

if "ADDRESS" not in environ:
	print("No ADDRESS set")
	exit(1);

ADDRESS=environ["ADDRESS"]

# File viewer modules. See https://developer.atlassian.com/cloud/bitbucket/modules/file-viewer/
# Examples:
#  - https://bitbucket.org/tpettersen/run-bucket-run/src/master/connect-account.json?at=master
#  - https://github.com/noamt/bitbucket-asciidoctor-addon/blob/master/atlassian-connect.json

schematic_sheet_viewer_svg = {
	"key" : "kicad-schematic-sheet-svg",
	"name": {
		"i18n": "en",
		"value": "Schematic sheet"
	},
	"file_matches": {"extensions": ["sch"]},
	"url": "/schematic-sheet-svg?repo_path={repo_path}&cset={file_cset}&file_path={file_path}"
}

schematic_viewer_pdf = {
	"key" : "kicad-schematic-pdf",
	"name": {
		"i18n": "en",
		"value": "Full schematic PDF"
	},
	"file_matches": {"extensions": ["sch"]},
	"url": "/schematic-pdf?repo_path={repo_path}&cset={file_cset}&file_path={file_path}"
}

layout_viewer_svg = {
	"key" : "kicad-layout-svg",
	"name": {
		"i18n": "en",
		"value": "Layout"
	},
	"file_matches": {"extensions": ["kicad_pcb"]},
	"url": "/layout-svg?repo_path={repo_path}&cset={file_cset}&file_path={file_path}"
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
			schematic_sheet_viewer_svg,
			schematic_viewer_pdf,
			layout_viewer_svg
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

	cipher = AES.new(b64decode(connections_db_key), AES.MODE_GCM)

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
		access_token
	)
	return "Installation succesfull"

def get_username(repo_path):
	return quote(repo_path.split("/")[0])

def validate_jwt(username, encoded_token):
	connection = get_connection(username)

	client_key = connections_db.get(connection+"/client_key").decode("utf-8")
	if client_key is None:
		# TODO: create a more specific exception
		raise Exception("Connection not found")

	print(client_key)
	nonce = b64decode(connections_db.get(connection+"/nonce"))
	cipher = AES.new(b64decode(connections_db_key), AES.MODE_GCM, nonce=nonce)
	secret = connections_db.get(connection+"/secret")
	secret = cipher.decrypt(secret).decode("utf-8")
	jwt.decode(encoded_token, secret, audience=client_key)
	# TODO: verify claims and validity of JWT

def validate_access_token(username, access_token):
	connection = get_connection(username)
	print(access_token)
	if not connections_db.sismember(connection+"/access_tokens", access_token):
		abort(401, "Invalid access token")


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


def create_jwt(connection, secret, endpoint, params = {}, validity=120):
	# See https://developer.atlassian.com/cloud/bitbucket/query-string-hash/
	canonical_request = "GET&"+endpoint+"&"
	# Adding params does not seem required, but is in spec...
	i = 0
	for p_key, p_value in params.items():
		canonical_request += "{}={}".format(p_key, quote(p_value))
		i += 1
		if i < len(params)-1:
			canonical_request += "&"
	qsh = sha256(canonical_request.encode('utf-8')).hexdigest()

	# Create JWT. See https://developer.atlassian.com/cloud/bitbucket/understanding-jwt-for-apps/#claims
	now = int(time())
	return jwt.encode({
		"iss": descriptor["key"],
		"iat": now,
		"exp": now + validity,
		"qsh": qsh,
		"sub": connection
	}, secret, algorithm='HS256')

def list_files(session, client_key, base_url, secret, repo_path, path, extensions=[]):
	# TODO: fetch next instead of using big pagelen
	params = {"pagelen": "50"}

	if len(extensions) > 0:
		params["q"] = "path~\"{}\"".format(extensions[0])
		for i in range(1, len(extensions)):
			print(extensions[i])
			params["q"] += " or path~\"{}\"".format(extensions[i])

	endpoint = "/2.0/repositories/{repo_path}/src/{node}/{path}".format(
		repo_path = repo_path,
		node = request.args.get("cset"),
		path = path
	)

	encoded_jwt = create_jwt(client_key, secret, endpoint, params)

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

	with open(full_file_path, "w") as f:
		f.write(r.content)

	return True


def get_schematic_files(client_key, base_url, secret, repo, cset, file_path):
	with requests.Session() as s:
		files = list_files(s, client_key, base_url, secret, repo, path.dirname(file_path), [".sch", ".lib", ".pro"])
		for file in files:
			# TODO: check if file already exists
			get_and_save_file(s, client_key, base_url, secret, repo, cset, file["path"])
			# Create copy of project files so cached symbols are found and libs are in correct order
			for ext in [".pro", "-cache.lib"]:
				if file["path"].endswith(ext) and file["path"].rpartition(ext)[0] != file_path.rpartition(".sch")[0]:
					copyfile(
						INPUT_DIR.format(cset=cset, path=file["path"]),
						INPUT_DIR.format(cset=cset, path=file_path.rpartition(".sch")[0]+ext)
					)

def render_svg_schematic(client_key, base_url, secret, repo, cset, file_path):
	get_schematic_files(client_key, base_url, secret, repo, cset, file_path)

	export_schematic(
		path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
		path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
		"SVG"
	)

	svg_file = path.abspath(OUTPUT_DIR.format(cset=cset, path=file_path+'.svg'))
	return send_file(svg_file)

def render_pdf_schematic(client_key, base_url, secret, repo, cset, file_path):
	get_schematic_files(client_key, base_url, secret, repo, cset, file_path)

	export_schematic(
		path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
		path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
		"PDF",
		True
	)

	pdf_file = path.abspath(OUTPUT_DIR.format(cset=cset, path=file_path.split(".")[0]+".pdf"))
	return send_file(pdf_file)

def render_svg_layout(client_key, base_url, secret, repo, cset, file_path, layer):
	print(file_path);
	with requests.Session() as s:
		get_and_save_file(s, client_key, base_url, secret, repo, cset, file_path)

	input_file = INPUT_DIR.format(cset=cset, path=file_path)
	output_dir = OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))

	directory = path.dirname(output_dir)
	if not path.exists(directory):
		makedirs(directory)

	with pcb_util.get_plotter(input_file, path.abspath(output_dir)) as plotter:
		output_filename = plotter.plot(pcb_util.layer_from_name(layer), PLOT_FORMAT_SVG)

	print output_filename
	return send_file(output_filename)

@app.route(base+"/render/<service>/<username>/<repo_name>/<path:file_path>", methods=['GET'])
def render_file(service, username, repo_name, file_path):
	cset = request.args.get("cset")
	# TODO: figure out commit hash if cset is not commit and redirect to commit hash
	print("Request to render {} for {} on {}".format(file_path, username, service))
	# TODO: fail early if no access token provided
	validate_access_token(username, request.args.get("access_token"))

	connection = get_connection(username)
	client_key = connections_db.get(connection+"/client_key".format(username)).decode("utf-8")
	base_url = connections_db.get(connection+"/api_url".format(username)).decode("utf-8")

	nonce = b64decode(connections_db.get(connection+"/nonce"))
	cipher = AES.new(b64decode(connections_db_key), AES.MODE_GCM, nonce=nonce)
	secret = connections_db.get(connection+"/secret")
	secret = cipher.decrypt(secret).decode("utf-8")

	file_path, out_extension = path.splitext(file_path)

	_, in_extension = path.splitext(file_path)

	out_extension = out_extension.lower()
	in_extension = in_extension.lower()

	print("In extension: {}, out: {}".format(in_extension, out_extension))

	repo = username+"/"+repo_name

	if (out_extension == ".svg"):
		if (in_extension == ".sch"):
			print ("Rendering SVG schematic")
			return render_svg_schematic(client_key, base_url, secret, repo, cset, file_path)
		elif (in_extension == ".kicad_pcb"):
			return render_svg_layout(client_key, base_url, secret, repo, cset, file_path, request.args.get("layer"))
	elif (out_extension == ".pdf"):
		if (in_extension == ".sch"):
			return render_pdf_schematic(client_key, base_url, secret, repo, cset, file_path)
		elif (in_extension == ".kicad_pcb"):
			return render_pdf_layout(client_key, base_url, secret, repo, cset, file_path)


def validate_and_get_request_data():
	repo_path = unquote(request.args.get("repo_path"))
	username = get_username(repo_path)
	try:
		validate_jwt(username, request.args.get("jwt"))
	except jwt.InvalidSignatureError:
		abort(401, "Invalid access token")

	file_path = request.args.get("file_path")
	cset = request.args.get("cset")

	access_token = connections_db.hget("/bitbucket.org/{}/access_token_names".format(username), "bitbucket").decode("utf-8")

	return username, repo_path, file_path, cset, access_token

@app.route(base+"/schematic-sheet-svg", methods=['GET'])
def schematic_sheet_svg():
	username, repo_path, file_path, cset, access_token = validate_and_get_request_data()

	svg_url = ADDRESS+base+"/render/{}/{}/{}.svg?cset={}&access_token={}".format(
		"bitbucket.org",
		repo_path,
		file_path,
		cset,
		access_token
	)
	return render_template('schematic-svg.html', svg_url=unquote(svg_url))

@app.route(base+"/schematic-pdf", methods=['GET'])
def schematic_pdf():
	username, repo_path, file_path, cset, access_token = validate_and_get_request_data()

	pdf_url = ADDRESS+base+"/render/{}/{}/{}.pdf?cset={}&access_token={}".format(
		"bitbucket.org",
		repo_path,
		file_path,
		cset,
		access_token
	)
	return render_template('pdf.html', pdf_url=pdf_url)

@app.route(base+"/layout-svg", methods=['GET'])
def layout_svg():
	username, repo_path, file_path, cset, access_token = validate_and_get_request_data()

	svg_url = ADDRESS+base+"/render/{}/{}/{}.svg?cset={}&access_token={}".format(
		"bitbucket.org",
		repo_path,
		file_path,
		cset,
		access_token
	)
	# TODO: figure out layers from file
	layers = [
		"F.Cu",
		"B.Cu"
	]
	return render_template('layout-svg.html', svg_url=unquote(svg_url), layers=layers)

@app.route('/static/<path:path>')
def send_js(path):
    return send_from_directory('static', path)

if __name__ == '__main__':
	if "INTERFACE" not in environ:
		app.run(5000)
	else :
		app.run(environ["INTERFACE"], 5000)
