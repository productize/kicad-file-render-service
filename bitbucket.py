
import json
from flask import Flask, request, Response
import jwt
from datetime import timezone, datetime, timedelta
import urllib.parse
from os import environ, path, makedirs
from hashlib import sha256
import requests
from redis import StrictRedis
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from kicad_automation_scripts.eeschema.export_schematic import export_schematic

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
	"baseUrl": "https://blue.productize.be"+base,
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

@app.route(base+descriptor["lifecycle"]["installed"], methods=['POST'])
def installed():
	print(request.data)

	cipher = AES.new(b64decode(environ["FILE_RENDERER_KEY"]), AES.MODE_GCM)

	connection = request.json["clientKey"]
	connections_db.set(
		"/bitbucket/{}/secret".format(connection),
		cipher.encrypt(request.json["sharedSecret"].encode("utf-8"))
	)
	connections_db.set(
		"/bitbucket/{}/nonce".format(connection),
		b64encode(cipher.nonce)
	)
	connections_db.set(
		"/bitbucket/{}/api_url".format(connection),
		request.json["baseApiUrl"]
	)
	return "Installation succesfull"

def get_connection(encoded_token):
	token = jwt.decode(encoded_token, verify=False)
	connection = token["iss"]
	secret = connections_db.get("/bitbucket/{}/secret".format(connection))
	if secret is None:
		# TODO: create a more specific exception
		raise Exception("Connection not found")

	nonce = b64decode(connections_db.get("/bitbucket/{}/nonce".format(connection)))
	cipher = AES.new(b64decode(environ["FILE_RENDERER_KEY"]), AES.MODE_GCM, nonce=nonce)
	secret = cipher.decrypt(secret).decode("utf-8", )

	jwt.decode(request.args.get("jwt"), secret, audience=connection)

	return connection, secret


@app.route(base+descriptor["lifecycle"]["uninstalled"], methods=['POST'])
def uninstalled():
	print(request.data)

	try:
		connection, secret = get_connection(request.args.get("jwt"))
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

def list_files(session, connection, base_url, secret, path, extensions=[]):
	# TODO: fetch next instead of using big pagelen
	params = {"pagelen": "50"}

	if len(extensions) > 0:
		params["q"] = "path~\"{}\"".format(extensions[0])
		for i in range(1, len(extensions)-1):
			params["q"] += " or path~\"{}\"".format(extensions[i])
	
	endpoint = "/2.0/repositories/{repo_path}/src/{node}/{path}".format(
		repo_path = urllib.parse.unquote(request.args.get("repo_path")),
		node = request.args.get("cset"),
		path = path
	)

	encoded_jwt = create_jwt(connection, secret, endpoint, params)

	print(encoded_jwt)

	r = session.get(base_url+endpoint, params=params, headers={
		'Authorization': "JWT "+encoded_jwt.decode('utf-8'),
	})

	if r.status_code != requests.codes.ok:
		print("Failed to list files")
		return []

	return r.json()["values"]

def get_and_save_file(session, connection, base_url, secret, file_path):
	cset = request.args.get("cset")
	endpoint = "/2.0/repositories/{repo_path}/src/{node}/{file_path}".format(
		repo_path = urllib.parse.unquote(request.args.get("repo_path")),
		node = cset,
		file_path = file_path
	)

	encoded_jwt = create_jwt(connection, secret, endpoint)

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

def svg_page(svg):
	yield """<!DOCTYPE html>
		<html lang="en">
		  <head>
		    <script src="https://bitbucket.org/atlassian-connect/all.js"></script>
		  </head> 
		  <body>"""
	chunk_size = 3*1024
	with open(svg, 'r') as f:
		while True:
			data = f.read(chunk_size)
			if not data:
				break
			yield data
	yield "</body></html>"

def pdf_page(pdf):
	# TODO: use a template or something? Probably requires to send PDF seperatly
	# PDFJS: https://mozilla.github.io/pdf.js/examples/
	yield """<!DOCTYPE html>
		<html lang="en">
		  <head>
		    <script src="https://bitbucket.org/atlassian-connect/all.js"></script>
		    <script src="//mozilla.github.io/pdf.js/build/pdf.js"></script>
		  </head> 
		  <body>
		  	<div>
			  <button id="prev">Previous</button>
			  <button id="next">Next</button>
			  <span>Page: <span id="page_num"></span> / <span id="page_count"></span></span>
			</div>
		    <canvas id="the-canvas"></canvas>
		  </body>
		  <script>
		    pdfData = atob('"""

	chunk_size = 3*1024
	with open(pdf, 'rb') as f:
		while True:
			data = f.read(chunk_size)
			if not data:
				break
			yield b64encode(data)

	yield """');
		    // Loaded via <script> tag, create shortcut to access PDF.js exports.
			var pdfjsLib = window['pdfjs-dist/build/pdf'];

			// The workerSrc property shall be specified.
			pdfjsLib.GlobalWorkerOptions.workerSrc = '//mozilla.github.io/pdf.js/build/pdf.worker.js';

			var pdfDoc = null,
			    pageNum = 1,
			    pageRendering = false,
			    pageNumPending = null,
			    scale = 0.8,
			    canvas = document.getElementById('the-canvas'),
			    ctx = canvas.getContext('2d');

			/**
			 * Get page info from document, resize canvas accordingly, and render page.
			 * @param num Page number.
			 */
			function renderPage(num) {
			  pageRendering = true;
			  // Using promise to fetch the page
			  pdfDoc.getPage(num).then(function(page) {
			    var viewport = page.getViewport(scale);
			    canvas.height = viewport.height;
			    canvas.width = viewport.width;

			    // Render PDF page into canvas context
			    var renderContext = {
			      canvasContext: ctx,
			      viewport: viewport
			    };
			    var renderTask = page.render(renderContext);

			    // Wait for rendering to finish
			    renderTask.promise.then(function() {
			      pageRendering = false;
			      if (pageNumPending !== null) {
			        // New page rendering is pending
			        renderPage(pageNumPending);
			        pageNumPending = null;
			      }
			    });
			  });

			  // Update page counters
			  document.getElementById('page_num').textContent = num;
			}

			/**
			 * If another page rendering in progress, waits until the rendering is
			 * finised. Otherwise, executes rendering immediately.
			 */
			function queueRenderPage(num) {
			  if (pageRendering) {
			    pageNumPending = num;
			  } else {
			    renderPage(num);
			  }
			}

			/**
			 * Displays previous page.
			 */
			function onPrevPage() {
			  if (pageNum <= 1) {
			    return;
			  }
			  pageNum--;
			  queueRenderPage(pageNum);
			}

			/**
			 * Displays next page.
			 */
			function onNextPage() {
			  if (pageNum >= pdfDoc.numPages) {
			    return;
			  }
			  pageNum++;
			  queueRenderPage(pageNum);
			}
			document.getElementById('next').addEventListener('click', onNextPage);
			document.getElementById('prev').addEventListener('click', onPrevPage);

			/**
			 * Asynchronously downloads PDF.
			 */
			pdfjsLib.getDocument({data: pdfData}).then(function(pdfDoc_) {
			  pdfDoc = pdfDoc_;
			  document.getElementById('page_count').textContent = pdfDoc.numPages;

			  // Initial/first page rendering
			  renderPage(pageNum);
			});
			</script>
		    <meta charset="utf-8" />
		    <meta http-equiv="X-UA-Compatible" content="IE=EDGE">
		</html>"""

@app.route(base+"/schematic-pdf", methods=['GET'])
def schematic_pdf():
	# TODO: Support revokeable access tokens so other services can access the files
	try:
		connection, secret = get_connection(request.args.get("jwt"))
	except jwt.InvalidSignatureError:
		return "JWT verification failed"

	# TODO: verify claims and validity of JWT

	print(request.data)

	base_url = connections_db.get("/bitbucket/{}/api_url".format(connection)).decode("utf-8")
	file_path = request.args.get("file_path")

	with requests.Session() as s:
		files = list_files(s, connection, base_url, secret, path.dirname(file_path), [".sch", ".lib", ".pro"])
		print(files)
		for file in files:
			# TODO: check if file already exists
			get_and_save_file(s, connection, base_url, secret, file["path"])

	cset = request.args.get("cset")
	# TODO: check if output file exists
	export_schematic(
		path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
		path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
		"PDF"
	)

	# TODO: mmap the file so KiCad can load it quicker and we don't
	# wait for the file to be flushed?
	# Also, maybe it's possible to already start opening the files before they
	# are fully downloaded (making sure they are all created)?

	# TODO: Store PDF in cache and link to cached PDF
	# This is prabably also required to use the browser's cache...

	pdf_file = path.abspath(OUTPUT_DIR.format(cset=cset, path=file_path.split(".")[0]+".pdf"))
	print(pdf_file)

	return Response(pdf_page(pdf_file))

@app.route(base+"/schematic-sheet-svg", methods=['GET'])
def schematic_sheet_svg():
	try:
		connection, secret = get_connection(request.args.get("jwt"))
	except jwt.InvalidSignatureError:
		return "JWT verification failed"

	# TODO: verify claims and validity of JWT

	print(request.data)

	base_url = connections_db.get("/bitbucket/{}/api_url".format(connection)).decode("utf-8")
	file_path = request.args.get("file_path")

	with requests.Session() as s:
		get_and_save_file(s, connection, base_url, secret, file_path)
		files = list_files(s, connection, base_url, secret, path.dirname(file_path), [".lib", ".pro"])
		print(files)
		for file in files:
			# TODO: check if file already exists
			get_and_save_file(s, connection, base_url, secret, file["path"])

	cset = request.args.get("cset")
	full_file_path = INPUT_DIR.format(cset=cset, path=file_path)
	# TODO: only plot one sheet
	export_schematic(
		path.abspath(INPUT_DIR.format(cset=cset, path=file_path)),
		path.abspath(OUTPUT_DIR.format(cset=cset, path=path.dirname(file_path))),
		"SVG"
	)

	svg_file = OUTPUT_DIR.format(cset=cset, path=file_path.split(".")[0]+".svg")
	print(svg_file)

	return Response(svg_page(svg_file))

if __name__ == '__main__':
	app.run('localhost', 5000, ssl_context='adhoc')
