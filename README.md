KiCad file render service
=========================

Render [KiCad] schematic and layout files into browser-viewable formats on
demand.

Features
--------

- Downloads KiCad schematics and layouts from Bitbucket and returns a rendered
  SVG image or PDF document on demand.
- Bitbucket Fileviewer to view KiCad schematics and layouts in Bitbucket.

Installation and running
------------------------

### Using Docker compose

TODO: use and document this

### Using Docker

- Start a docker network:

```
docker network create kicad-file-render-network
```

- Start the connections_db Redis database connected to the network:

```
docker run --name connections-db -d --network kicad-file-render-network redis
```

Hint: You can use redis:alpine if you want a smaller container size
Another hint: pass -p 6379:6379 to allow you host to connect to the DB for
debugging purposes.

- Create a secret key:

This service requires a (secret) key in order to safely store secrets. You can
pass it:

As an environmental variable:

```
export KICAD_FILE_RENDERER_KEY=$(dd if=/dev/random bs=3 count=16 2>/dev/null | base64)

```

Or as a Docker secret (requires a Docker swarm): 

```
dd if=/dev/random bs=3 count=16 2>/dev/null | base64 | docker secret create file-render-key-test -
```

- Run the service

The service needs to know where it's running so it can tell Bitbucket and other
services. You can pass it using the ADDRESS environmetal variable.

It also needs the secret created in the previous step.

This can also be passed as an environmental variable:

```
docker run -p 5000:5000 --name kicad-file-render-service -d --network kicad-file-render-network -e KICAD_FILE_RENDERER_KEY=$(KICAD_FILE_RENDERER_KEY) productize/kicad-file-render-service
```

Or by using the docker secret

Note: If you don't want to use Docker hub, you can also build the docker image
yourself from this repo using:

```
docker build .
```

Yet another note: For debugging purposes it's useful to run the docker image
interactively using the source files on the host. This can be done with Docker
volumes:

```
docker run -p 5000:5000 --name kicad-file-render-service -it --network kicad-file-render-network -v `pwd`:/kicad-file-render-service/ productize/kicad-automation-scripts

```

### Manually

- Install the dependencies, e.g:

```
apt-get install -y kicad python3 python3-pip xvfb recordmydesktop xdotool
pip3 install kicad_automation_scripts/eeschema/requirements.txt
```

See the Dockerfiles for an up-to date list of dependencies.

- Export the (secret) KICAD_FILE_RENDERER_KEY variable, e.g:

```
export KICAD_FILE_RENDERER_KEY=$(dd if=/dev/random bs=3 count=16 2>/dev/null | base64)

```

- Run the flask app:
```
export FLASK_APP=bitbucket.py
ADDRESS="https://kicad-file-render-service.your-domain.com" python3 -m flask run
```

### Set up an HTTPS proxy to port 5000

Bitbucket requires the service to run on HTTP with a verifiable, valid
certificate. If you don't have one you could give [letsencrypt] a try.

The easiest way to achieve this is setting up an HTTPS proxy towards the port
this app is configured to use (5000 by default / in example) in your favorite
HTTPS server. E.g on NGINX:

```
server {
    listen      443 default;
    server_name kicad-file-renderer.productize.be;

    ssl on;
    ssl_certificate     /your/certs/chained-certificate.crt;
    ssl_certificate_key /your/certs/certificate-key.key;
    location / {
        proxy_pass http://localhost:5000;
    }
}

```

Wishlist
--------

- Add support for KiCad schematic libraries and layout footprints
- Add support for files hosted on Github and Gitlab ([no way to add file
  viewers in Github][github-1005], but could be done by e.g embedding in
  e.g README's).
- Create a diffview for reviewing changesets
	- Incorporate the diffview in Pullrequest views
	  ([not supported in Bitbucket][bitbucket-issue-13269]).
- A home page
- Run it as a service

[KiCad]: http://kicad.org/
[github-1005]: https://github.com/isaacs/github/issues/1005
[bitbucket-issue-13269]: https://bitbucket.org/site/master/issues/13269/add-an-extension-point-for-the-pull
[letsencrypt]: https://letsencrypt.org/
