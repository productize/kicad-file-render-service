FROM productize/kicad-automation-scripts
MAINTAINER Seppe Stas <seppe@productize.be>
LABEL Description="KiCad file render service"

# Add requirements in separate step to prevent rebuild of requirement install 
# when only source code changes
ADD requirements.txt .

RUN apt-get -y update && \
    apt-get -y install build-essential libssl-dev libffi-dev && \
    pip3 install -r requirements.txt && \
    rm requirements.txt && \
    apt-get -y remove build-essential libssl-dev libffi-dev && \
    apt-get -y autoremove -y && \
    rm -rf /var/lib/apt/lists/*

ADD . /kicad-file-render-service/
WORKDIR /kicad-file-render-service

RUN ln -s /kicad-automation ./kicad_automation_scripts

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV FLASK_APP=bitbucket.py
EXPOSE 5000
CMD ["python3", "-mflask", "run"]
