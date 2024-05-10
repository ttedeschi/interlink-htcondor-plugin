FROM htcondor/mini:9.0.17-el7

RUN pip3 install pyyaml

COPY handles.py /utils/handles.py
COPY SidecarConfig.yaml /utils/SidecarConfig.yaml
RUN touch /utils/condor_config
RUN mkdir /utils/.knoc

WORKDIR /utils

CMD ["/bin/sh", "-c", "/start.sh & python3 handles.py"]