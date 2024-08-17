FROM python:3.11-slim-bullseye

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y git libxml2 libjansson4 libyaml-0-2 vim

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0

COPY . .

# install redis
RUN apt install build-essential -y --no-install-recommends
RUN cd resources/redis-7.2.3 && \
    make && \
    make install && \
    cd .. && \
    rm -rf /usr/src/app/resources/redis-7.2.3

ENV JAVA_HOME "/usr/src/app/resources/jdk-17.0.11"
ENV PATH $PATH:$JAVA_HOME/bin

EXPOSE 8000

CMD redis-server --daemonize yes && python3 server.py