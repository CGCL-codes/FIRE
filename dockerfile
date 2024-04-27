FROM python:3.11-slim-bullseye

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y git libxml2 libjansson4 libyaml-0-2 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install torch==2.1.0 torchvision==0.16.0 torchaudio==2.1.0 --index-url https://download.pytorch.org/whl/cpu

COPY . .

ENV JAVA_HOME "/usr/src/app/resources/jdk-19.0.2"
ENV PATH $PATH:$JAVA_HOME/bin

EXPOSE 8000

CMD ["python3", "server.py"]