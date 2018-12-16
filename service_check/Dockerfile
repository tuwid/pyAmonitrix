FROM       python:2
RUN        apt update && apt-get upgrade -y
RUN        pip install pip --upgrade
RUN        pip install pika requests
RUN        mkdir /app
COPY       notification.py /app
WORKDIR    /app
CMD ["python", "notification.py"]
