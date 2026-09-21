ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3 py3-pip

COPY requirements.txt /app/requirements.txt
RUN python3 -m pip install --no-cache-dir --break-system-packages -r /app/requirements.txt

COPY app.py operations.py run.sh /app/
RUN chmod 0755 /app/run.sh

CMD ["/app/run.sh"]
