FROM python:3.12-bullseye

RUN apt update
RUN apt install libpq-dev -y

RUN useradd --create-home devops
USER devops
WORKDIR /home/devops

ENV VIRTUALENV=/home/devops/venv
RUN python3 -m venv $VIRTUALENV
ENV PATH="$VIRTUALENV/bin:$PATH"

COPY --chown=devops dist/*.whl /tmp/
COPY --chown=devops .env .env

RUN pip install -U pip \
    && pip install --no-cache-dir /tmp/*.whl \
    && rm -rf /tmp/*.whl

ENTRYPOINT [ "api" ]