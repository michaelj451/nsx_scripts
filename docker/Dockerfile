FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /srv/fc_nsx

# System deps
COPY docker/requirements-apt.txt /tmp/requirements-apt.txt
# RUN apt-get update \
#   && xargs -r -a /tmp/requirements-apt.txt apt-get install -y --no-install-recommends \
#   && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
  && sed -i 's/\r$//' /tmp/requirements-apt.txt \
  && grep -vE '^\s*($|#)' /tmp/requirements-apt.txt | xargs -r apt-get install -y --no-install-recommends \
  && rm -rf /var/lib/apt/lists/*

# Python deps 
COPY docker/requirements-pip.txt /tmp/requirements-pip.txt
RUN pip install --no-cache-dir -r /tmp/requirements-pip.txt

# Copy code (compose will also bind-mount over this for live edits)
COPY . /srv/fc_nsx

# Make imports work even without compose env overrides
ENV PYTHONPATH=/srv/fc_nsx/app

EXPOSE 8000