FROM python:3.12-slim

RUN pip install --no-cache-dir prometheus-client==0.21.0 requests==2.32.3

RUN useradd --uid 1000 --create-home app
USER app
WORKDIR /home/app

COPY --chown=app:app release-exporter.py /home/app/release-exporter.py

EXPOSE 8080
CMD ["python3", "-u", "/home/app/release-exporter.py"]
