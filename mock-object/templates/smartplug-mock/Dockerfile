FROM python:3.11-alpine
WORKDIR /app
COPY smartplug_server.py .
EXPOSE 80 9999 1900/udp
CMD ["python", "smartplug_server.py"]
