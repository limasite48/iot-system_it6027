FROM python:3.11-alpine
WORKDIR /app
COPY camera_server.py .
EXPOSE 8080 1900/udp
CMD ["python", "camera_server.py"]
