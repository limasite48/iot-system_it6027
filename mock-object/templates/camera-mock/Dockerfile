FROM python:3.11-alpine

WORKDIR /app

# Install system dependencies & zeroconf for mDNS
RUN pip install --no-cache-dir zeroconf

# Copy modular camera engine and profiles
COPY engine/ ./engine/
COPY profiles/ ./profiles/
COPY templates/camera-mock/camera_server.py .

ENV CAMERA_PROFILE=dlink_dcs932l
ENV HTTP_PORT=8080
ENV RTSP_PORT=554

EXPOSE 80 8080 8081 554 1900/udp

CMD ["python", "camera_server.py"]
