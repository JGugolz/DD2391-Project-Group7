FROM python:3.12-alpine

# Install iproute2 for ip command used in entrypoint.sh
RUN apk add --no-cache iproute2

WORKDIR /app

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh

# Copy index.html to the working directory
COPY index.html /app/index.html
# COPY vulnerable_server.py /app/vulnerable_server.py

# Expose port 80
EXPOSE 80

CMD ["/entrypoint.sh"]
