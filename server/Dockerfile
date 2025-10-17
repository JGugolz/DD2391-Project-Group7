FROM python:3.12-alpine

# Install iproute2 for ip command used in entrypoint.sh
RUN apk add --no-cache iproute2

WORKDIR /app

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh

# Expose port 80
EXPOSE 80

CMD ["/entrypoint.sh"]
