# Nginx Reverse Proxy for Vendiant
FROM nginxinc/nginx-unprivileged:1.25-alpine

# Switch to root to install packages and set up directories
USER root

# Install additional tools for health checks and SSL
RUN apk add --no-cache curl openssl

# Create directories for SSL certificates and logs
RUN mkdir -p /etc/nginx/ssl /var/log/nginx && \
    chown -R nginx:nginx /var/log/nginx

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY csp.conf /etc/nginx/csp.conf

# Create a simple health check script
RUN echo '#!/bin/sh' > /usr/local/bin/health-check.sh && \
    echo 'curl -f http://localhost:80/health || exit 1' >> /usr/local/bin/health-check.sh && \
    chmod +x /usr/local/bin/health-check.sh

# Drop back to the unprivileged nginx user
USER nginx

# Expose ports
EXPOSE 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/health-check.sh

# Start nginx
CMD ["nginx", "-g", "daemon off;"]

