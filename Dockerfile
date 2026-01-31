FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application files
COPY src/ ./src/
COPY uploads/ ./uploads/

# Create necessary directories
RUN mkdir -p uploads src/data/logs src/data/config

# Expose port
EXPOSE 3000

# Set environment variable
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Warning message
RUN echo "⚠️  WARNING: This container runs an INTENTIONALLY VULNERABLE application" && \
    echo "    Use only in isolated lab environments for security demonstrations" && \
    echo "    DO NOT expose to untrusted networks or the internet"

# Start application
CMD ["node", "src/index.js"]

# Labels
LABEL maintainer="security-demo" \
      description="PreFirewall Lab - Intentionally vulnerable web app for firewall demos" \
      version="1.0.0" \
      security.warning="INTENTIONALLY VULNERABLE - LAB USE ONLY"
