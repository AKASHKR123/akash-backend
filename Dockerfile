# Secure Dockerfile
FROM node:20-alpine  # Updated to a secure and lightweight version

# Create a non-root user
RUN addgroup appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy only essential files first to leverage Docker caching
COPY package*.json ./

# Install dependencies securely
RUN npm ci --only=production && npm cache clean --force

# Copy the rest of the application code
COPY . .

# Use a non-root user for enhanced security
USER appuser

# Expose only the necessary port
EXPOSE 3000

CMD ["npm", "start"]
