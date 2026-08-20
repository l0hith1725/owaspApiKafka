FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY gateway/package*.json ./gateway/
COPY common/package*.json ./common/
RUN npm install --omit=dev
COPY common/ ./common/
COPY gateway/ ./gateway/
ENV NODE_ENV=production
CMD ["node", "gateway/src/index.js"]
