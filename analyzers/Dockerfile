FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY analyzers/package*.json ./analyzers/
COPY common/package*.json ./common/
RUN npm install --omit=dev
COPY common/ ./common/
COPY analyzers/ ./analyzers/
ENV NODE_ENV=production
CMD ["node", "analyzers/src/index.js"]
