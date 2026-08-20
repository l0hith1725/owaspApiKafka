FROM node:20-alpine
WORKDIR /app
COPY sample-app/package*.json ./
RUN npm install --omit=dev
COPY sample-app/ ./
ENV NODE_ENV=production
CMD ["node", "src/index.js"]
