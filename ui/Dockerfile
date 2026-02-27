FROM node:18-alpine AS build
WORKDIR /app
COPY ui/package.json ui/vite.config.js ./
COPY ui/src ./src
COPY ui/public ./public
COPY ui/index.html .
RUN npm install && npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY ui/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
