# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /d
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
ENV VITE_API_BASE=/api
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /d/dist /usr/share/nginx/html
EXPOSE 8080
