# --- Build -------------------------------------------------------------------
FROM docker.io/library/node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# --- Runtime: static files, runs as an arbitrary non-root UID (OpenShift) ------
FROM docker.io/nginxinc/nginx-unprivileged:stable-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist/secret-sealer/browser /usr/share/nginx/html
EXPOSE 8080
