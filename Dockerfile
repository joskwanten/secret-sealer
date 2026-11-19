# Static files only: no build step. Runs as an arbitrary non-root UID (OpenShift).
FROM docker.io/nginxinc/nginx-unprivileged:stable-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY web /usr/share/nginx/html
EXPOSE 8080
