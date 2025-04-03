FROM nginx:alpine
COPY nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
RUN apk add nginx-mod-http-js
CMD ["nginx", "-g", "daemon off;"]