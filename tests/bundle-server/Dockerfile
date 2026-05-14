FROM nginx:alpine as builder

# Install build dependencies
RUN apk add bash

COPY conf/nginx.conf /etc/nginx/nginx.conf

CMD ["nginx", "-g", "daemon off;"]
