FROM node:12.22.5-alpine3.14

MAINTAINER Eigen

RUN apk add --no-cache python3 make g++ gcompat

WORKDIR /app
COPY . /app
RUN yarn build && yarn test
