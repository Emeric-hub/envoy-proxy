FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /geoip-service .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /geoip-service /usr/local/bin/geoip-service

EXPOSE 8092
CMD ["geoip-service"]
