FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY *.go .
RUN CGO_ENABLED=0 go build -o /envoy-control-plane .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /envoy-control-plane /usr/local/bin/envoy-control-plane

EXPOSE 18000
CMD ["envoy-control-plane"]
