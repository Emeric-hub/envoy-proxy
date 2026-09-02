FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /letsencrypt-sidecar .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /letsencrypt-sidecar /usr/local/bin/letsencrypt-sidecar

EXPOSE 8090
CMD ["letsencrypt-sidecar"]
