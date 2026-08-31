FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY *.go .
RUN CGO_ENABLED=0 go build -o /coraza-service .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /coraza-service /usr/local/bin/coraza-service

EXPOSE 8003
CMD ["coraza-service"]
