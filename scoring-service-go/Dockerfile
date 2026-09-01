FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -o /scoring-service-go .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /scoring-service-go /usr/local/bin/scoring-service-go

EXPOSE 8001 9001
CMD ["scoring-service-go"]
