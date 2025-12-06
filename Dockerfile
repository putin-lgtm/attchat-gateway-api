FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o gateway-api ./cmd/main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/gateway-api .
EXPOSE 8080
CMD ["./gateway-api"]
