# Stage 1: Build the binary
FROM golang:1.25.5-alpine AS builder

WORKDIR /app

# Copy go.mod and sum files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY . .
RUN go build -o main .

# Stage 2: Run the binary
FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/main .

EXPOSE 8080

CMD ["./main"]
