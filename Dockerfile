# Step 1: Build the Go application
FROM golang:1.23 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the Go Modules and download the dependencies
COPY go.mod go.sum ./
RUN go mod tidy

# Copy the source code into the container
COPY . .

# Build the Go app
RUN go build -o main .

# Step 2: Create a minimal runtime image
FROM debian:bullseye-slim

# Set the Current Working Directory inside the container
WORKDIR /root/

# Copy the pre-built binary from the builder image
COPY --from=builder /app/main .

# Expose the port that your app runs on
EXPOSE 8443

# Command to run the executable
CMD ["./main"]
