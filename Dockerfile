FROM golang:1.13.5-alpine

#RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ make ; apt clean ; rm -rf /var/lib/apt/lists/* 

LABEL maintainer="Alessio Savi <alessiosavibtc@gmail.com>"

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . /app

RUN go clean

# Build the Go app
RUN go build -o AuthentiGo .

# Expose port 8080 to the outside world
EXPOSE 11001

# Run the executable
CMD ["./AuthentiGo"]