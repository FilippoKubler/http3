FROM golang:1.21.7 AS build

# Set destination for COPY
RUN mkdir app 
WORKDIR /app

# Download Go modules
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copy the source code. Note the slash at the end, as explained in
# https://docs.docker.com/reference/dockerfile/#copy
COPY http3-client.go ./

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o ./http3-client

FROM alpine

COPY --from=build /app/http3-client /usr/bin/http3-client

RUN mkdir certs
COPY ./certs/cert.pem ./certs/cert.pem
COPY ./certs/priv.key ./certs/priv.key

# Run
ENTRYPOINT ["/usr/bin/http3-client"]