FROM golang:1-alpine as build

# Set build environment
ENV CGO_ENABLED=0

# Build binary
COPY . /atumd
WORKDIR /atumd
RUN go build -a -ldflags '-extldflags "-static"' -o "/bin/atumd" .

# Start building the final image
FROM scratch

# Copy binary from build stage
COPY --from=build /bin/atumd /bin/atumd
