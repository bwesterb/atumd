FROM golang:1-alpine as build

# Build binary
COPY . /atumd
WORKDIR /atumd
RUN go build -a -o "/bin/atumd" .

# Start building the final image
FROM scratch

# Copy binary from build stage
COPY --from=build /bin/atumd /bin/atumd
