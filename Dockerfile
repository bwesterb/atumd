FROM golang:1-alpine as build

# Build binary
COPY . /atumd
WORKDIR /atumd
RUN go build -a -ldflags '-extldflags "-static"' -o "/bin/atumd" .

# Create application user
RUN adduser -D -u 1000 -g atumd atumd

# Start building the final image
FROM scratch

# Ensure the application user and group is set
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# Copy binary from build stage
COPY --from=build --chown=atumd:atumd /bin/atumd /bin/atumd

# Switch to application user
USER atumd

ENTRYPOINT ["atumd"]