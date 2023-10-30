FROM golang:1-alpine as build

ARG SECRETS_LOCATION=/.secrets/

# Build binary
COPY . /atumd
WORKDIR /atumd
RUN go build -a -ldflags '-extldflags "-static"' -o "/bin/atumd" .

# Create empty secrets directory
RUN mkdir -p ${SECRETS_LOCATION}

# Create application user
RUN adduser -D -u 1000 -g atumd atumd

# Start building the final image
FROM scratch

ARG SECRETS_LOCATION=/.secrets/

# Ensure the application user and group is set
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# Copy binary from build stage
COPY --from=build --chown=atumd:atumd /bin/atumd /bin/atumd

# Make the secrets directory available to the application
COPY --from=build --chown=atumd:atumd ${SECRETS_LOCATION} ${SECRETS_LOCATION}

# Switch to application user
USER atumd

ENTRYPOINT ["atumd"]