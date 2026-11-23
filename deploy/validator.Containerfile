FROM golang:1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /oauth2-sidecar ./cmd/oauth2-sidecar

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /oauth2-sidecar /oauth2-sidecar
USER 65532:65532
ENTRYPOINT ["/oauth2-sidecar", "validate"]
