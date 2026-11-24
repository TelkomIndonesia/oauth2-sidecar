FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
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
