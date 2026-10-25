FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /vigil ./cmd/vigil

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
RUN adduser -D -u 1001 vigil
COPY --from=build /vigil /usr/local/bin/vigil
USER vigil
ENTRYPOINT ["/usr/local/bin/vigil"]
