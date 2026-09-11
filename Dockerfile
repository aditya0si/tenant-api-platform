FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -o /out/migrate ./cmd/migrate \
 && CGO_ENABLED=0 go build -trimpath -o /out/worker ./cmd/worker

FROM alpine:3.20 AS runner
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 app
USER app
COPY --from=build /out/api /bin/api
COPY --from=build /out/migrate /bin/migrate
COPY --from=build /out/worker /bin/worker
# The API's port. The worker's metrics port is not exposed here because it is selected per
# deployment; a compose service publishes it explicitly.
EXPOSE 8080
ENTRYPOINT ["/bin/api"]
