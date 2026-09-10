FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache git ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -o /out/migrate ./cmd/migrate

FROM alpine:3.20 AS runner
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 app
USER app
COPY --from=build /out/api /bin/api
COPY --from=build /out/migrate /bin/migrate
EXPOSE 8080
ENTRYPOINT ["/bin/api"]
