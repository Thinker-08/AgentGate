FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/agentgate ./cmd/agentgate

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 app
USER app
COPY --from=build /out/agentgate /usr/local/bin/agentgate
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/agentgate"]
