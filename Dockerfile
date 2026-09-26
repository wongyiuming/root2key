FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/root2key ./cmd/root2key

FROM alpine:3.20
RUN addgroup -S root2key && adduser -S -G root2key -H root2key
COPY --from=build /out/root2key /usr/local/bin/root2key
USER root2key
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/root2key"]
