FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cuevello-relay .

FROM alpine:3.20
RUN addgroup -S cuevello && adduser -S cuevello -G cuevello
WORKDIR /app
COPY --from=build /out/cuevello-relay /app/cuevello-relay
USER cuevello
EXPOSE 443 8443
ENTRYPOINT ["/app/cuevello-relay"]
