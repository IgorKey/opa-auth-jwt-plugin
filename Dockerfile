FROM golang:1.18 AS builder
RUN mkdir /app
COPY . /app/
WORKDIR /app
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o opa

FROM alpine:3.19
RUN addgroup -S opa && adduser -S -G opa opa
COPY --from=builder /app/opa /usr/local/bin/
RUN chown opa:opa /usr/local/bin/opa && chmod 755 /usr/local/bin/opa
USER opa
WORKDIR /usr/local/bin/

EXPOSE 8181
ENTRYPOINT ["opa"]