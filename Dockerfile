FROM golang:latest AS builder
WORKDIR /go/src/github.com/jsimonetti/ldapserv
ADD . /go/src/github.com/jsimonetti/ldapserv
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -ldflags '-w -extldflags "-static"' -o /ldapserv

FROM scratch
WORKDIR /app
COPY --from=builder /ldapserv /app
COPY ldif /app/ldif

EXPOSE 6389
CMD [ "/app/ldapserv" ]
