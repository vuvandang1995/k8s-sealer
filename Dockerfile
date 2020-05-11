FROM golang:1.13 as builder

WORKDIR /app

COPY go.mod .
RUN GO111MODULE=on go mod download

FROM builder AS server_builder

COPY . .
RUN GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -ldflags="-s -w" -o ./seal ./cmd;

FROM ubuntu:18.04
COPY --from=server_builder /app/seal .
CMD [ "./seal" ]