FROM docker.io/golang:1.23.5-alpine3.21 as build

# Install some required dependencies
RUN apk add --no-cache --update ca-certificates linux-headers musl-dev gcc git make clang \
    llvm libbpf

WORKDIR /go/src/app

COPY . .

RUN go mod download && go generate
RUN CGO_ENABLED=0 go build -o /go/bin/app/rootisnaked

FROM gcr.io/distroless/static-debian12
COPY --from=build /go/bin/app/rootisnaked /
CMD ["/rootisnaked"]