FROM golang:1.21 AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /fleet .

FROM gcr.io/distroless/static-debian12
COPY --from=build /fleet /fleet
EXPOSE 8081
ENTRYPOINT ["/fleet"]
