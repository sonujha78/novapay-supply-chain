FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/novapay-api .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/novapay-api /novapay-api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/novapay-api"]
