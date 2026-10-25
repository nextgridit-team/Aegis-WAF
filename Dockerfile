FROM node:22-alpine AS dashboard
WORKDIR /build/web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.26-alpine AS backend
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=dashboard /build/internal/app/assets/ internal/app/assets/
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/aegis-waf ./cmd/aegis-waf

FROM alpine:3.23
RUN mkdir -p /var/cache/aegis && chmod 0777 /var/cache/aegis && apk add --no-cache ca-certificates && addgroup -g 10001 aegis-waf && adduser -D -u 10001 -G aegis-waf aegis-waf
COPY --from=backend /out/aegis-waf /usr/local/bin/aegis-waf
COPY third_party_licenses/ /usr/share/licenses/aegis/dependencies/
COPY LICENSE /usr/share/licenses/aegis/LICENSE
COPY --from=backend /usr/local/go/LICENSE /usr/share/licenses/aegis/GO-LICENSE
USER 10001:10001
ENV TMPDIR=/tmp
EXPOSE 8080 8443 9090
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s CMD ["/usr/local/bin/aegis-waf", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/aegis-waf"]
