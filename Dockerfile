# Run ajar without installing anything locally:
#   docker build -t ajar .
#   docker run --rm -v "$PWD:/src" ajar scan /src
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ajar" \
      org.opencontainers.image.description="Defensive scanner for fail-open logic and web vulnerabilities" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir .

# Drop root for safety.
RUN useradd --create-home scanner
USER scanner

WORKDIR /src
ENTRYPOINT ["ajar"]
CMD ["scan", "/src"]
