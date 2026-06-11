# Runner image for safedata's hardened container isolation
# (run_safely(..., isolation="docker")).
#
# Build once:
#     docker build -t safedata-guard-runner:1.0.7 .
#
# The image bundles safedata + its analysis deps so the container can run with
# NO network and a READ-ONLY root filesystem at run time (the secure defaults in
# safedata.bodyguard.DOCKER_DEFAULTS). Nothing is installed at run time.
FROM python:3.11-slim

# Pinned to match DOCKER_DEFAULTS["image"]; bump both together on release.
RUN pip install --no-cache-dir "safedata-guard==1.0.7" pandas numpy

# Optional: add polars if you analyse Polars frames inside the container.
# RUN pip install --no-cache-dir polars

# Run as a non-root user; the host mounts the per-job work dir at /job.
RUN useradd --create-home runner
USER runner

# The parent process invokes `python -m safedata._runner ...` explicitly, so no
# ENTRYPOINT is needed; this just documents the contract.
WORKDIR /job
