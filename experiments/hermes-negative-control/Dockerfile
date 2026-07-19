# interlock negative control — real hermes-agent, stub model, no network at run time.
#
# Build needs network (pip). RUN TIME MUST NOT: see run.sh, which passes
# --network none. The stub model listens on loopback inside the container, so
# the agent has a "model" without the container having an internet route.
FROM python:3.12-slim

# Pinned so the experiment is reproducible and so the adapter's liveness check
# is exercised against the version its wiring audit was written for.
ARG HERMES_VERSION=0.18.2

# uid pinned so the tmpfs uid= options in run.sh cannot drift from the image.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin agent

WORKDIR /opt
COPY --chown=agent:agent . /opt/interlock

RUN pip install --no-cache-dir "hermes-agent==${HERMES_VERSION}" \
 && pip install --no-cache-dir /opt/interlock \
 && mkdir -p /victim /run/interlock /home/agent/.hermes \
 && chown -R agent:agent /victim /run/interlock /home/agent

USER agent
ENV HERMES_HOME=/home/agent/.hermes \
    OPENAI_API_KEY=stub \
    HERMES_YOLO_MODE=1 \
    INTERLOCK_SOCKET=/run/interlock/interlock.sock \
    VICTIM_DIR=/victim \
    N_CALLS=50 \
    APPROVED_INDEX=7 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /opt/interlock/experiments/hermes-negative-control
ENTRYPOINT ["python", "run_arm.py"]
CMD ["--arm", "interlock"]
