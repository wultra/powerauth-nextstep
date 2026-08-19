FROM ghcr.io/wultra/wultra-base-images:jre-semeru-25_3

# Prepare environment variables
ENV LOGBACK_CONF=/opt/logback/conf \
    APP_PATH="/app/powerauth-nextstep.war" \
    CONTEXT_PATH="/powerauth-nextstep"

# Deploy and run applications
COPY powerauth-nextstep/target/powerauth-nextstep-*.war "${APP_PATH}"

COPY powerauth-nextstep/docker/conf/logback/* $LOGBACK_CONF/