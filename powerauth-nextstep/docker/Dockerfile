FROM ghcr.io/wultra/wultra-base-images:jre-semeru-25_7@sha256:30d496462a9fa1ead309d9397f23a27f6deadf235733547e7c24a4040a3f98fa

# Prepare environment variables
ENV LOGBACK_CONF=/opt/logback/conf \
    APP_PATH="/app/powerauth-nextstep.war" \
    CONTEXT_PATH="/powerauth-nextstep"

# Deploy and run applications
COPY powerauth-nextstep/target/powerauth-nextstep-*.war "${APP_PATH}"

COPY powerauth-nextstep/docker/conf/logback/* $LOGBACK_CONF/