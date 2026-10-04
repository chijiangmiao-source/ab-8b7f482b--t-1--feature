FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

RUN chmod +x scripts/verify.sh

ENV PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/health',timeout=2)"

# 默认运行服务；verify 入口见 docker-compose.yml 的 verify 服务
CMD ["python", "-m", "app.server"]
