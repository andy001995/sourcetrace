# sourcetrace 容器镜像（形态C：开发者）
# 用法：
#   docker build -t sourcetrace .
#   docker run -p 8000:8000 sourcetrace                     # 网页版
#   docker run sourcetrace python main.py --target http://example.com --output /app/output  # CLI
FROM python:3.10-slim
LABEL org.opencontainers.image.title="星巡 · 源链（SourceTrace）"
LABEL org.opencontainers.image.description="前端静态源码业务链路解析工具 · 零主动探测"
LABEL org.opencontainers.image.licenses="AGPL-3.0"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LLM_PROVIDER=off

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
