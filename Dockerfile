# gvl-recon 容器镜像（形态C：开发者）
# 用法：
#   docker build -t gvl-recon .
#   docker run -p 8000:8000 gvl-recon                     # 网页版
#   docker run gvl-recon python main.py --target http://vul001.test --output /app/output  # CLI
FROM python:3.10-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LLM_PROVIDER=off

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
