# ---- 中心与 Agent 共用一个镜像,通过 entrypoint 区分 ----
# 基础镜像做成可覆盖:国内直连 Docker Hub 经常拉不动,
#   docker build --build-arg BASE_IMAGE=你的镜像地址/python:3.12-slim .
ARG BASE_IMAGE=python:3.12-slim
FROM ${BASE_IMAGE}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    MESH_DATA_DIR=/data \
    MESH_KEYS_DIR=/keys

WORKDIR /app

# 先装依赖再拷代码:改代码不会让依赖层失效
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd -m -u 10001 mesh \
    && mkdir -p /data /keys \
    && chown -R mesh:mesh /data /keys /app

COPY --chown=mesh:mesh agentmesh ./agentmesh

USER mesh
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=4s --start-period=8s --retries=3 \
    CMD python -c "import httpx,os;httpx.get(f'http://127.0.0.1:{os.getenv(\"MESH_PORT\",\"8765\")}/api/health',timeout=3)"

ENTRYPOINT ["python", "-m", "agentmesh.hub"]