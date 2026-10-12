# 上云部署

面向一台云主机(2 核 4G 就够跑几十个 Agent)。三种方式,按推荐顺序:
Docker Compose → systemd + venv → 裸跑。

---

## 0. 先想清楚三件事

**① 中心暴露到哪**

Agent 之间和看板都要连中心。但中心管理接口(建任务、启停 Agent)**不应该**暴露公网。

```bash
# 只监听本机,对外交给 nginx
python -m agentmesh.hub --host 127.0.0.1 --port 8765
```

**② 必须设注册口令**

`MESH_ENROLLMENT_TOKEN` 留空 = 任何人都能注册一个"Agent"进来。
生产环境不设口令,等于把系统变成谁都能往里塞任务的公共池。

```bash
export MESH_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"
```

Agent 侧用 `--token` 或同名环境变量带上。

**③ 私钥放哪**

```
keys/
├── hub.pem              中心私钥 —— 泄露 = 攻击者能伪造 operator/system 事件
├── public/              公钥目录(可公开)
│   ├── hub.pem
│   └── <agent_id>.pem
└── agents/              Agent 私钥
    └── <agent_id>.pem   权限 0600
```

备份策略:`data/`(事件日志)和 `keys/`(公钥)都要备;**`keys/hub.pem` 和
`keys/agents/*.pem` 决定系统身份,单独加密备份,别和日志混在一起**。
丢了 Agent 私钥,这个 Agent 就得重新注册换钥(走 `rotate-key` 接口)。

---

## 1. Docker Compose 部署(推荐)

```bash
git clone <your-repo> agentmesh && cd agentmesh
cp .env.example .env

# 生成注册口令写进 .env
echo "MESH_ENROLLMENT_TOKEN=$(openssl rand -hex 32)" >> .env

docker compose up -d --build
docker compose ps
docker compose logs -f hub
```

> **构建卡在拉基础镜像?** `python:3.12-slim` 要从 Docker Hub 拉,国内经常拉不动。
> 换镜像源构建(基础镜像在 Dockerfile 里是可覆盖的 `ARG`):
> ```bash
> docker build --build-arg BASE_IMAGE=你的镜像加速地址/python:3.12-slim -t agentmesh .
> # 或在 daemon.json 里配 registry-mirrors,对所有构建生效
> ```

验证:

```bash
curl -s localhost:8765/api/health
curl -s localhost:8765/api/state | python3 -m json.tool | head -20
```

容器里跑离线校验:

```bash
docker compose exec hub python -m agentmesh.tools.verify
```

**加一个员工:**

```yaml
  data-scientist:
    build: .
    entrypoint: ["python", "-m", "agentmesh.agent"]
    command: ["--id", "data-wren", "--name", "数据 温润", "--role", "数据分析",
              "--capabilities", "analyze,docs", "--hub", "http://hub:8765"]
    environment:
      MESH_ENROLLMENT_TOKEN: ${MESH_ENROLLMENT_TOKEN}
    volumes: [mesh-data:/data, mesh-keys:/keys]
    depends_on: [hub]
    restart: unless-stopped
```

```bash
docker compose up -d data-scientist
```

### 密钥隔离(更严格的做法)

当前所有容器共享 `/keys`,意味着中心容器技术上能读到 Agent 私钥。
虽然代码里中心从不去读,但生产环境建议物理隔开:

```yaml
  hub:
    volumes:
      - mesh-data:/data
      - hub-keys:/keys          # 只有中心自己的钥
  analyst:
    volumes:
      - agent-data:/data/agents
      - hub-keys:/keys          # 只读挂载公钥目录
```

代价:Agent 注册后中心才会拿到它的公钥,需要在启动顺序上处理。
不想折腾就保持共享卷 —— 代码层面中心没有任何读取 Agent 私钥的路径。

---

## 2. systemd + venv(不用 Docker)

```bash
# 依赖
sudo apt install -y python3-venv nginx
python3 -m venv /opt/agentmesh/.venv
/opt/agentmesh/.venv/bin/pip install -r /opt/agentmesh/requirements.txt
```

**中心单元** `/etc/systemd/system/mesh-hub.service`:

```ini
[Unit]
Description=AgentMesh Hub
After=network.target

[Service]
Type=simple
User=mesh
WorkingDirectory=/opt/agentmesh
Environment=MESH_ENROLLMENT_TOKEN=填你的口令
Environment=MESH_HOST=127.0.0.1
Environment=MESH_PORT=8765
Environment=MESH_DATA_DIR=/var/lib/agentmesh
Environment=MESH_KEYS_DIR=/etc/agentmesh/keys
ExecStart=/opt/agentmesh/.venv/bin/python -m agentmesh.hub
Restart=always
RestartSec=3

# 加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/agentmesh /etc/agentmesh/keys

[Install]
WantedBy=multi-user.target
```

**一个 Agent 单元** `/etc/systemd/system/mesh-analyst.service`:

```ini
[Unit]
Description=AgentMesh Agent analyst-lumen
After=mesh-hub.service
Requires=mesh-hub.service

[Service]
Type=simple
User=mesh
WorkingDirectory=/opt/agentmesh
Environment=MESH_ENROLLMENT_TOKEN=同一个口令
ExecStart=/opt/agentmesh/.venv/bin/python -m agentmesh.agent \
    --id analyst-lumen --name "分析师 卢明" --role 需求分析 \
    --capabilities analyze --hub http://127.0.0.1:8765
Restart=always
RestartSec=5
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mesh-hub mesh-analyst
journalctl -u mesh-analyst -f
```

给每个 Agent 一份单元文件,改改 `--id` 和 `--capabilities` 就行。

---

## 3. nginx 反向代理 + HTTPS

Agent 之间走内网 HTTP 就够(加密由签名提供完整性);**浏览器访问中心**需要 HTTPS,
因为公钥和 token 在传输里。

```nginx
server {
    listen 80;
    server_name mesh.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name mesh.example.com;

    ssl_certificate     /etc/letsencrypt/live/mesh.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mesh.example.com/privkey.pem;

    client_max_body_size 4m;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }

    # WebSocket 必须显式升级,否则事件流连不上,看板会一直转圈
    location /ws {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
        proxy_read_timeout 3600s;   # 长连接别被默认 60s 掐断
        proxy_send_timeout 3600s;
    }
}
```

> WebSocket 那段忘了 `Upgrade`/`Connection`,是这类看板最常见的"页面能开但不动"。

收紧跨域(看板和中心同源时其实不需要 CORS):

```
MESH_CORS_ORIGINS=https://mesh.example.com
```

---

## 4. 跨主机部署:Agent 跑在别的机器上

完全支持 —— 这正是中心/Agent 分离的设计目的:

```bash
# 远端机器上
MESH_ENROLLMENT_TOKEN=同一个口令 \
python -m agentmesh.agent --id qa-vera --name "测试 韦安" \
  --capabilities test --hub https://mesh.example.com
```

要点:

- 远端机器的时钟要用 NTP 校准。时间戳不可信到秒级,审计会很别扭
- 远端 Agent 要能访问中心的 **公钥接口** `/api/keys`(默认开放,可按需加白名单)
- 带宽:事件量不大,几百 Agent 也就 KB/s 量级

---

## 5. 换 Postgres(多主机 / 高可用)

当前是单写者 SQLite。要跑多中心或更高吞吐,仓储层是隔离的,加一个 Postgres 实现即可。

**什么时候该换:**

| 场景 | SQLite 够吗 |
|---|---|
| 单中心、几十个 Agent | ✅ 绰绰有余 |
| 单中心、几百个 Agent | ⚠️ 看写入 QPS,可能要换 |
| 多中心同时写 | ❌ 必须换 |
| 要做时间点恢复 / 主从 | ❌ 换 |

**迁移步骤:**

1. 实现 `agentmesh/store_pg.py`,对齐 `Store` 的方法签名
   (`create_task` / `claim_next` / `handoff_task` / `release_expired_leases` …)
2. 认领的原子性靠 Postgres 的条件更新,逻辑照搬:
   ```sql
   UPDATE tasks SET state='claimed', owner=$1, lease_expires_at=$2
    WHERE task_id=$3 AND state='ready' AND owner IS NULL
   ```
   `rowcount = 1` 才算抢到 —— 和 SQLite 版本一模一样
3. 链头要在事务里读(`SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1`),
   不要外挂 Redis 缓存,否则链头和写入可能不一致
4. 迁移历史:直接拷 `events` 表,哈希链原样成立(链只跟内容有关,跟存储无关)

---

## 6. 备份与审计

```bash
# 备份(热备,WAL 模式可以不停服)
sqlite3 /var/lib/agentmesh/mesh.db ".backup '/backup/mesh-$(date +%F).db'"

# 归档私钥(务必加密)
tar czf keys-$(date +%F).tar.gz /etc/agentmesh/keys
gpg --encrypt --recipient ops@example.com keys-*.tar.gz
```

**定期离线审计** —— 这是这套系统最有价值的运维动作:

```bash
/opt/agentmesh/.venv/bin/python -m agentmesh.tools.verify \
    --db /backup/mesh-$(date +%F).db --keys /etc/agentmesh/keys/public
```

退出码非 0 就说明历史被动过。接进 cron:

```cron
0 4 * * * /opt/agentmesh/.venv/bin/python -m agentmesh.tools.verify \
    --db /var/lib/agentmesh/mesh.db --keys /etc/agentmesh/keys/public \
    >> /var/log/agentmesh-audit.log 2>&1
```

```bash
# 退出码非 0 时告警
0 4 * * * /opt/agentmesh/.venv/bin/python -m agentmesh.tools.verify \
    --db /var/lib/agentmesh/mesh.db --keys /etc/agentmesh/keys/public \
    || mail -s "AgentMesh 链校验失败" ops@example.com < /var/log/agentmesh-audit.log
```

---

## 7. 上线检查清单

- [ ] `MESH_ENROLLMENT_TOKEN` 已设置,且不是仓库里的默认值
- [ ] 中心只监听 `127.0.0.1`,外部走 nginx
- [ ] 已配 HTTPS,`/ws` 的 WebSocket 升级头配好(打开看板能看到事件在滚动)
- [ ] `MESH_CORS_ORIGINS` 收紧到实际域名
- [ ] `keys/hub.pem` 权限 0600,已加密备份
- [ ] `data/` 和 `keys/` 都有定时备份
- [ ] 离线校验接进 cron,退出码非 0 会告警
- [ ] 服务器时钟开了 NTP
- [ ] Agent 用的 `step-seconds` 按真实能力耗时调整(能力函数里那点 sleep 是模拟)
- [ ] 跑一遍 `./run_tests.sh` 确认部署环境正常