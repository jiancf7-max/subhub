# SubHub 独立订阅聚合服务

该服务可独立部署，与其他项目无耦合。

## 功能

- 登录后管理多个订阅源（添加 / 启停 / 删除）
- 单个或批量测试连通性（状态码、延迟、节点数）
- 导出四种合集订阅：
  - `Xray`: `/sub/{token}/xray`
  - `Raw`: `/sub/{token}/raw`
  - `Clash Meta`: `/sub/{token}/clash`
  - `sing-box`: `/sub/{token}/singbox`
- 前端支持链接复制和二维码展示
- `sing-box 官方客户端导入` 会输出 `sing-box://import-remote-profile?...`
- `NekoBox(Android) 导入` 会输出 `sn://subscription?...`，并优先使用 `V2Ray/Xray` 数据源

## 启动

```bash
cd /root/subhub-panel
./run_subhub.sh
```

默认配置文件：`/root/subhub-panel/config.json`

默认端口：`8850`
管理员凭据：无固定默认值。

## 初始化管理员（推荐）

启动前可以通过环境变量显式指定管理员账号和密码：

```bash
export SUBHUB_ADMIN_USER='your_admin_user'
export SUBHUB_ADMIN_PASSWORD='your_strong_password'
./run_subhub.sh
```

如果未设置，服务首次启动会自动生成随机管理员用户名和密码，并写入启动日志。

## API（需登录）

- `GET /api/subhub/state`
- `POST /api/account/password`
- `POST /api/subhub/sources`
- `PUT /api/subhub/sources/{source_id}`
- `DELETE /api/subhub/sources/{source_id}`
- `POST /api/subhub/test/{source_id}`
- `POST /api/subhub/test-all`
- `POST /api/subhub/token/rotate`

## 数据文件

- 配置：`/root/subhub-panel/config.json`
- 订阅源+token：`/root/subhub-panel/subhub_data.json`

## systemd（可选）

示例：`/root/subhub-panel/subhub-panel.service.example`
