# 华师大开放数据

`@eduwork/dsh-ecnu-open-data` · v0.1.0 · MulanPSL-2.0 AND MIT

把华东师范大学开发者平台的数据开放能力接进 DSH 会话：人员检索、学生与教职工档案、证件照、身份治理岗位，以及一个走白名单的通用查询工具。

学校平台上有两套 OAuth2，本插件严格分开使用。机构级读取用平台的 `client_credentials`（平台明确允许并发多个令牌）；属于某个人的数据用学校 SSO 的授权码模式，回调落在本机 loopback 端口，因此可以省略学工号直接读当前登录者自己的记录。

## 亮点

- 八个只读工具，插件里没有任何写接口。
- 两种凭据不互相兜底：`mode=institutional` 绝不用个人令牌，`mode=personal` 绝不用应用凭据。
- 应用令牌一会话只取一次，到期前五分钟刷新；网关返回 `A401OT` 时作废并重取一次。
- 本地限速桶按平台每应用每分钟 300 次的上限留余量。
- 通用查询是白名单：证件号、人脸识别、身份核验、消息发送、应用管理、数据同步等路径在请求发出前就被拒绝。
- 所有结果里的证件号都脱敏，工具输出有字段与条数上限。
- 登录态存在 `$DSH_HOME/ecnu-open-data/user-token.json`（权限 0600），`ecnu_open_logout` 会删除它。

## 安装

```sh
dsh plugin --profile web add https://github.com/xiehao-001/dsh-ecnu-open-data
```

离线时把同一条命令指到本地目录即可。

## 配置

bundle 的 patch 只装一行默认配置。凭据不进 profile，从 DSH 凭据库读取。

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `apiBaseURL` | `https://api.ecnu.edu.cn` | 网关源，调用时拼 `/api/v1`。 |
| `ssoBaseURL` | `https://sso.ecnu.edu.cn` | SSO 源，派生出 authorize/token/profile/logout 四个端点。 |
| `scope` | `ECNU-Basic` | 申请的 OAuth2 scope。 |
| `redirectUri` | `http://127.0.0.1:47823/oauth2/callback` | 本机回调，必须与平台登记值完全一致。 |
| `clientIdRef` | `ECNU_OPENAPI_CLIENT_ID` | 公开 client id 的凭据引用。 |
| `clientSecretRef` | `ECNU_OPENAPI_CLIENT_SECRET` | client secret 的凭据引用。 |
| `userTokenRef` | `ECNU_OPENAPI_USER_TOKEN` | 可选，粘贴个人令牌时优先于浏览器登录。 |
| `requestTimeoutMs` | `20000` | 单次请求超时。 |
| `rateLimitPerMinute` | `240` | 本地限速，平台默认 300。 |
| `allowGenericQuery` | `true` | 设为 `false` 时只保留五个专用读取工具。 |
| `recordLimit` | `200` | 单个结果保留的最大记录数。 |

`apiBaseURL` 与 `ssoBaseURL` 也可由 `ECNU_OPENAPI_BASE_URL`、`ECNU_OPENAPI_SSO_URL` 提供。三个凭据值写进 `$DSH_HOME/.credentials.yaml` 的 `refs`。

## 工具

| 工具 | 读取 | 备注 |
| --- | --- | --- |
| `ecnu_open_auth_status` | – | 应用凭据是否配好、是否有人登录、令牌剩余时间。 |
| `ecnu_open_login` | – | 返回授权地址；loopback 接收回调，结果看 `ecnu_open_auth_status`。 |
| `ecnu_open_logout` | – | 本地忘记登录者并关闭 loopback 监听。 |
| `ecnu_open_user_info` | `/user/info` | 姓名、身份类型、部门、在职在校状态。 |
| `ecnu_open_user_profile` | `/user/profile/{student,staff,bks,yjs}` | 完整档案，可指定字段。 |
| `ecnu_open_positions` | `/user/position`、`/user/positionusers` | 人查岗位，或岗位查人。 |
| `ecnu_open_user_photo` | `/user/photo` | base64 data URL，上限 512 KiB。 |
| `ecnu_open_query` | 白名单 `/api/v1/*` | 组织、教学、校园卡等目录类读取的出口。 |

`mode` 取 `auto`（默认）、`institutional`、`personal`。`auto` 优先已登录的本人（这条路可以省略 `userId`），否则回落应用凭据。

## 要求

- DSH `>=0.2.1 <0.3.0`，`@deepseek-ai/dsh-tools >=0.1.2-rc.1`。
- 在开放平台申请到应用凭据，并按数据分类申请所需接口权限。
- 网关只对校园网地址开放；校外请求会在网络层失败，插件会报网络错误而不是凭据错误。
- 授权码回调必须在平台登记为 `redirectUri` 的完整值（含端口）。

## 限制

- 所有读取都是 GET。插件故意不提供写、消息、同步类工具。
- `client_credentials` 令牌有效两小时；授权码模式按人发令牌，过期要靠 `refresh_token` 续。刷新同样需要 client secret，所以它只放在凭据库里。
- 平台规定同一用户同一应用同时只能有一个授权码令牌；在另一台机器登录可能让当前令牌失效，下一次读取会重取或直接报错。
- 证件照与档案是个人信息。结果只留在当前会话，除上述令牌缓存外不落盘，插件也不记录任何响应正文。
- 验证限度：工具装配、令牌处理、白名单、loopback 登录由 `tools/test-ecnu-open-data.mjs`（21 项）与 `tools/e2e-ecnu-open-data.mjs`（14 项）用 mock 网关覆盖。**未对真实 ECNU 网关联调**，因为需要已批准的 client id 与校园网地址。

## English documentation

See [README.md](./README.md).

## 许可

Mulan PSL v2，插件壳部分 MIT；见 [LICENSE](./LICENSE)、[LICENSE-MIT](./LICENSE-MIT) 与 [LICENSING.md](./LICENSING.md)。
