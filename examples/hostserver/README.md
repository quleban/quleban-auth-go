# APP服务器 HTTP 回调接入与示例

本目录提供独立、可运行的APP接口示例。SDK 本身不发网络请求；这里的服务器用于接收APP 以及平台大厅的请求。

## 获取示例

```sh
git clone https://github.com/quleban/quleban-auth-go.git
cd quleban-auth-go
```

## 运行

打开本目录的 `main.go`，直接给结构体设置平台提供的 AppID、AppSecret：

```go
auth := &qulebanauth.QuLeBanAuth{
    AppID:     "平台提供的 AppID",
    AppSecret: "平台提供的 AppSecret",
}
```

在同一个 `main` 函数中，`provider.uid` 是开发测试用户，默认 `111`；将 `provider.sessionToken` 的占位符替换为自己生成的至少 32 字符随机开发会话密钥。占位符没有替换时，示例拒绝启动。

随后在 SDK 根目录执行：

```sh
go run ./examples/hostserver
```

监听地址固定为 `127.0.0.1:18080`，默认本机 HTTP。可在 `main.go` 同时设置 `cert` / `key` 两个证书文件路径，启动 HTTPS。正式部署应接入自己的 HTTPS 服务与证书，不应直接暴露开发身份适配器。

请求 `POST /quleban/get_code` 时发送 `Authorization: Bearer <配置的 sessionToken>`。该开发会话只代表服务器 `provider.uid` 指定的用户，查询参数或 JSON 中的 UID 不影响身份。

生产接入须实现 `IdentityProvider`：`AuthenticateApp` 从APP真实登录会话取得用户；`UserInfo` 查询APP自己的数据库并检查用户是否仍有效。示例头像为空、昵称固定，仅用于本机验证，不代表接通真实用户资料。

将 APP 实际部署的 `/quleban/get_sstoken` 地址填写到 `CodeExchangeUrl`，`/quleban/update_sstoken` 填写到 `TokenRefreshUrl`，`/quleban/get_user_info` 填写到 `PlayerInfoUrl`。路径可自行修改。使用 HTTPS（本机调试允许 HTTP）；大厅将 code 原样交给 APP 校验，采用返回的 SSToken 和用户资料。

## HTTP 数据协议

所有接口为 POST，JSON UTF-8；回调请求体不超过 64 KiB。业务成功使用 HTTP 200 和 `ret_code: 0`，失败 `ret_code` 非零。SDK 失败将原始错误码填到 `sdk_error_code`，不返回用户资料或凭据。

### code 换 SSToken

请求：

```json
{"code":"Go SDK生成的code"}
```

响应：

```json
{
  "ret_code": 0,
  "ret_msg": "",
  "sdk_error_code": 0,
  "data": {
    "ss_token": "服务端凭据",
    "expire_date": 1800007200000,
    "expire_date_str": "1800007200000"
  }
}
```

处理时通过 `GetUidByCode` 取得可信 UID，确认用户有效后调用 `GetSSTokenByDefaultDuration`。`expire_date` 为毫秒时间戳，`expire_date_str` 是同值的十进制字符串。

### 查询用户资料

请求：

```json
{"ss_token":"服务端凭据"}
```

响应：

```json
{
  "ret_code": 0,
  "ret_msg": "",
  "sdk_error_code": 0,
  "data": {
    "uid": "111",
    "nick_name": "用户昵称",
    "avatar_url": "https://cdn.example.com/avatar.png",
    "gender": "male"
  }
}
```

通过 `GetUidBySSToken` 验证身份后查库，返回 UID 必须与 token 的 UID 一致。`gender` 使用 `male` / `female` / 空字符串；头像使用实际图片 HTTPS URL，可为空。

### 更新 SSToken

`POST /quleban/update_sstoken` 同样接收 `{"ss_token":"旧凭据"}`，校验通过后为同一 UID 生成新 SSToken，响应与兑换接口相同。旧 token 已过期则失败，需重新获取 code。大厅当前登录链路只调用兑换和资料接口，不自动调用此刷新接口。

### 失败响应

```json
{"ret_code":1,"ret_msg":"invalid code","sdk_error_code":1005,"data":{}}
```

身份或签名错误也可以返回 HTTP 401；JSON/字段非法返回 400；重放存储不可用返回 503。不要在错误信息或日志里输出 AppSecret、code、SSToken、APP会话凭据。

## 大厅到APP的请求签名

兑换、刷新、资料接口必须校验以下四个请求头：

| 请求头 | 内容 |
|---|---|
| Sud-AppId | GM 分配的 AppID |
| Sud-Timestamp | Unix 毫秒时间戳，允许前后 300 秒 |
| Sud-Nonce | 16 个随机字节的小写 hex，共 32 字符 |
| Sud-Signature | HMAC-SHA1 结果的小写 hex，共 40 字符 |

签名内容由以下四项组成，每项后都带一个 LF（`\n`），包括原始 body 后的最后一个换行：

```text
AppID\n
Timestamp\n
Nonce\n
原始请求body\n
```

使用 `AppSecret` 原文 UTF-8 字节作为 HMAC-SHA1 密钥。body 必须使用实际收到的原始字节，不能解析 JSON 后重新序列化。URL 路径和查询参数不参与签名。请求头使用 `Sud-AppId`、`Sud-Timestamp`、`Sud-Nonce`、`Sud-Signature`。

```go
// auth.VerifyRequest 会读 body 并还原，业务仍能继续解析。
if err := auth.VerifyRequest(req); err != nil {
    // 返回 401，禁止继续执行
    return
}
// 原子消费 AppID + Nonce，成功后才处理业务。
```

`SignRequest(req *http.Request) error` 用于需要构造签名请求的调用方或联调工具；它只写入签名头，不发送请求。`VerifyRequest(req *http.Request) error` 校验方法、AppID、时间、签名和 body 大小，不自己保存 nonce。

示例通过 `NonceStore` 在验签后原子消费 nonce。`memoryNonces` 有容量上限，满时拒绝请求，不淘汰尚有效记录；仅适合单进程调试。正式多实例部署须提供共享存储，如 Redis `SET key value NX EX ttl`，保留至请求毫秒时间戳所指时刻再加 301 秒。重试须使用新时间与新 nonce 重新签名。不要把请求 nonce 去重误认为 code 一次性：同一个有效 code 仍可重新兑换。

## 验证

SDK 根目录执行 `go test ./...`。示例测试覆盖已登录身份→code→SSToken→用户资料→刷新、忽略客户端伪造 UID、拒绝未签名请求、nonce 重放与并发消费、code/SSToken 类型隔离。

公开跨语言向量位于 `testdata/auth-vectors.json`，含测试 AppID/AppSecret、固定验证时刻、JWT 和 Sud HTTP 回调签名。测试凭据不能用于真实渠道。网络层须由双方使用真实 HTTPS 地址进行联调；本示例不连接真实APP数据库。
