# QuLeBanAuth Go 服务器接入

## SDK 环境要求

- 支持 Go 1.21 或以上版本，使用 Go Modules。
- 向平台获取 AppID、AppSecret。
- GitHub 仓库：[quleban/quleban-auth-go](https://github.com/quleban/quleban-auth-go)。

## 集成流程

1. 在 APP 服务器项目根目录（已有 go.mod）执行以下命令，从 GitHub 拉取 SDK：

```sh
go get github.com/quleban/quleban-auth-go@latest
```

Go 会下载 SDK 及所需依赖，并更新 APP 项目的 go.mod 和 go.sum。后续升级时再次执行此命令。

2. 导入 SDK，在 APP 服务器代码中直接设置 AppID 和 AppSecret：

```go
import qulebanauth "github.com/quleban/quleban-auth-go"

auth := &qulebanauth.QuLeBanAuth{
    AppID:     "平台提供的 AppID",
    AppSecret: "平台提供的 AppSecret",
}
```

3. APP 登录成功后，使用服务器已验证用户的 UID 生成 code，返回给 APP：

```go
result := auth.GetCodeByDefaultDuration(uid)
if !result.IsSuccess {
    // 根据 result.SdkErrorCode 处理失败。
    return
}
// 将 result.Code、result.ExpireDate 返回给 APP。
```

4. APP 服务器按以下方式实现认证相关 HTTPS 接口，并将实际地址交给平台：

| 接口 | 使用方式 |
| --- | --- |
| 获取 code | APP 调用；服务器确认登录态后调用 GetCode 或 GetCodeByDefaultDuration。 |
| get_sstoken | 平台调用；GetUidByCode 校验 code，再用返回的 UID 调用 GetSSToken，返回凭据及用户资料。 |
| get_user_info | 平台调用；GetUidBySSToken 校验 SSToken，再用 UID 查询 APP 用户资料。 |
| update_sstoken | 平台调用；GetUidBySSToken 校验旧凭据，再为同一 UID 生成新凭据。 |

AppSecret、SSToken 仅用于服务器。code 过期后重新获取；旧 SSToken 已过期时重新走 code 兑换流程。HTTP 数据格式和示例见 [APP 服务器回调示例](examples/hostserver/README.md)。

5. 需要查看或运行示例时，将源码拉取到本地：

```sh
git clone https://github.com/quleban/quleban-auth-go.git
cd quleban-auth-go
go test ./...
```

修改 examples/hostserver/main.go 中的示例配置后，按示例 README 运行。SDK 使用 github.com/golang-jwt/jwt/v5 处理凭据，下载依赖需要网络。

## QuLeBanAuth Go

```go
type QuLeBanAuth struct {
    AppID     string
    AppSecret string
}

func NewQuLeBanAuth(appID string, appSecret string) *QuLeBanAuth {
    return &QuLeBanAuth{
        AppID:     appID,
        AppSecret: appSecret,
    }
}

func (client *QuLeBanAuth) GetCode(uid string, expireDuration int64) *QuLeBanCode
func (client *QuLeBanAuth) GetCodeByDefaultDuration(uid string) *QuLeBanCode
func (client *QuLeBanAuth) GetSSToken(uid string, expireDuration int64) *QuLeBanSSToken
func (client *QuLeBanAuth) GetSSTokenByDefaultDuration(uid string) *QuLeBanSSToken
func (client *QuLeBanAuth) GetUidByCode(code string) *QuLeBanUid
func (client *QuLeBanAuth) GetUidBySSToken(ssToken string) *QuLeBanUid
func (client *QuLeBanAuth) VerifyCode(code string) bool
func (client *QuLeBanAuth) VerifySSToken(code string) bool
```

## 错误码定义

```go
const (
    TokenSuccess      = 0    // 成功
    TokenCreateFailed = 1001 // 凭据创建失败
    TokenVerifyFailed = 1002 // 算法或签名校验失败
    TokenDecodeFailed = 1003 // 凭据解析失败
    TokenInvalid      = 1004 // 参数、应用配置或凭据内容非法
    TokenExpired      = 1005 // 凭据过期
    TokenUnknown      = 9999 // 未知错误
)
```

生成及获取 UID 的方法通过 isSuccess、sdkErrorCode 返回结果；VerifyCode、VerifySSToken 返回 bool。以下返回值表使用 JSON 字段名，Go 中对应 Code、Token、ExpireDate、Uid、IsSuccess、SdkErrorCode。

### NewQuLeBanAuth

- 说明

```text
使用 AppID、AppSecret 创建本地 SDK 实例，也可直接初始化 QuLeBanAuth 结构体。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| appID | 是 | string | 平台提供的 AppID。 |
| appSecret | 是 | string | 平台提供的 AppSecret。 |

- 返回值（*QuLeBanAuth）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| 返回值 | *QuLeBanAuth | SDK 实例，用于调用下列方法。 |

### QuLeBanAuth.GetCode

- 说明

```text
获取 code，自定义有效时长。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| uid | 是 | string | APP用户 ID，本应用内唯一，取自APP已验证的登录会话；UTF-8 不超过 200 字节，无首尾空白。 |
| expireDuration | 是 | int64 | 有效时长，单位毫秒。例如 1 小时为 3600000；最短 30 分钟，小于 1800000 按 1800000 处理。 |

- 返回值（QuLeBanCode）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| code | string | 生成的 code；失败时为空。 |
| expireDate | int64 | 过期时间戳，单位毫秒，精度为秒；失败时为 0。 |
| isSuccess | bool | 是否生成成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.GetCodeByDefaultDuration

- 说明

```text
获取 code，默认有效时长为 2 小时。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| uid | 是 | string | APP用户 ID，本应用内唯一，取自APP已验证的登录会话；UTF-8 不超过 200 字节，无首尾空白。 |

- 返回值（QuLeBanCode）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| code | string | 生成的 code；失败时为空。 |
| expireDate | int64 | 过期时间戳，单位毫秒，精度为秒；失败时为 0。 |
| isSuccess | bool | 是否生成成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.GetSSToken

- 说明

```text
获取服务器之间使用的 SSToken，自定义有效时长。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| uid | 是 | string | APP用户 ID，本应用内唯一，取自APP已验证的登录会话；UTF-8 不超过 200 字节，无首尾空白。 |
| expireDuration | 是 | int64 | 有效时长，单位毫秒。例如 4 小时为 14400000；最短 2 小时，小于 7200000 按 7200000 处理。 |

- 返回值（QuLeBanSSToken）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| token | string | 生成的 SSToken；失败时为空。 |
| expireDate | int64 | 过期时间戳，单位毫秒，精度为秒；失败时为 0。 |
| isSuccess | bool | 是否生成成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.GetSSTokenByDefaultDuration

- 说明

```text
获取 SSToken，默认有效时长为 2 小时。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| uid | 是 | string | APP用户 ID，本应用内唯一，取自APP已验证的登录会话；UTF-8 不超过 200 字节，无首尾空白。 |

- 返回值（QuLeBanSSToken）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| token | string | 生成的 SSToken；失败时为空。 |
| expireDate | int64 | 过期时间戳，单位毫秒，精度为秒；失败时为 0。 |
| isSuccess | bool | 是否生成成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.GetUidByCode

- 说明

```text
校验 code 并获取对应用户 UID；校验失败时不返回 UID。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| code | 是 | string | 待校验的 code 原值。 |

- 返回值（QuLeBanUid）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| uid | string | 校验成功后的用户 ID；失败时为空。 |
| isSuccess | bool | 是否校验成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.GetUidBySSToken

- 说明

```text
校验 SSToken 并获取对应用户 UID；校验失败时不返回 UID。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| ssToken | 是 | string | 待校验的 SSToken 原值。 |

- 返回值（QuLeBanUid）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| uid | string | 校验成功后的用户 ID；失败时为空。 |
| isSuccess | bool | 是否校验成功。 |
| sdkErrorCode | int | 0 表示成功，其他值见错误码定义。 |

### QuLeBanAuth.VerifyCode

- 说明

```text
校验 code 是否有效。需要 UID 或具体错误码时，调用 GetUidByCode。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| code | 是 | string | 待校验的 code 原值，不能传 SSToken。 |

- 返回值（bool）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| 返回值 | bool | true：有效；false：校验失败。 |

### QuLeBanAuth.VerifySSToken

- 说明

```text
校验 SSToken 是否有效。需要 UID 或具体错误码时，调用 GetUidBySSToken。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| code | 是 | string | 参数名为 code，实际传入 SSToken 原值。 |

- 返回值（bool）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| 返回值 | bool | true：有效；false：校验失败。 |

expireDuration 为毫秒，使用 Go 时间常量时传 time.Hour.Milliseconds()。code 与 SSToken 不可混用。凭据在过期前可重复校验，新凭据不会自动撤销旧凭据。

## HTTP 回调辅助方法

```go
func (client *QuLeBanAuth) SignRequest(req *http.Request) error
func (client *QuLeBanAuth) VerifyRequest(req *http.Request) error
```

### QuLeBanAuth.SignRequest

- 说明

```text
为 POST 回调请求设置签名头；不发送请求。用于服务端调用方或联调工具。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| req | 是 | *http.Request | 待签名的 POST 请求，包含实际 URL 和原始 body。 |

- 返回值（error）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| 返回值 | error | nil：签名成功；非 nil：配置、请求或读取失败。 |

### QuLeBanAuth.VerifyRequest

- 说明

```text
校验平台回调请求的应用身份、签名、时间和 body；读取后保留 body，供业务继续解析。
```

- 参数

| 参数名 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| req | 是 | *http.Request | APP服务器收到的原始 HTTP POST 请求，包含平台签名头。 |

- 返回值（error）

| 参数名 | 类型 | 说明 |
| --- | --- | --- |
| 返回值 | error | nil：校验通过；非 nil：校验失败，停止业务处理。 |

回调 body 最大 64 KiB；请求头及签名格式与 Sud HTTPS 回调文档一致。VerifyRequest 校验时间窗口为前后 300 秒，APP服务器须按示例原子消费 AppID 与 nonce，防止同一请求重复执行。具体接法见 examples/hostserver/README.md。
