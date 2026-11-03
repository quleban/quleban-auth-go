# QuLeBanAuth Go

APP 服务器（Go）接入库，提供 code / SSToken 的生成、校验与 UID 读取，以及可选的 HTTPS 回调验签方法。

- [完整接入步骤及全部方法](QuLeBanAuth-Go服务器接入文档.md)
- [APP 服务器 HTTP 回调示例](examples/hostserver/README.md)

## 集成

支持 Go 1.21+。在 APP 项目根目录执行：

```sh
go get github.com/quleban/quleban-auth-go@latest
```

在服务器代码中直接设置平台提供的凭据：

```go
import qulebanauth "github.com/quleban/quleban-auth-go"

auth := &qulebanauth.QuLeBanAuth{
    AppID:     "平台提供的 AppID",
    AppSecret: "平台提供的 AppSecret",
}

result := auth.GetCodeByDefaultDuration(uid) // uid 取自服务器已验证会话
if !result.IsSuccess {
    // 根据 result.SdkErrorCode 处理失败
    return
}
// 将 result.Code、result.ExpireDate 返回 APP
```

AppSecret 仅供服务器使用。构造方法 NewQuLeBanAuth(appID, appSecret) 与结构体初始化等价。回调 SignRequest / VerifyRequest 使用 Sud HTTP 回调协议；APP 已有验签实现时可直接使用自己的代码。

## 拉取源码与验证

```sh
git clone https://github.com/quleban/quleban-auth-go.git
cd quleban-auth-go
go test ./...
go vet ./...
```

testdata/auth-vectors.json 中的凭据是公开测试数据，只用于互操作验证。依赖 github.com/golang-jwt/jwt/v5，版本由 go.mod 锁定。
