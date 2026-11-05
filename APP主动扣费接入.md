# APP 主动扣费接入

## 接入步骤

1. 更新 Go SDK，使用平台提供的 AppID、AppSecret 创建 `QuLeBanAuth`。
2. APP 移动端通过 SDK 收到订单，将 `orderToken` 提交给 APP 自己的服务器，同时携带 APP 登录凭据。
3. APP 服务器调用 `VerifyPaymentOrder`，核对返回的 UID 与已登录用户一致，按返回的金额直接扣费。不需要先查询大厅。
4. APP 服务器持久化扣费流水和待通知任务，调用大厅的扣费通知接口。失败重试同一订单和流水，重新生成请求签名。
5. APP 提供游戏处理结果与订单退款回调地址，接收大厅通知。扣费成功、游戏处理成功和退款结果分别记录。

游戏服生成唯一订单、冻结操作和金额，向大厅登记成功后，携带大厅返回的 `orderToken` 交给移动端。前端明文订单用于展示，APP 扣费使用 SDK 校验后返回的数据。

只有玩家主动扣费经过移动端。订单退款由大厅调用下文的 APP 订单退款接口。开启 APP 查询结算后，对局奖励按 [游戏对局结算接入](游戏对局结算接入.md) 查询并发放；其他奖励仍走原有服务器货币接口。

## QuLeBanAuth.VerifyPaymentOrder

```go
func (client *QuLeBanAuth) VerifyPaymentOrder(orderToken string) (*PaymentOrder, error)
```

- 说明：在 APP 服务器本地校验订单凭据、AppID、数据和有效期，返回可信订单内容。此方法不扣费、不发起网络请求，也不消费订单。

| 参数 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| orderToken | 是 | string | SDK 转交的完整订单凭据，原样传入。 |

| 返回值 | 类型 | 说明 |
| --- | --- | --- |
| order | *PaymentOrder | 校验通过的订单，失败时为 nil。 |
| err | error | nil 为成功；ErrPaymentOrderExpired 为过期，ErrPaymentOrderInvalid 为无效凭据、内容或应用身份。 |

```go
auth := &qulebanauth.QuLeBanAuth{
    AppID: "平台提供的 AppID",
    AppSecret: "平台提供的 AppSecret",
}
order, err := auth.VerifyPaymentOrder(orderToken)
if err != nil { return err }
if order.UID != authenticatedUID { return errors.New("订单用户与当前登录用户不一致") }
// 在 APP 自己的数据库事务中，以 order.OrderID 为唯一键：
// 校验余额，扣除 order.Amount，生成稳定 transaction_id，保存待通知大厅的任务。
// 重复请求读取原交易结果，不能再次扣费。
```

以上 `authenticatedUID` 必须来自 APP 服务器验证过的会话；不能采用移动端随请求提交的 UID。扣费与“待通知大厅”任务应在同一事务中保存，避免扣费后重启导致通知丢失。

## PaymentOrder 字段

| JSON 字段 | Go 字段 | 类型 | 说明 |
| --- | --- | --- | --- |
| app_id | AppID | string | 本 APP 身份。 |
| order_id | OrderID | string | 游戏服生成、已在大厅登记的全链路订单号。 |
| uid | UID | string | APP 用户 ID。 |
| mg_id | GameID | string | 游戏 ID。 |
| room_id | RoomID | string | 房间；非房间操作可为空。 |
| round_id | RoundID | string | 对局；非对局操作可为空。 |
| amount | Amount | int64 | 扣费正整数，目前范围 1～2147483647。 |
| action | Action | string | 固定操作码，供 APP 记录消费类型。 |
| action_name | ActionName | string | 操作展示名称。 |
| action_data | ActionData | json.RawMessage | 操作详情 JSON 对象。 |
| created_at | CreatedAt | int64 | 创建时间，Unix 毫秒。 |
| expire_at | ExpireAt | int64 | 开始扣费的截止时间，Unix 毫秒。 |

订单示例：

```json
{
  "app_id": "平台提供的AppID",
  "order_id": "游戏服生成的订单号",
  "uid": "111",
  "mg_id": "1",
  "room_id": "12345",
  "round_id": "",
  "amount": 100,
  "action": "mall_purchase",
  "action_name": "购买商城商品",
  "action_data": {"goodsId":"item_001"},
  "created_at": 1793879700000,
  "expire_at": 1793880000000
}
```

目前游戏使用以下操作码。业务按 `action` 判断，展示使用 `action_name`，具体参数取 `action_data`。

| action | 操作 | action_data |
| --- | --- | --- |
| mall_purchase | 猛鬼商城购买道具、皮肤或随从 | goodsId：商品 ID。 |
| arena_entry | 加入猛鬼竞技席位 | role：所选角色；play：是否进入游戏座位。 |
| arena_ghost_pick | 选择竞技猛鬼，支付费用差额 | kind：猛鬼类型。 |
| arena_item_use | 使用竞技道具 | goodsId：商品；pos：使用位置；requestId：游戏操作标识。 |
| arena_ghost_skill | 释放竞技猛鬼技能 | skillId：技能；playerId：游戏内目标。 |
| pool_cosmetic | 购买台球装饰或球杆 | itemId：商品；requestId：游戏操作标识。 |
| pool_entry | 台球入座或准备新一局 | purpose 为 sit 或 ready；acceptedStake：确认的局费；sit 含 seat，ready 含 ready。 |

扣除数量始终使用订单 `amount`，不能用操作参数里的价格或费用重新计算。

## QuLeBanAuth.SignAPIRequest

```go
func (client *QuLeBanAuth) SignAPIRequest(req *http.Request) error
```

- 说明：为 APP → 大厅的 POST 请求生成 `Authorization: QuLeBan-Auth`，签名使用原始请求体；调用后仍可读取/发送原请求体。

| 参数 | 必选 | 类型 | 说明 |
| --- | --- | --- | --- |
| req | 是 | *http.Request | 已设置 URL 和 JSON 请求体的 POST 请求，正文不超过 64 KiB。 |

返回 nil 表示成功，非 nil 表示请求或凭据无效。每次网络重试重新创建请求并调用本方法；订单号和交易流水号保持原值。

`SignRequest` / `VerifyRequest` 继续用于大厅 → APP 的四头回调，`SignAPIRequest` 用于 APP → 大厅的 Authorization 请求。

## 扣费成功通知

```text
POST https://<大厅域名>/user/app/server/payment/notify
Content-Type: application/json;charset=utf-8
Authorization: QuLeBan-Auth ...
```

```json
{
  "order_id": "游戏订单号",
  "transaction_id": "APP扣费流水号",
  "uid": "111",
  "mg_id": "1",
  "amount": 100,
  "payment_status": "paid"
}
```

`payment_status` 省略时按 `paid`。其余字段来自已验证订单与 APP 已提交的扣费记录。大厅校验 AppID、订单用户、游戏、金额和唯一流水；冲突通知不能覆盖原订单。

```go
payload, err := json.Marshal(map[string]any{
    "order_id": order.OrderID, "transaction_id": transactionID,
    "uid": order.UID, "mg_id": order.GameID, "amount": order.Amount,
    "payment_status": "paid",
})
if err != nil { return err }
req, err := http.NewRequest(http.MethodPost,
    hallBaseURL + "/user/app/server/payment/notify", bytes.NewReader(payload))
if err != nil { return err }
req.Header.Set("Content-Type", "application/json;charset=utf-8")
if err = auth.SignAPIRequest(req); err != nil { return err }
// 用带超时的 HTTP client 发送；同时检查 HTTP 状态和返回 JSON 的 ret_code。
// 发送前 transactionID 所对应扣费必须已提交，不能先通知后扣费。
```

大厅用 `ret_code`、`ret_msg`、`data` 应答，`ret_code=0` 表示通知已可靠接收。游戏仍可能待处理，不能把通知接收成功当作游戏发放成功。超时/网络失败表示结果未知，保留同一订单重新通知。

```json
{
  "ret_code": 0,
  "ret_msg": "",
  "data": {
    "order_id": "游戏订单号",
    "transaction_id": "APP扣费流水号",
    "payment_status": "paid",
    "game_status": "pending",
    "refund_status": "none",
    "refund_target": 0,
    "refunded_amount": 0,
    "result_code": "",
    "result_data": {},
    "order": {"说明":"完整 PaymentOrder，字段见上表"}
  }
}
```

| ret_code | 说明 | APP 处理 |
| --- | --- | --- |
| 0 | 接收成功 | 持久化通知完成状态，等待游戏结果。 |
| 400 | 请求参数错误 | 核对字段和类型，修正后用原订单通知。 |
| 401 | 身份、签名或时间无效 | 核对凭据和服务器时间，重新签名。 |
| 404 | 订单不存在 | 保留已扣费记录，核对大厅环境和订单号后处理。 |
| 409 | 重复 nonce，或订单内容、状态、流水冲突 | 重新签名查询原订单并核对流水，不能新建订单再次扣费。 |
| 429 | 请求限流 | 稍后重新签名通知，保持订单和流水不变。 |
| 503 | 暂时无法处理 | 保留任务，稍后重新签名重试。 |

APP 服务器明确取消且保证没有扣费时，可发送同接口、同订单身份和金额、`payment_status:"cancelled"`，不填写交易流水号。已扣费订单不能用此方式取消。移动端关闭窗口或网络超时不能作为“未扣费”的依据。

## 查询订单结果（可选）

```text
POST https://<大厅域名>/user/app/server/payment/query
Authorization: QuLeBan-Auth ...
```

```json
{"order_id":"游戏订单号"}
```

用于通知超时、断线恢复或主动查询最终处理结果；正常扣费流程无需先调用本接口。使用 `SignAPIRequest` 签名。

应答结构与扣费通知相同，`data.order` 是已登记的完整订单。只允许查询当前 AppID 的订单。

## 接收游戏处理结果

APP 提供 HTTPS 回调地址，由平台填入 `PaymentResultUrl`。大厅使用四个 `Sud-*` 头签名，APP 可用 `VerifyRequest` 验签，并原子记录 AppID+nonce 防重放。

```json
{
  "order_id": "游戏订单号",
  "transaction_id": "APP扣费流水号",
  "uid": "111",
  "mg_id": "1",
  "amount": 100,
  "payment_status": "paid",
  "game_status": "success",
  "refund_status": "none",
  "refund_target": 0,
  "refunded_amount": 0,
  "result_code": "",
  "result_data": {"item_id":"item_001","quantity":1},
  "completed_at": 1793879800000
}
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| order_id | string | 原游戏订单号。 |
| transaction_id | string | APP 扣费流水；未支付取消时为空。 |
| uid / mg_id | string | APP 用户 ID / 游戏 ID。 |
| amount | int | 原订单扣费金额。 |
| payment_status | string | `pending` 待支付、`paid` 已支付、`cancelled` 未支付取消、`refunding` 退款处理中、`refunded` 已退款。 |
| game_status | string | `pending` 待游戏处理、`success` 成功、`failed` 失败。 |
| refund_status | string | `none` 未退款、`pending` 退款处理中、`partial` 已部分退款、`refunded` 已全额退款。 |
| refund_target | int | 本单已确认需要退回的累计数量。 |
| refunded_amount | int | APP 已确认退回的累计数量，不超过原订单金额。 |
| result_code | string | 游戏返回的业务结果码，可为空；APP 取消为 `payment_cancelled`。 |
| result_data | object | 游戏操作结果详情。 |
| completed_at | int64 | 游戏结果或取消状态的记录时间，Unix 毫秒。 |

APP 持久化结果后返回：

```json
{"ret_code":0,"ret_msg":""}
```

回调可能重复，按订单幂等更新；重复成功仍返回0。失败订单后续可能收到退款完成状态，不能把第一次回调永久视为最后一个状态。

成功以游戏服持久化业务结果为准。游戏暂时断线、通知超时不直接判失败；游戏明确无法执行后，大厅发起下面的订单退款请求。APP 收到 `failed` 结果回调只记录结果，不自行再退一次。实际加币在专用退款接口中幂等处理。

已成功入座后正常退费不会把 `game_status:success` 改成失败；是否退费以 `refund_status` 和 `refunded_amount` 为准。重复或乱序结果通知不能使已退款数量倒退。

## APP 订单退款接口

APP 提供 HTTPS POST 地址，由平台填入 `PaymentRefundUrl`。大厅使用四个 `Sud-*` 头签名，APP 调用 `VerifyRequest` 验签并检查 nonce。

游戏明确无法执行已支付操作时，大厅按原订单申请退款；正常退桌或退回费用差额也归入同一订单的退款记录。退款请求包含原订单号，APP 不需要猜测扣的是哪一笔钱。

```json
{
  "order_id": "原游戏订单号",
  "transaction_id": "原APP扣费流水号",
  "refund_id": "本批退款唯一请求号",
  "uid": "111",
  "mg_id": "1",
  "amount": 60,
  "refund_total": 100,
  "reason": "game_failed"
}
```

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| order_id | string | 原扣费订单号，与最初收到的订单一致。 |
| transaction_id | string | APP 原扣费流水。 |
| refund_id | string | 本批退款的稳定幂等号，重试保持原值；按原样存储。 |
| uid / mg_id | string | 原用户 / 游戏 ID。 |
| amount | int | **本批需要加回的货币数量**，正整数。 |
| refund_total | int | 本批成功后，该原订单累计退回的数量。不是本次加币量。 |
| reason | string | `game_failed` 表示操作失败退款，`game_refund` 表示正常退费。 |

上例表示此前已退 40，本批再退 60，累计退 100。APP 在同一数据库事务中校验原付款订单、退款流水与金额上限，加回本批 `amount` 并保存 `refund_id`；重复请求直接返回原成功结果，不能再次加币。即使分多次退款，累计退款也不能超过原扣费金额。

退款已可靠完成后返回：

```json
{
  "ret_code": 0,
  "ret_msg": "",
  "data": {
    "order_id": "原游戏订单号",
    "refund_id": "本批退款唯一请求号",
    "amount": 60,
    "refund_status": "refunded"
  }
}
```

这里 `data.refund_status:"refunded"` 表示**本批请求**已完成。大厅严格核对回显订单号、退款请求号、金额和状态；只返回 `ret_code:0` 不代表有效退款确认。

网络超时、非成功响应或回显不符时，大厅保留原批次重试。APP 若已退款但应答丢失，按同一 `refund_id` 返回成功即可。游戏结果未知时不会因超时自动退款；确认无法执行后才发起失败退款。部分已退后又确认整笔操作失败，大厅只申请剩余可退金额。

订单有效期限制开始扣费时间。扣费已经完成，但通知延迟到达时，仍发送原交易通知，由大厅处理，不能再扣一次。

玩家重试过期待付订单时，游戏可申请为同一个订单续签有效期，订单号、用户、金额和操作保持不变。APP 仍按 AppID+order_id 查询自己的原流水：已扣费则补通知，不再扣费；已明确取消则保持取消。不能把新的 orderToken 当作新的消费订单。
