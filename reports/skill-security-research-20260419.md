# Skill 安全检测研究与 `yao-doctor-skill` 算法改进报告

日期：`2026-04-19`  
研究对象：面向本地 agent skill / OpenClaw skill / 相关 agent 配置与工作流的安全检测机制  
研究目的：在不把“权限大”误判成“恶意”的前提下，提升 `yao-doctor-skill` 对真实隐私窃取、凭据外传、伪装诱导、供应链投毒、混淆执行等行为的识别能力，并系统性降低误报。

---

## 一、摘要

这份报告聚焦一个非常具体、但又容易被做偏的问题：**如何检测 skill 的不安全行为，而不是只检测它“有能力做什么”**。  
如果把这个问题做成传统的权限扫描器，那么几乎所有真正有用的 skill 都会被打成高风险，因为它们天然需要读文件、跑命令、联网、调用 API。这样的工具看起来很严格，实际却不可靠，因为它没有回答用户最关心的问题：**这个 skill 到底是在正常做事，还是在偷偷偷东西、发东西、诱导东西、绕过东西？**

本研究围绕六类高信号参考对象展开：

1. [TruffleHog](https://github.com/trufflesecurity/trufflehog)
2. [Gitleaks](https://github.com/gitleaks/gitleaks)
3. [detect-secrets](https://github.com/Yelp/detect-secrets)
4. [AgentShield](https://github.com/affaan-m/agentshield)
5. [GitHub Agentic Workflows Threat Detection](https://github.github.com/gh-aw/reference/threat-detection/)
6. [Malicious Or Not: Adding Repository Context to Agent Skill Classification](https://arxiv.org/abs/2603.16572)

结论可以先提前说清楚：

- 真正高质量的安全扫描，不是“规则越多越好”，而是**上下文越准越好**。
- 真正有价值的检测，不是“看到网络就报”，而是**把敏感源、转换、出口、意图、来源上下文、仓库语境串起来看**。
- 真正能长期稳定运行的系统，不是“靠分析师每次手工解释误报”，而是**要有审阅基线、可追溯抑制、可解释置信度**。
- 真正对抗伪装型恶意 skill 的关键，不是只看文件名或单条代码，而是**看“声明的用途”和“实际行为”是否一致，看仓库上下文是否支撑该行为**。

基于这些研究结果，`yao-doctor-skill` 的设计不应该走“万能黑名单扫描器”路线，而应该明确分成六层：

1. 来源上下文层：这个命中来自运行面、工作流面、配置面，还是文档/示例/测试夹具。
2. 能力面层：这个 skill 拥有哪些潜在能力。
3. 行为层：这个 skill 是否出现了真实不安全行为证据。
4. 链路层：是否形成“敏感源 -> 转换/打包 -> 外传/执行”的闭环。
5. 伪装层：声明用途、文件命名、仓库角色与实际行为是否一致。
6. 审阅记忆层：历史已确认误报、已接受风险是否可持续记忆，而不是每次重复判断。

这份报告的核心价值不是列一堆项目介绍，而是把这些项目真正值得借鉴的机制提取出来，映射到 `yao-doctor-skill` 的检测算法、误报收敛策略、报告设计和后续路线图。

---

## 二、问题定义：什么是“风险”，什么是“不安全”

在 skill 安全审计里，最常见也最致命的设计错误，就是把“风险”和“不安全”混为一谈。

### 2.1 风险不是罪证

一个 skill 只要稍微有点用，通常就需要下面这些能力中的一种或多种：

- 读写文件
- 访问环境变量
- 运行本地命令
- 调用第三方 API
- 下载依赖或工具
- 调度自动化任务

这些能力确实会扩大攻击面，但它们本身只说明：**如果这个 skill 恶意，它有条件作恶**。  
它们并不说明：**这个 skill 已经在作恶**。

例如：

- 一个文档处理 skill 读取 `.docx`、解压 OOXML、调用 `soffice`，这是高能力面，不等于恶意。
- 一个 GitHub 同步 skill 读取 `GITHUB_TOKEN` 并访问 `api.github.com`，这是有边界的信任扩张，不等于信息窃取。
- 一个测试编排 skill 跑 `make test`、`pytest`、`npm install`，这是工程能力，不等于远控执行。

如果扫描器看到这些动作就直接打成“unsafe”，最后只会得到一个噪声巨大的结果：  
真正危险的 skill 淹没在大量正常工程逻辑里，分析师和用户都不再相信报告。

### 2.2 不安全需要行为证据

对 skill 而言，真正需要重点识别的是下面这些模式：

- 明确读取敏感路径，如 `~/.ssh`、浏览器登录态、钱包、系统 keychain、`.aws/credentials`
- 读取环境变量、token 文件、auth 配置，并与外部发送行为联动
- 静默外传、隐藏执行、绕过确认、伪装成普通整理流程
- 下载远程内容并执行，尤其是 `curl | sh`、`bash -c`、`python -c`、`node -e`
- 用短链、paste 站、压缩包、base64 之类手段隐藏最终 payload
- 改写 CI/CD、依赖清单、agent 指令文件、自动化配置，建立后续持久化或供应链入口

所以一个成熟的 skill 安全审计系统必须明确做两条轴：

- `capability risk`：它有多大攻击面
- `unsafe behavior`：它有没有真实不安全证据

只有把这两条轴拆开，才可能同时做到：

- 不把正常 skill 大面积打成“恶意”
- 又能把真正伪装过的 skill 从正常工程逻辑里提出来

### 2.3 为什么 skill 比普通代码更难审

skill 与普通仓库代码不同的地方在于：

- 它天然混合了说明文档、提示词、脚本、配置、评估、样例、生成物
- 很多危险行为不会写在一个函数里，而是分散在文档、脚本、manifest、workflow、远端资源之间
- 恶意作者很可能不会直接写“steal secrets”，而会伪装成“backup”、“sync”、“benchmark”、“helper”、“release”
- 很多真正危险的东西并不在 skill 主体里，而在它后续下载的脚本、引用的 prompt、工作流产出的 patch、被劫持的仓库上

这也是为什么简单的关键词扫描会在 skill 场景里迅速失效。  
你看到的不是一段纯代码，而是一组跨文件、跨语义层的复合对象。

---

## 三、研究方法与评估框架

这次研究并不是只看 README 做概览，而是按下面的方法分层进行：

### 3.1 研究材料来源

主要材料来自：

- 官方仓库 README、配置、核心实现文件
- 官方文档与规则设计说明
- 与误报收敛直接相关的设计文档、测试、审计记录
- 学术论文摘要与论文主张

### 3.2 关注维度

每个项目都从以下维度进行拆解：

1. 它到底在解决什么问题
2. 它的检测核心对象是什么
3. 它如何降低误报
4. 它如何保留审阅结论
5. 它如何处理“上下文”
6. 它的机制哪些适合 skill 安全扫描，哪些不适合

### 3.3 判断标准

不是所有好用的秘密扫描器都适合 skill 安全扫描。  
因此本研究特别关注三类“可迁移性”：

- **规则可迁移性**：规则能否直接迁移到 skill 检测
- **机制可迁移性**：其思想是否能迁移，但实现方式要改
- **工作流可迁移性**：它的审阅、基线、治理流程是否值得借鉴

一个典型例子是 TruffleHog。  
它的“在线验证 secret 是否有效”非常强，但对 yao-doctor-skill 这种离线优先、本地安全审计器来说，不应该默认照搬。  
因为这会引入新的网络边界和额外副作用。  
然而它“先快速筛、再精确判、再分 verified / unverified”的思路，是高度值得借鉴的。

---

## 四、TruffleHog：验证优先的秘密检测体系

### 4.1 项目定位

TruffleHog 的核心价值不只是“找 secret”，而是**尽可能确认这个 secret 是不是真的活的**。  
它的思路比传统纯 regex 扫描更激进，也更实战：  
发现一个看起来像 token 的东西还不够，最好还能验证它是否真实有效、属于哪个 provider、是否还活着。

从官方仓库描述看，它覆盖了大量来源，包括 Git、文件系统、对象存储、聊天、wiki 等，并支持大量 detector。  
但对我们更重要的，不是覆盖面，而是它的三层架构：

1. 快速筛选
2. 类型识别
3. 外部验证

### 4.2 关键实现机制

从其核心实现和配置设计可以看到几个非常重要的点。

#### 4.2.1 关键词预过滤

TruffleHog 在自定义 detector 和大量 provider detector 里都强调 `keywords`。  
这不是一个小优化，而是大规模扫描里极重要的误报控制手段。

它的逻辑不是直接对每段文本跑所有 regex，而是先用关键词触发 detector 的激活，再做后续匹配。  
这意味着：

- 没有 provider 语义线索的文本，不会轻易进入昂贵规则
- 规则之间不会彼此过度打扰
- 性能更稳，噪声也更低

对 `yao-doctor-skill` 的启发非常直接：  
很多高风险规则都不该做“全局裸扫”，而应该有前置信号。  
例如：

- `credentialed-egress` 最好要求 token/credential 线索 + 网络行为，而不是只看任一侧
- `archive-staged-exec` 最好要求 archive + 可疑执行 或 archive + 下载 + 执行，而不是 archive + 任意 subprocess
- `behavior-mismatch` 最好只对真正敏感类别触发，而不是对所有能力行为一视同仁

#### 4.2.2 验证状态分层

TruffleHog 最有代表性的设计之一，是把结果分成：

- verified
- unverified
- unknown

这背后体现的是一个成熟安全工具的重要哲学：  
**结果不是非黑即白，而是有验证强度差异。**

对于 `yao-doctor-skill`，虽然我们不应该默认去联网验证第三方 token，但这个思想非常值得迁移。  
我们完全可以把 skill 安全 finding 的置信度分层，例如：

- `documentation-context`
- `file-wide-correlation`
- `nearby-chain`
- `active-runtime`
- `reviewed-accepted-risk`

也就是把“命中是否真实可疑”从简单的 severity 里拆出来。  
severity 表示后果等级，confidence 表示证据强度。  
这两者不该混用。

#### 4.2.3 多轮解码与解码深度

TruffleHog 的引擎里有 `MaxDecodeDepth`，允许对 chunk 进行多轮迭代解码。  
这个设计非常值得 skill 场景借鉴，因为很多恶意 payload 不会直接以明文出现，而会经过：

- base64
- gzip / zip / tar
- UTF-16 / escaped payload
- 分段拼接

`yao-doctor-skill` 目前已经引入了 `base64 + exec`、`archive unpack + suspicious execution`、`shortlink/paste download` 等规则，但严格说还只是“浅层组合规则”，并不是真正的多轮解码分析。

下一步如果要继续提高对伪装型 skill 的识别能力，就应该从 TruffleHog 学到：

- 不要只匹配明文字符串
- 要承认攻击者会使用分层编码和 staged delivery
- 解码不是单独的 feature，而是 detection pipeline 的一部分

#### 4.2.4 验证重叠保护

TruffleHog 在引擎里有一个很值得注意的保护：当多个 detector 对同一结果发生重叠时，会默认禁用验证，避免错误验证路径带来风险或混淆。  
这其实是在承认一个现实：**多 detector 命中不一定意味着更可靠，反而可能意味着歧义上升。**

对 `yao-doctor-skill` 的启发是：

- 多个规则命中同一文件，不等于危险度线性叠加
- 同一证据不应该被多个类别重复计分
- 对同一个行为，要做去重、聚合、主导类别归并

这一点已经部分体现在 `dedupe_findings` 和类别级聚合打分里，但后续还可以更进一步，例如引入“证据簇”的概念。

### 4.3 值得借鉴的地方

TruffleHog 最值得借鉴的不是 provider 规则库本身，而是下面四点：

- 关键词触发优于全局裸 regex
- 验证强度分层优于单一 severity
- 多轮解码优于只看明文
- 重叠保护优于重复叠分

### 4.4 不适合直接照搬的地方

- 默认联网验证不适合本地 skill 审计器
- provider 级海量 detector 不适合一开始就引入，否则系统复杂度会过高
- 以“secret 是否活着”为核心，不足以解释 skill 的伪装执行、上下文劫持、供应链劫持问题

### 4.5 对 `yao-doctor-skill` 的落地建议

可直接迁移为：

1. 高风险规则引入前置信号 gating
2. 每个 finding 增加 `confidence` 轴
3. 增加“轻量多轮解码”能力，而不做大而全解码器框架
4. 引入“证据簇去重”，避免同一行为被多个规则重复夸大

---

## 五、Gitleaks：规则工程、组合条件与基线治理

### 5.1 项目定位

Gitleaks 是非常典型的高采用度规则型 secret scanner。  
它之所以值得研究，不是因为“规则很多”，而是因为它把规则工程、allowlist、baseline、组合规则做得很成熟。

如果说 TruffleHog 强在“验证”，那么 Gitleaks 强在“规则系统化治理”。

### 5.2 关键实现机制

#### 5.2.1 规则的最小表达单元很清晰

其 `Rule` 结构里包含：

- `RuleID`
- `Description`
- `Entropy`
- `SecretGroup`
- `Regex`
- `Path`
- `Keywords`
- `Allowlists`
- `RequiredRules`

这是一个非常成熟的规则对象模型。  
尤其重要的是：它没有把所有逻辑都塞进一个 regex，而是允许：

- 内容匹配
- 路径匹配
- 熵阈值
- 关键词预触发
- allowlist
- 组合依赖

这说明一个现实：  
**高质量检测几乎从来不是“一个 regex 解决所有问题”，而是多种证据的结构化组合。**

#### 5.2.2 关键词预过滤与路径过滤

在 `detect.go` 中可以看到它对 fragment 先构建 keyword map，再决定哪些规则真正进入扫描。  
同时，规则本身也可以带 path regex。

这对 skill 场景非常有启发：

- 某些行为只有在 `scripts/`、`.github/workflows/`、`agents/` 里出现才应该高权重
- 某些规则在 `references/`、`reports/`、`tests/` 里应该天然降级
- 某些文件名本身就是重要语义，比如 `github_*.py`、`sync_*.sh`、`benchmark_*.py`

也就是说，**路径不是辅助信息，而是主信号之一**。

#### 5.2.3 组合规则与邻近性

Gitleaks 的 `RequiredRules`、`WithinLines`、`WithinColumns` 很关键。  
它允许一个主规则必须与多个辅助规则在一定邻近范围内同时满足，才真正成立。

这个机制对 `yao-doctor-skill` 有极强借鉴意义。  
因为我们面对的最大问题之一，就是“同文件共现”不等于“真实链路”。

例如：

- 文件里同时出现 `os.environ` 和 `requests.post`，但相距 400 行，且属于两个完全独立函数
- 文件里既有 `zipfile.extractall` 又有 `subprocess.run`，但二者不是同一执行链
- 文档里既提到 `base64`，又给了一个 `curl` 示例，但只是教学说明

目前 `yao-doctor-skill` 已经通过 `chain_confidence` 把距离分成：

- local
- nearby
- file-wide

这一步就是沿着 Gitleaks 的组合规则思路走出来的，只是还没有完全结构化为“主规则 + 辅助规则 + 邻近范围”的 rule engine。  
从长期看，这个方向是对的。

#### 5.2.4 Allowlist 与 `.gitleaksignore`

Gitleaks 的 allowlist 机制非常实用，支持：

- commits
- paths
- regexes
- stopwords
- OR / AND match condition

同时它还有 `.gitleaksignore`，允许基于 fingerprint 忽略具体 finding。

对 `yao-doctor-skill` 的启发不是要照搬 `.gitleaksignore` 这个文件名，而是要学它对“误报治理”的态度：

- 忽略不是拍脑袋写死在代码里
- 忽略必须是有指向性的、可审计的
- 忽略最好是针对具体 finding，而不是针对整类规则永久关闭

这直接对应到我们本轮已经加入的 `review-baseline.json`：

- `false-positive`：压制结果
- `accepted-risk`：保留可见，但标注为已审阅

这类机制之所以重要，是因为 skill 审计一定会出现“真实但低等级”和“误报但值得记忆”两类结果。  
如果没有 review baseline，分析师会反复对同一 finding 做重复劳动。

#### 5.2.5 基线不是“隐藏问题”，而是“隔离历史债务”

Gitleaks 的 baseline 逻辑本质上是在说：

- 历史问题先记下来
- 新扫描只关注新增问题
- 已知问题不反复污染主报告

这一思想对 skill 生态尤为关键，因为很多 skill 本身就包含：

- 旧示例
- 已知可接受的工程风险
- 尚未处理但短期不会修的告警

如果每次全量扫描都把它们等同对待，报告会迅速失去“变更感知能力”。  
所以 baseline 的真正价值不是“让结果看起来更干净”，而是让报告重新对增量和新风险敏感。

### 5.3 值得借鉴的地方

- 规则对象化，而不是散落 regex
- 关键词 + 路径 + 熵/条件 联合建模
- required rule 与邻近性
- allowlist 的结构化治理
- baseline 的增量视角

### 5.4 不适合直接照搬的地方

- Secret-centric 的规则库不能直接解释 prompt 注入、隐藏意图、agent 指令篡改
- 纯 finding baseline 无法替代 skill 场景的“用途一致性”判断

### 5.5 对 `yao-doctor-skill` 的落地建议

1. 长期把高价值规则改造成“组合规则”
2. 为高风险类别定义显式主辅条件和邻近范围
3. 审阅基线继续沿 finding 粒度演进，而不是做大范围白名单
4. 后续考虑为 finding 引入稳定 fingerprint

---

## 六、detect-secrets：基线优先、审阅优先、过滤优先

### 6.1 项目定位

detect-secrets 非常适合拿来研究“误报如何被流程化管理”。  
它的重要价值不在于 detector 多先进，而在于它很明确地承认：

- 大仓库里本来就会有历史问题
- 真正可用的工具必须允许团队逐步治理
- 审阅信息本身就是系统资产

### 6.2 关键实现机制

#### 6.2.1 baseline-first 的世界观

detect-secrets 的 README 和核心实现都围绕 `.secrets.baseline` 展开。  
它不是附属功能，而是整个工具工作流的中心：

- `scan` 生成 baseline
- `hook` 用 baseline 忽略旧问题，主要阻断新问题
- `audit` 对 baseline 进行人工标注和统计

这背后的思想非常适合 yao-doctor-skill：

一个 skill 安全审计系统，如果没有“历史已知结论存储层”，就很难长期用起来。  
因为每次都是从零开始解释报告。

#### 6.2.2 审阅结果会回写并保留

在其 `SecretsCollection.merge` 等逻辑里，可以看到它会保留已有审阅状态，例如：

- `is_secret`
- `is_verified`

也就是说，机器扫描和人工判断不是互斥的，而是可以逐步累积的。

对 `yao-doctor-skill` 来说，这直接对应两个设计方向：

1. `review-baseline.json` 不是临时文件，而是持续积累的审计资产
2. 后续可以把 review status 扩展成更丰富的枚举，例如：
   - `false-positive`
   - `accepted-risk`
   - `needs-followup`
   - `fixed-upstream`
   - `blocked-for-use`

#### 6.2.3 inline allowlist / pragma

detect-secrets 允许通过 `pragma: allowlist secret` 等方式做行级豁免。  
这类行级抑制的好处是：

- 它离证据非常近
- 代码评审时可见
- 不会把规则整体关掉
- 对未来维护者有上下文提示

这正是 `yao-doctor-skill:ignore` / `yao-doctor-skill:ignore-nextline` 的思路来源。  
在 skill 场景里，这种机制尤其重要，因为很多文档、示例、fixture 会稳定触发规则，但又不值得每次靠 baseline 去解释。

#### 6.2.4 heuristic filters 是大规模误报治理核心

detect-secrets 的 `filters/heuristic.py` 很值得看。  
它做了很多“看似不起眼、但非常救命”的判断：

- 顺序字符串
- UUID
- 模板变量
- 间接引用
- 非文本文件
- lock file
- swagger 文件

这些判断本质是在问：**这个看起来像 secret 的东西，更像真的 secret，还是更像一个常见误报形状？**

这给 `yao-doctor-skill` 一个非常重要的启示：

对 skill 安全扫描来说，误报治理不能只靠“白名单路径”，还要靠**形状过滤**和**场景过滤**。  
例如：

- Markdown 里的说明性代码块
- Office 文档类 skill 的 OOXML 解压处理
- 官方 API host + allowlist
- 项目生成脚手架里的固定 tarball 解压

这些都可以做成结构化 heuristic，而不是事后人工解释。

#### 6.2.5 audit 是产品能力，不只是工程能力

detect-secrets 的 `audit` 很值得重视。  
它并没有把“人工复核”当成外部补丁，而是把它做成核心产品能力。

这对于 `yao-doctor-skill` 的报告设计非常关键。  
一份真正可用的 skill 安全报告，不应该只是列 finding，而应该支持：

- 为什么它只是 risk，不是 unsafe
- 为什么它是 accepted-risk
- 为什么它是 false-positive
- 哪些 finding 需要再次复核
- 哪些 finding 与历史相比是新增

换句话说，**报告不是终点，而是审阅工作台的一部分**。

### 6.3 值得借鉴的地方

- baseline-first 设计
- 审阅状态持久化
- 行级 allowlist
- heuristic filters
- 把 audit 纳入产品主流程

### 6.4 不适合直接照搬的地方

- 它还是偏 secret detection，不是 skill 行为检测
- 它的 baseline 结构主要围绕 secret 结果，不足以表达用途一致性、上下文置信度、链路解释

### 6.5 对 `yao-doctor-skill` 的落地建议

1. 继续强化 `review-baseline.json` 的 schema
2. 后续加入 review diff，显示“新增 / 已审阅 / 已压制”
3. 把报告页面里的 baseline 解释做得更显眼
4. 为常见 skill 误报模式增加 heuristic filter，而不是只靠 baseline

---

## 七、AgentShield：最接近 skill 场景的上下文感知扫描器

### 7.1 为什么它特别重要

如果说前面三个项目主要是“秘密检测”的参考，那么 AgentShield 是更接近我们问题本体的。  
它的目标不是普通源码，而是 agent 配置、hooks、MCP、skills、prompt surfaces 这类对象。  
因此它面临的噪声结构，与 `yao-doctor-skill` 非常像：

- 文档和模板极多
- 配置与实际实现分离
- 大量 declarative surface
- 误报和“真风险但低置信度”很容易混淆

### 7.2 最有价值的机制：runtime confidence

AgentShield 的一个核心思想，是给 finding 标记 `runtimeConfidence`。  
例如：

- `docs-example`
- `plugin-manifest`
- `project-local-optional`
- `hook-code`

这个设计的意义非常大。  
它不是简单说“这个 finding 危险不危险”，而是在说：

> 这个 finding 出现在什么类型的来源里，因此我们应如何解释它。

也就是说，它把“来源上下文”从隐含信息提升成了显式元数据。

这对 yao-doctor-skill 的意义非常直接：

- 同样的 `curl`，出现在 `scripts/` 和出现在 `README` 里，含义完全不同
- 同样的 “读取路径”，出现在测试 fixture 和出现在运行脚本里，含义完全不同
- 同样的 “hook” 语义，出现在 manifest 和出现在真正 hook code 里，也完全不同

`yao-doctor-skill` 已经引入：

- `source_kind`
- `source_weight`
- `chain_confidence`

这其实已经沿着 AgentShield 的方向走了一步。  
但未来还可以更明确地在报告中把“来源类型”提升为一级解释维度，而不仅仅作为 finding 附属字段。

### 7.3 跨文件上下文解析

AgentShield 的 false-positive audit 文档非常值得研究。  
它多次强调：

- 不要孤立看 settings
- 不要孤立看 hooks manifest
- 要能顺着 manifest 找到实现文件
- 要区分 declarative surface 和 executable implementation

这正是 skill 场景最容易踩坑的地方。  
很多危险行为不是直接写在 `SKILL.md` 里，而是在：

- `hooks/hooks.json`
- `.claude/settings.json`
- `manifest`
- `workflow`
- 远程下载脚本

之间跳转完成的。

这意味着，真正靠谱的 skill 扫描器不能只做逐文件规则匹配，还要做**跨文件关联**。

`yao-doctor-skill` 当前已经开始做的，是：

- frontmatter / 目的说明 与 finding 之间的用途一致性判断
- trusted API host guard 检测
- source/sink 的局部链路置信度

下一步真正该补的是：

- manifest -> script 的解析
- workflow -> referenced file 的解析
- downloaded artifact -> subsequent execution 的跨语句甚至跨文件关联

### 7.4 误报审计文档本身就是重要资产

AgentShield 的 `false-positive-audit.md` 非常值得借鉴。  
它不是一个内部临时笔记，而是结构化记录：

- 哪类误报出现过
- 哪些是规则 bug
- 哪些只是需要重分类
- 哪些是“真实存在，但不该打这么高”

这类文档的价值在于，它让扫描器迭代不再是“感觉更准了”，而是：

- 有证据
- 有案例
- 有回归原则
- 有未来迭代边界

对 `yao-doctor-skill` 来说，这意味着：

- 研究文档和误报审计文档都应该进仓库
- 不应该只保留代码变更，而把“为什么这么改”丢在聊天记录里

### 7.5 值得借鉴的地方

- runtime confidence
- declarative vs executable distinction
- cross-file context
- 误报审计文档化
- 降级而不是直接 suppress 的思路

### 7.6 不适合直接照搬的地方

- 它主要围绕 Claude/agent config 场景，skill 目录结构与 OpenClaw skill 不完全一致
- 某些规则强依赖其自身目标生态的文件命名约定

### 7.7 对 `yao-doctor-skill` 的落地建议

1. 把 source context 从内部打分字段提升成报告一级解释轴
2. 引入跨文件解析，特别是 manifest / workflow / downloaded artifact 的后续执行链
3. 建立自己的 `false-positive-audit.md`
4. 对“真实但低等级”的 finding，优先重分类、降权，而不是直接压制

---

## 八、GitHub Agentic Workflows Threat Detection：把威胁检测嵌进执行架构

### 8.1 为什么它值得看

GitHub Agentic Workflows 的 threat detection 和前三类扫描器不同。  
它不是一个离线扫描工具，而是把 threat detection 设计成 agent 工作流中的一个独立安全层。

它最大的启发不是具体规则，而是架构思路：

- agent 先在只读权限环境里产出 output / patch
- threat detection job 对产物做分析
- 只有通过后，safe outputs 才会真正写 Issue / PR / Comment

这意味着它不是“扫描一次文件”，而是在**执行边界上设卡**。

### 8.2 关键机制

#### 8.2.1 safe outputs 与 threat detection 解耦

文档明确指出：

- 主 agent job 产生输出
- threat detection 分析 agent output 与 patch
- safe output jobs 只有在 threat detection 通过时才执行

这个模式非常值得 `yao-doctor-skill` 借鉴。  
即使 `yao-doctor-skill` 本身当前是离线审计 skill，也应该在理念上吸收这一点：

> 检测不仅要扫描“代码长什么样”，还要扫描“它将要做什么结果”。

对 skill 场景来说，后续可以延伸成：

- 扫描 skill 代码
- 扫描 skill 生成的补丁/命令计划
- 扫描 skill 要写入的关键文件

#### 8.2.2 protected files

官方文档的 protected files 设计非常关键。  
它明确把下面几类文件视为供应链高敏感面：

- dependency manifests
- CI/CD config
- agent instruction files

一旦 patch 触碰这些文件，就直接走保护逻辑。

这个机制对 `yao-doctor-skill` 有非常直接的启发：

在 skill 生态里，也存在一组“高杠杆文件”，例如：

- `SKILL.md`
- `agents/interface.yaml`
- `manifest.json`
- `.github/workflows/*`
- `requirements*.txt`
- `package.json`
- `pnpm-lock.yaml`
- `pyproject.toml`
- `.claude/*`
- `.agents/*`
- hooks manifest / automation config

对这些文件的修改，尤其是联网 skill 或自更新 skill 的修改，危险度应该天然更高。  
因为它们会影响后续执行边界、依赖边界、指令边界。

#### 8.2.3 自定义 pre/post steps

GitHub Agentic Workflows 允许在 threat detection 前后接入自定义步骤，比如：

- Semgrep
- TruffleHog
- LlamaGuard

这意味着一个成熟系统不应该幻想“一个模型/一个规则引擎解决所有安全问题”，而应该接受：

- 有些规则擅长结构静态分析
- 有些规则擅长 secret 检测
- 有些模型擅长语义判断
- 它们应该是层叠，而不是互斥

这对 `yao-doctor-skill` 的启发是：

- 后续完全可以把 scanner 设计成 pipeline
- 规则引擎、上下文分析、review baseline、甚至小模型语义分类，都可以是独立阶段

#### 8.2.4 fail-safe

文档强调：如果 threat detection 自己失败，也要阻断 safe outputs。  
这体现了一个非常重要的安全工程原则：

> 安全检测失败时，不应默认放行。

对于 `yao-doctor-skill` 而言，这个原则可以转译成：

- baseline 文件损坏时，不能静默忽略
- 关键解析失败时，应该保守标注“需要人工复核”
- report 生成失败时，不应该伪装成扫描通过

### 8.3 值得借鉴的地方

- 威胁检测应嵌入执行边界，而不只是离线报告
- protected files 思维非常适合 skill 供应链场景
- 多阶段安全 pipeline
- fail-safe 原则

### 8.4 对 `yao-doctor-skill` 的落地建议

1. 增加 `protected-surface` 或 `governance-surface` 类别
2. 对触碰关键文件的联网/下载/执行行为提高权重
3. 后续如果 yao-doctor-skill 接入自动化执行链，必须先审再写
4. 把“检测失败”显式显示在报告概览里

---

## 九、《Malicious Or Not》：仓库上下文决定误报率

### 9.1 这篇论文为什么关键

这篇论文最重要的价值，不是告诉我们“恶意 skill 很多”或者“很少”，而是指出一个根本问题：

> 只看 skill 描述做分类，会严重高估恶意率；  
> 把 skill 放回它所在的 GitHub 仓库语境中，误报会大幅下降。

论文摘要中直接提到：

- 早期 scanner 在一些市场里能把高达 46.8% 的 skill 标成 malicious
- 当作者收集 238,180 个 unique skills，并纳入仓库上下文后，非 benign 比例降到 0.52%
- 论文还指出了被废弃 GitHub 仓库劫持这类真实攻击向量

这几个结论对我们非常重要。

### 9.2 核心启示一：skill 不能脱离仓库语境判断

一个 skill 的 `SKILL.md` 写了：

- benchmark scan
- sync docs
- release helper
- migration support

如果你只看这几行文字，再配上少量命令、API、文件访问，很容易过度告警。  
但如果你把它放回完整仓库里看，可能会发现：

- 整个仓库就是在做 GitHub benchmark
- 整个仓库到处都是同类集成脚本
- 它的网络访问全部指向官方 API
- 它的命名、路径、周边文档、测试、依赖都支持这个用途

这时，风险仍然存在，但“恶意窃取”的概率就会显著下降。

### 9.3 核心启示二：真正危险的不只是 skill 内容，还包括宿主仓库命运

论文摘要特别提到 abandoned GitHub repositories 被劫持。  
这说明一件事：

skill 风险不只是“现在这份代码在干嘛”，还包括：

- 这个 skill 来自什么仓库
- 仓库是否长期无人维护
- 仓库是否可能被转手、被接管、被植入恶意更新
- skill 的下载/安装/更新链是否可控

这对 `yao-doctor-skill` 的长期路线很关键。  
如果以后要做更强的安全审计，不能只看本地目录里的快照，还应考虑：

- 源仓库 provenance
- 最近 commit 活跃度
- 默认分支是否突然发生异常变更
- 发布者与历史维护者是否一致

### 9.4 核心启示三：用途一致性比“危险关键词”更重要

这篇论文与我们的经验判断非常一致：  
大量误报来自“扫描器把能力面和行为面混了”。

因此 skill 检测里最有价值的信号之一是：

- **purpose congruence**

也就是：

- skill 的 name / description / 仓库主题 / 邻近文件 / 目录结构
- 是否真的支撑它现在做的这些敏感行为

这也是 `behavior-mismatch` 类别存在的理由。  
它不是说“一不一致就是恶意”，而是说：

> 如果一个 skill 声称自己只是做标题生成、笔记清理、排版整理，却同时出现了 credentialed egress、remote exec、sensitive-source，那么至少应该被强制人工审阅。

### 9.5 论文对 `yao-doctor-skill` 的直接指导

这篇论文告诉我们，未来 `yao-doctor-skill` 的真正升级方向不是“再加 200 条关键词规则”，而是：

1. 做 repo-context aware scanning
2. 做 purpose congruence
3. 做 provenance / repository health
4. 做恶意宿主仓库劫持检测

也就是说，**要把单文件静态检测，升级成“skill + repo + surrounding assets”的组合判断。**

---

## 十、跨项目综合：真正有效的 skill 安全检测应遵循什么原则

把前面六类研究对象放在一起，会出现几个非常稳定的共同规律。

### 10.1 原则一：来源上下文优先于字符串

同样一段文本：

- 在 `scripts/` 中
- 在 `.github/workflows/` 中
- 在 `README.md` 中
- 在 `tests/fixtures/` 中

语义完全不同。

如果扫描器不区分来源上下文，误报率一定高。  
AgentShield 最清楚地把这点产品化了；Gitleaks 和 detect-secrets 则从 path、allowlist、heuristic 角度间接体现了这一点。

### 10.2 原则二：链路优先于单点

真正危险的 skill 往往不是某一个 API 调用，而是链路：

- 敏感源
- 转换/混淆/打包
- 外传 / 执行 / 持久化

Gitleaks 的 required rules、TruffleHog 的解码/验证流程、GitHub threat detection 的 patch + safe outputs 分层，都在说明一件事：  
**单点命中不如闭环链路。**

### 10.3 原则三：真实世界里的误报治理必须被产品化

误报不可能被彻底消灭。  
所以一个可长期使用的系统必须具备：

- inline ignore
- baseline
- reviewed state
- confidence labeling
- false-positive audit docs

detect-secrets 和 AgentShield 在这方面最值得学。

### 10.4 原则四：trusted integration 与 arbitrary exfiltration 必须拆开

`GITHUB_TOKEN + api.github.com`  
和  
`token + webhook / mail / paste site`

不是一回事。

如果扫描器不拆开这两类，会同时犯两种错：

- 把正常集成打得过重
- 把真正任意外传的行为稀释掉

`yao-doctor-skill` 当前引入：

- `credentialed-egress`
- `bounded-credentialed-egress`
- `source-sink-chain`

就是沿着这条原则做的。

### 10.5 原则五：用途一致性和仓库语境会显著降低误报

《Malicious Or Not》已经从大规模数据上证明了这一点。  
在 skill 场景里，这一点比普通源码分析更重要，因为 skill 天然带有“自然语言说明层”。

### 10.6 原则六：安全边界文件比普通文件更值得重点关注

GitHub Agentic Workflows 的 protected files 思路非常关键。  
在 skill 生态中，真正高杠杆的文件包括：

- 指令入口
- workflow
- dependency manifests
- automation config
- hooks
- governance manifest

它们被篡改的后果，远大于普通业务脚本。

---

## 十一、对 `yao-doctor-skill` 的算法改进映射

### 11.1 已经落地的关键收紧点

结合这轮研究，`yao-doctor-skill` 已经落地或强化了以下机制：

1. `source_kind` / `source_weight`
   - 区分 executable code、workflow、manifest、docs-example、tests-fixture、generated-artifact

2. `chain_confidence`
   - 区分 local / nearby / file-wide
   - 不再把大文件中的弱共现当成强闭环

3. `credentialed-egress` 与 `bounded-credentialed-egress`
   - 官方 API + host guard 与任意外传拆开

4. `behavior-mismatch`
   - 用途不一致时再加审阅信号

5. `yao-doctor-skill:ignore` / `yao-doctor-skill:ignore-nextline`
   - 显式、可审计、就地抑制

6. `review-baseline.json`
   - 误报和已接受风险可以持久化

7. 新增 obfuscation 规则
   - `obfuscated-exec`
   - `archive-staged-exec`
   - `shortlink-download`

8. 文档上下文与 archive-staged-exec 进一步收紧
   - 非 `SKILL.md` 的 Markdown 默认视为文档上下文
   - `archive-staged-exec` 从“解压 + 任意执行”收紧为“解压 + 可疑解释器执行”或“解压 + 下载 + 执行”

### 11.2 为什么这些改动方向是对的

这些改动共同指向一个目标：

> 让扫描器越来越像一个“证据评估器”，而不是“危险关键词播报器”。

也就是：

- 先判断这是哪类来源
- 再判断它具有什么能力
- 再判断是否形成不安全行为证据
- 再判断链路强度
- 再考虑用途一致性
- 最后允许历史审阅结论接管重复劳动

### 11.3 当前仍然存在的短板

即便这轮收紧之后，`yao-doctor-skill` 仍然有几类明显短板：

#### 11.3.1 还不是 AST / 语义级数据流分析

现在多数规则仍然基于文件内容和局部邻近关系。  
这已经比裸 regex 强很多，但还不是真正的 taint analysis。

因此它还不能稳定判断：

- 某个 token 变量是否真的流入某个请求 body
- 某个下载内容是否真的被随后执行
- 某个 archive 解出的文件是否真的被 interpreter 调用

#### 11.3.2 跨文件解析能力仍弱

目前对 workflow、manifest、downloaded artifact 的串联能力还很有限。  
真正恶意 skill 往往会把危险动作拆到多个文件里，这一点后续必须补。

#### 11.3.3 缺乏仓库 provenance / 健康度信号

这使得它还无法识别：

- 被废弃仓库劫持
- 长期无人维护但近期突然活跃
- 技术栈与 skill 行为完全不匹配的异常仓库

#### 11.3.4 混淆检测还比较浅

当前的 `base64 + exec`、`archive + suspicious exec`、`shortlink download` 只能覆盖一部分显眼模式。  
后续还应扩展到：

- 分段拼接执行
- `exec(base64.b64decode(...).decode())`
- shell variable 拼接
- 动态下载后写临时文件再执行
- GitHub raw / gist / paste site / temporary host 轮换

---

## 十二、下一阶段最值得做的算法路线图

### 12.1 P0：继续稳住误报和可解释性

这是最现实、最该优先做的层。

建议包括：

1. 为 finding 引入稳定 fingerprint
2. 在报告里高亮“新增 finding / 基线已审阅 finding”
3. 增加 `confidence` 字段，而不是只依赖 severity
4. 补一份 `false-positive-audit.md`
5. 对更多常见工程模式做 heuristic 收口

这是让工具能长期被信任的基础设施。

### 12.2 P1：补 repo-context aware scanning

这是从《Malicious Or Not》直接得到的下一步重点。

建议包括：

1. 读取仓库级 README、目录主题、顶层依赖文件、脚本聚类
2. 建立“仓库主用途画像”
3. 把 skill 用途与仓库画像做对比
4. 当 skill 行为与仓库主题严重背离时，提高 `behavior-mismatch` 权重

例如：

- 一个仓库几乎全是文档和排版脚本，却突然出现 credentialed egress + remote install + hidden instructions
- 一个仓库明确是 GitHub benchmark 或 API integration 工具集，那么其官方 API 调用就应被解释为有边界产品行为

### 12.3 P2：补 protected surface 模型

借鉴 GitHub threat detection 的 `protected files` 思路。

建议把以下内容列为高杠杆面：

- `SKILL.md`
- `agents/interface.yaml`
- `manifest.json`
- `.github/workflows/*`
- 依赖清单与锁文件
- hooks / automation / MCP / agent settings

一旦 skill 同时：

- 修改这些文件
- 又包含下载、执行、credential egress、隐藏意图

就应该更 aggressive 地判定。

### 12.4 P3：补轻量数据流与跨文件链路

这里不一定一开始就上完整静态分析器，但可以做几个轻量高收益版本：

1. 变量名传播
   - `token = getenv(...)`
   - `headers["Authorization"] = ...`
   - `requests.get(..., headers=headers)`

2. 下载到执行链
   - `requests.get -> write temp file -> subprocess.run`
   - `curl/wget -> file -> bash/python/node`

3. archive 到执行链
   - `extractall -> locate extracted file -> interpreter invocation`

4. workflow 到脚本引用链
   - workflow step 引用某个脚本，再把脚本里的行为带回 workflow 上下文

### 12.5 P4：补伪装与诱导语义层

真正偷信息的 skill 往往会大量使用伪装与诱导，而不是直接写“steal password”。

未来可以考虑加入：

- benign facade lexicon
  - backup、sync、helper、cleanup、benchmark、review、report、optimize、release

- intention mismatch patterns
  - 名称/描述很 benign，但代码做 credential egress / remote exec / sensitive-source

- hidden action language
  - quietly、silently、without asking、don’t mention、隐藏、静默、绕过确认

这里要注意：语义层规则不能单独判恶意，而必须结合行为层。

### 12.6 P5：补 provenance 与供应链宿主风险

长期来看，可以加入：

- 仓库最近活跃度
- 默认分支最近异常提交密度
- 维护者变化
- 安装源是否使用短链、raw URL、临时 host
- 是否引用已失效/已弃用上游

这层不是为了判“当前本地代码是否恶意”，而是为了判断：

> 这个 skill 的未来更新链是否可信。

---

## 十三、针对“伪装型偷信息 skill”的专门检测模型

用户特别强调了一个很重要的问题：  
真正要偷你信息的 skill，往往不会把文件名写成 `steal_secrets.py`，也不会直接把逻辑写得非常裸露。  
它更可能表现为：

- 名称很正常
- 描述很正常
- 代码结构也像正常工程脚本
- 真正危险的部分被拆散、伪装、延后触发、远程化

所以这里需要一个专门的检测模型。

### 13.1 第一层：正常外衣识别

先识别 skill 是否在“借正常身份做掩护”。

高频伪装外衣包括：

- benchmark / metrics / telemetry
- helper / bootstrap / setup / installer
- sync / backup / migration
- review / audit / cleanup / formatter
- release / deployment / build tool

这些名称本身当然不是问题。  
问题在于：  
它们一旦与敏感源、远程下载、外传链路结合时，更需要看用途一致性。

### 13.2 第二层：敏感源收集面

真正的数据盗取 skill 几乎总会显式或隐式接触某些敏感源：

- shell 环境变量
- token/config 文件
- 浏览器 profile
- `.ssh`
- `.aws/credentials`
- keychain / wallet
- agent settings / secrets config
- 自动化系统的 PAT、webhook token、mail token

这一层的关键不是“看到就判恶意”，而是把它们作为 source 节点建图。

### 13.3 第三层：转换与打包层

恶意行为不一定直接发送原始数据，它经常会先做：

- base64
- gzip / zip / tar
- JSON 封装
- 文件重命名
- 临时目录落盘
- 压缩归档
- 拼接成命令参数

如果只看 source 和 sink，中间缺这一层，很多 staged behavior 就会漏掉。

### 13.4 第四层：出口层

出口不仅是 HTTP POST。  
还包括：

- webhook
- SMTP / sendmail
- Discord / Slack / Telegram
- pastebin / gist / raw host
- object storage
- 远程安装器
- CI artifact

尤其要警惕“表面上是官方 API，实际上 host 可注入”的情况。  
所以：

- 官方 API 常量 host
- 官方 API + allowlist guard
- 任意 host 拼接

必须是三个不同等级。

### 13.5 第五层：伪装与抑制层

恶意 skill 常见的一组配套行为是：

- 不告诉用户
- 静默发送
- 隐藏步骤
- 绕过确认
- 把真正动作塞进例外分支或 fallback
- 用 benchmark、health check、diagnostic 之类理由包装外发

这一层单独看不一定成立，但只要与 source/sink 联动，就应显著加权。

### 13.6 第六层：远程化层

很多 skill 不会把恶意逻辑直接提交进仓库，而是：

- 下载远程脚本
- 拉取压缩包
- 从 paste 站、raw URL、gist、临时 host 获取 payload
- 读取远程 prompt / config / instruction

这层非常关键，因为它使得本地静态快照看起来很干净。  
所以对 skill 场景来说，“远程载荷入口”是必须重点盯的。

### 13.7 第七层：后续持久化层

更高级的恶意 skill 不只是偷一次，而是会试图留下后门：

- cron
- LaunchAgents
- hooks
- workflow patch
- dependency manifest 污染
- agent instruction 文件篡改

这类行为一旦与外发、远程下载结合，就不是普通风险，而是供应链级问题。

### 13.8 结论

所以，对伪装型 skill 的检测，本质上不是“搜恶意词”，而是构建下面这张证据图：

**正常外衣 -> 敏感源 -> 转换/打包 -> 出口 -> 伪装抑制 -> 远程化 -> 持久化**

只要其中闭合的层数越多，越接近真实恶意。

---

## 十四、报告与产品层面的建议

算法再好，如果报告不会解释，用户还是会不信。

### 14.1 不要只给总分

必须同时显示：

- capability risk
- unsafe behavior
- source context
- chain confidence
- baseline review status

否则用户很容易把“高能力面”误读成“高恶意”。

### 14.2 每个 finding 必须回答五个问题

1. 它发生在哪个文件、哪一行
2. 它属于哪一类来源上下文
3. 它为什么只是 risk，还是已经 unsafe
4. 它证据强度如何
5. 它是否已被人工审阅

### 14.3 报告模块建议

当前可视化报告已经做了不错的基础层，但后续还可以继续加强：

- 单独的“已审阅基线”模块
- 单独的“高杠杆面变更”模块
- 单独的“source-to-sink 链路”模块
- 单独的“可疑伪装模式”模块

### 14.4 面向 GitHub 同步的文档要求

既然这份研究文档后续可能同步到 GitHub，那么它必须具备：

- 明确的数据日期
- 明确的研究范围
- 明确的来源链接
- 明确的“已实现 / 未实现 / 下一步”

否则它会沦为一次性的调研笔记，而不是项目资产。

---

## 十五、结论

如果只用一句话概括这轮研究的结论，那就是：

> skill 安全检测的核心，不是扩大危险关键词库，而是把“来源上下文、用途一致性、敏感链路、审阅记忆、仓库语境”系统地引入判断。

具体来说：

- TruffleHog 教会我们：验证强度、解码链和关键词 gating 很重要
- Gitleaks 教会我们：规则对象化、组合条件、allowlist 和 baseline 很重要
- detect-secrets 教会我们：审阅状态和误报治理必须成为产品核心能力
- AgentShield 教会我们：runtime confidence、source context 和跨文件上下文是 skill 场景的关键
- GitHub Agentic Workflows 教会我们：安全检测应该被嵌入执行边界，关键文件需要受保护
- 《Malicious Or Not》教会我们：仓库语境和用途一致性会显著降低误报，并揭示“被劫持宿主仓库”这种传统静态扫描看不到的真实风险

对 `yao-doctor-skill` 而言，这意味着正确路线已经非常清楚：

1. 继续沿“risk / unsafe 双轴”走，不回退到权限恐吓式扫描
2. 继续加强 source context、chain confidence、review baseline
3. 把 obfuscation、protected surface、repo context、cross-file linkage 做成下一阶段重点
4. 把研究文档、误报审计、baseline 一起视为扫描器的一部分，而不是外围材料

真正成熟的 skill 安全系统，最终应该像一个“证据编排器”，而不是一个“危险词高亮器”。

---

## 十六、参考来源

### 官方仓库与文档

- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [AgentShield](https://github.com/affaan-m/agentshield)
- [GitHub Agentic Workflows Threat Detection](https://github.github.com/gh-aw/reference/threat-detection/)

### 论文

- [Malicious Or Not: Adding Repository Context to Agent Skill Classification](https://arxiv.org/abs/2603.16572)

### 本仓库内相关输出

- [open-source-reference-scan.md](open-source-reference-scan.md)
- [solution-architecture.md](solution-architecture.md)

---

## 十七、附：建议纳入后续实现 backlog 的条目

为了避免这份研究文档停留在“看过”，这里把可执行 backlog 单独列出来：

1. 为 finding 增加稳定 fingerprint，并让 baseline 基于 fingerprint 优先匹配
2. 增加 `false-positive-audit.md`，把误报归因写成结构化案例
3. 增加 `confidence` 轴，并在报告中可视化
4. 增加 `protected-surface` 检测
5. 增加 repo-context profiling
6. 增加 workflow -> script / manifest -> implementation 的跨文件解析
7. 增加轻量数据流跟踪
8. 扩展 obfuscation 检测到分段拼接、临时文件落盘执行、raw/gist/paste 变体
9. 报告中增加新增 finding 与历史 finding 对比
10. 对已审阅 finding 支持更多状态，而不只有 `false-positive` 和 `accepted-risk`

如果这些条目持续推进，`yao-doctor-skill` 会逐步从“一个更聪明的静态规则扫描器”，进化成“一个真正适合 skill 生态的安全评估器”。
