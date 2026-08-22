[![CI](https://github.com/mokuyoaxis/agent-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/mokuyoaxis/agent-guard/actions/workflows/ci.yml)

# agent-guard

**让 AI Agent 的破坏性操作默认可逆。**
**[English](README.md)**

Agent 正在越来越多地自主执行 shell 命令。当命令是 `rm -rf` 时,一个错误的变量、
一次误判的上下文,就足以让整个仓库灰飞烟灭。agent-guard 让破坏*默认可逆*、
*全程留痕*,并且可以接入任何能跑 Python 的 harness。

> **Agent Guard 不是审批系统,而是带人工升级的自动恢复系统。**
> 只要操作保持可逆,Agent 就不被打断;只有当 Guard 无法安全代办、
> 而用户意图又可能合理时,决策才升级给人类。
>
> 它是可靠性基础设施,**不是安全沙箱**:它防的是判断失误与上下文错误,
> 不是拥有相同 OS 权限的恶意 Agent。

## 四根支柱

| 支柱 | 保证 |
|---|---|
| **Scope(边界)** | Workspace 边界、`.git` 与外部路径永不可删 |
| **Recoverability(可恢复)** | 删除先迁移到 `.agent-trash/` 并记录 manifest;git 覆写先做快照 |
| **Authorization(授权)** | 会话级能力;否决即单向降权,只有人类能恢复 |
| **Auditability(审计)** | 每个判决、每次补偿与恢复都落入追加式 JSONL |

贯穿四者的一条原则:**不确定性提升限制**(fail-closed)。

## 决策协议

稳定的跨 harness 接口不是 allow/block,而是一套 Decision Protocol:

```
效果 → 分类器 → 策略 → Decision   ∈ { ALLOW, RELOCATE, SNAPSHOT,
                                     ASK, BLOCK }
                           + ReasonCode   (稳定机器码)
                           + Explanation  (面向人类的解释)
                           + RecoveryPlan (txid 与补偿策略)
```

| 层级 | 判决 | Agent 的体验 |
|---|---|---|
| **SAFE** | `ALLOW` · `RELOCATE` · `SNAPSHOT` | 静默执行;补偿先行;凭 txid 可恢复 |
| **AMBIGUOUS** | `ASK` | 单次执行授权(`ASK_ONCE`)——例如 Guard 无法安全代办的复合形态 |
| **FORBIDDEN** | `BLOCK` | 附理由与修正建议拒绝;永不升级为询问 |

真正的效果不确定(`$VAR` 目标、`bash -c`、`find -delete`、管道喂入列表)
一律走 BLOCK:放行它们等于放弃核心保证。各适配器把判决映射到原生机制——
DSH 的 `PreToolDecision`、Claude Code PreToolUse 的 `ask`,不支持询问的
harness 则降级为"携带解释的拒绝"。

## 快速开始

零第三方依赖。要求:Python 3.9+、POSIX shell、git。

```bash
# 删除文件/目录/glob —— 进入隔离区而非销毁:
python3 skills/delete-guard/scripts/safe_delete.py build/ --reason "stale"

# 查看状态与恢复:
python3 skills/delete-guard/scripts/status.py
python3 skills/delete-guard/scripts/restore.py list
python3 skills/delete-guard/scripts/restore.py <txid>

# 隔离区维护(默认只出计划,不动数据):
python3 skills/delete-guard/scripts/gc.py
```

harness 适配——在任何 shell 命令执行前拦截:

```bash
python3 skills/delete-guard/scripts/check.py --enforce -- "$COMMAND"
case $? in 0) 执行 "$COMMAND" ;; 2) 拒绝 ;; 3) 交由用户决定 ;; esac
```

## 受保护行为一览

```text
rm -rf build/            → RELOCATE  (整树隔离后放行)
rm -rf .                 → BLOCK     (workspace 根)
rm -rf $DIR/             → BLOCK     (目标无法解析:fail-closed)
rm *.log                 → BLOCK     (不透明通配;safe_delete 会显式展开)
cd X && rm -rf build     → ASK_ONCE  (COMPOUND_CWD_DELETE)
touch f && rm f          → ASK_ONCE  (COMPOUND_CREATE_DELETE)
git clean -fd            → RELOCATE  (先 -n 枚举迁移再放行)
git reset --hard         → SNAPSHOT  (先 stash,可 apply 找回)
git push --force         → BLOCK     (远端历史不交给 Agent 自动处理)
node_modules/(已 ignore) → ALLOW     (可证明可再生)
隔离区写满               → BLOCK     (绝不回退到永久删除)
```

## 适配器

| Harness | 状态 | 机制 |
|---|---|---|
| **DSH**(DeepSeek Harness) | 已上线,真实会话久经考验 | `tools/pre-execute` 瀑布 + 模型工具 + 提示层 |
| **Claude Code** | 就绪(`adapters/claude/`) | PreToolUse hook → `permissionDecision` allow/ask/deny |
| OpenCode / MCP | 规划中 | 待一致性保证在两个适配器上验证后再扩 |

跨 harness 保证(由 `tests/test_conformance.py` 强制):同一命令、同一 cwd、
同一 workspace 状态,经任何适配器必须产出完全一致的 decision + reason code。

## 目录结构

```
agent-guard/
├── skills/delete-guard/   # Agent 行为层:SKILL.md + CLI 脚本
├── core/                  # classifier · policy · recovery · audit
├── adapters/claude/       # Claude Code PreToolUse hook 适配器
├── tests/                 # unittest 测试套件,含跨 harness 一致性
└── docs/                  # architecture · threat-model · friction log
```

Skill 负责 Agent 行为引导,约束全部下沉 Core。未来的 `git-guard`、
`database-guard`、`cloud-guard` 直接挂同一补偿引擎,无需重构仓库。

## 文档

| 阅读 | 内容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 四柱↔组件映射、数据流、关键设计决定 |
| [docs/threat-model.md](docs/threat-model.md) | 诚实边界:它是什么、不是什么 |
| [docs/friction.md](docs/friction.md) | 真实 Agent 撞出来的教训(F1–F8) |
| [skills/delete-guard/references/policy.md](skills/delete-guard/references/policy.md) | 完整规则表与判决码 |

## 状态与路线图

V1 加固完成;`v0.1.0` 发布门槛:CI(本仓库)、保留期政策文档化、
Claude 适配器一致性全绿。下一步:第二个适配器真机验证、保留期自动化、
Windows 方言(需求驱动),然后在同一补偿引擎上扩展 `database-guard`
与 `cloud-guard`。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
