# 发布到 GitHub 的三种方式

任选一种。推荐 **方式 B（GitHub Desktop）**，图形界面、不用记命令、以后改代码也方便。

---

## 方式 A：网页拖拽上传（不装任何软件，最快）

适合：只想先把代码放上去，短期不打算频繁改动。

1. 打开你刚建的空仓库页面
2. 点 **`uploading an existing file`** 链接（或地址栏后加 `/upload/main`）
3. **把整个 `burp-idor-watcher` 文件夹拖进浏览器**
   - 文件夹里的结构会被保留
   - ⚠️ **先删掉 `lib/`、`out/`、`dist/` 三个目录再拖**（`lib/montoya-api.jar` 是 PortSwigger 的东西，不要上传）
4. 底部 Commit changes 填 `feat: initial release v0.1.0`
5. 点 **Commit changes**

缺点：以后每次改文件都要重复拖拽，且看不到 diff。

---

## 方式 B：GitHub Desktop（推荐）

### 1. 安装

下载：https://desktop.github.com/

安装后用 GitHub 账号登录。

### 2. 把仓库克隆到本地

- 菜单 `File` → `Clone repository`
- 选中你刚建的那个仓库 → 选择本地路径（例如 `D:\code`）→ `Clone`

### 3. 把文件复制进去

把 `burp-idor-watcher` 目录下的**所有内容**（不含 `lib/`、`out/`、`dist/`）复制到克隆下来的仓库文件夹里。

最终本地目录应该是：

```
你的仓库文件夹/
├── src/IdorWatcher.java
├── scripts/extract-montoya-api.sh
├── scripts/extract-montoya-api.ps1
├── samples/sample-output.csv
├── build.sh
├── build.ps1
├── README.md
├── LICENSE
├── CHANGELOG.md
└── .gitignore
```

### 4. 提交并推送

- 左侧会列出所有新文件
- 左下角 Summary 填 `feat: initial release v0.1.0`
- 点 **`Commit to main`**
- 点顶部的 **`Push origin`**

刷新网页就能看到了。

---

## 方式 C：命令行（最标准）

### 1. 安装 Git for Windows

https://git-scm.com/download/win

安装时保持默认即可（会附带 Git Bash）。

### 2. 配置身份（只需一次）

```bash
git config --global user.name "你的名字"
git config --global user.email "你的邮箱@example.com"
```

### 3. 初始化并推送

```bash
cd /d/code/burp-idor-watcher

git init
git add .
git commit -m "feat: initial release v0.1.0"
git branch -M main
git remote add origin https://github.com/你的用户名/你的仓库名.git
git push -u origin main
```

> 首次 push 会弹出浏览器让你授权 GitHub 登录，按提示走完即可。

---

## 推送之后：让仓库"看起来像个项目"

这一步比代码本身更能影响别人对你的判断，别跳过。

### 1. 填 About（右上角齿轮）

**Description**（一句话说清是什么）：

```
Burp Suite 被动式越权（IDOR）检测插件：自动归集同路径不同资源 ID 的请求，支持双身份重放对照。
```

（若要英文版，可写 `Passive IDOR watcher for Burp Suite with dual-identity replay.`）

**Topics**（决定别人能不能搜到你，最多 20 个）：

```
burp-extensions  burp-suite  montoya-api  idor  broken-access-control
security-tools  web-security  penetration-testing  java
```

### 2. 检查 README 渲染

打开仓库首页，确认：

- 顶部徽章正常显示（蓝色 MIT / 橙色 java / 紫色 Burp）
- 代码块有语法高亮
- 表格正常渲染

### 3. Release（可选但很加分）

- 右侧 `Releases` → `Create a new release`
- Tag 填 `v0.1.0`
- 标题填 `v0.1.0 首个可用版本`
- 把 `dist/idor-watcher.jar` **作为附件上传**（这样别人不用自己编译就能直接用）
- 描述里贴 CHANGELOG 的要点

### 4. Pin 到个人主页

- 你的主页 → `Customize your pins` → 勾选这个仓库
- 这样别人点进你主页第一眼就能看到

---

## 千万不要上传的东西

| 文件 | 原因 |
|---|---|
| `lib/montoya-api.jar` | PortSwigger 的 API 包，不是你的代码，且版权归属他们；README 已说明如何自行抽取 |
| `burpsuite.jar` | Burp 本体，商业软件，绝对不能传 |
| `out/` `dist/` 里的 class | 构建产物；如果要发 jar，走 Release 附件，不要进仓库 |
| 任何测试目标的真实数据 | 域名、IP、Cookie、账号、业务数据，一律脱敏 |

`.gitignore` 已经帮你挡掉了大部分，但 `git add` 前还是自己看一眼 `git status`。

---

## 常见问题

**Q：推送时报 `Authentication failed`？**
A：GitHub 从 2021 年起不再支持账号密码。用 GitHub Desktop / 浏览器授权 / Personal Access Token 三种方式之一。最省事是用 GitHub Desktop。

**Q：我想改 README 但不想用命令行？**
A：在仓库网页上点 README 右上角的铅笔图标，直接在浏览器里编辑并提交。

**Q：以后加新功能怎么提交？**
A：
```bash
git add .
git commit -m "feat: 支持响应体归一化"
git push
```
提交信息建议用 `feat:` / `fix:` / `docs:` 前缀，看起来专业很多。

**Q：别人提 Issue 我该怎么回？**
A：先确认问题能否复现；能复现就修完在 Issue 里回一句"已在 vX.X 修复"并关联 commit。开放、及时的回复记录本身就是加分项。
