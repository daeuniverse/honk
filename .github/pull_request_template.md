<!--
AI may help you write this; unverified content may not be submitted.
可以用 AI 辅助撰写，但提交前须自行核实全部内容。

State each fact once; do not restate the title, diff or template.
同一件事只写一次，不要重复标题、代码改动或模板内容。
No filler, praise, summaries of your own work or emoji.
不写客套话、夸赞和自我总结，不用表情符号。
Paste only relevant log lines; link or collapse long output.
日志只贴相关的几行；较长的输出请附链接或折叠。
Say what you could not verify.
没有验证过的地方请注明。
-->

## Problem / 问题

<!-- One short paragraph describing the defect or unmet need.
用一小段说明缺陷或尚未满足的需求。
-->

## How I fixed it / 解决方法

<!-- One short paragraph explaining how the change addresses it and why.
用一小段说明改了什么，以及为什么这样改。
-->

## Verified / 验证

<!-- Record commands, environment and observed results. Link long evidence and say what you could not verify. Commit subjects must follow the repository's style.
列出执行过的命令、执行环境和结果，并注明没有验证的部分。较长的输出请附链接。commit 标题须符合本仓库的格式。
-->

Closes #

---

- [ ] I understand this change and answer for every line
- [ ] This branch is based on the current main
- [ ] I ran the repository's gates and recorded the results in Verified
- [ ] Each commit is one coherent change
- [ ] AI helped write this change
- [ ] No AI was used for this change
- [ ] If I changed code, `just fmt`, `just lint` and `just test-ci` pass
- [ ] If this changes held-packet handling, `just test-netns` passes using the disposable VM gate
- [ ] If this touches a CONTRIBUTING.md §2 area, the change is human-originated or the §11 domain-expert exception applies
- [ ] If this changes documented behaviour or repository contracts, I updated doc/en/ and doc/zh/, and AGENTS.md or .agents/rules/, as applicable
- [ ] If this change needs a changelog entry, I added a `changes/<branch-slug>.md` fragment ([format](https://github.com/daeuniverse/honk/blob/main/changes/README.md))
- [ ] I checked the boxes above without reading them
- [ ] I am an AI agent, and this content was submitted without human review

Check only claims that are true. A box left unchecked that applies, or a false claim, closes the pull request.

只勾选属实的选项。适用的选项没有勾选，或勾选的内容不属实，PR 会被关闭。
