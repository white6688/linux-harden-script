# Linux 系统安全加固脚本使用说明

## 简介

这是一个功能全面的 Linux 系统安全加固脚本，通过一系列优化和配置调整来增强 Linux 系统的安全性。脚本采用模块化设计，可自定义多项安全加固选项。

## 功能特点

- **自动备份** - 在修改前自动备份系统关键配置文件
- **并行处理** - 支持多任务并行执行，提高效率
- **模块化设计** - 可选择性执行或跳过特定安全组件
- **自动恢复** - 生成恢复脚本，支持一键恢复原始设置
- **安全基线检查** - 生成安全状态报告
- **兼容性强** - 支持多种 Linux 发行版（如 Debian/Ubuntu、CentOS/RHEL）

## 系统要求

- Linux 操作系统（已测试：Ubuntu、Debian、CentOS、RHEL 等主流发行版）
- root 权限（必需）
- bash shell 环境

## 使用方法

### 基本使用

```bash
# 下载脚本
wget https://url/to/linux-hardening-script.sh

# 添加执行权限
chmod +x linux-hardening-script.sh

# 以 root 用户执行（最基本用法）
sudo ./linux-hardening-script.sh
```

### 参数说明

脚本支持多种命令行参数来定制加固行为：

```
--help                显示帮助信息
--no-backup           不创建配置备份
--disable-usb         禁用 USB 存储设备
--ssh-port PORT       更改 SSH 端口为指定值
--no-audit            不配置审计系统
--interactive         交互模式，逐步确认每个更改
--dry-run             仅显示将执行的操作，不实际更改系统
--no-parallel         禁用并行处理，顺序执行所有任务
--skip COMPONENT      跳过指定组件的加固（可用:ssh,firewall,kernel,network,dns,containers）
--log-file FILE       指定自定义日志文件路径
--backup-dir DIR      指定自定义备份目录
--restore FILE        从指定的备份恢复系统配置
--profile PROFILE     使用预定义的安全配置文件（可用:server,desktop,minimal）
--no-root-login       禁止 root 用户通过 SSH 登录（默认允许）
```

### 使用示例

```bash
# 执行加固，但不配置审计和禁用 USB
sudo ./linux-hardening-script.sh --no-audit

# 使用交互模式，逐步确认每个更改
sudo ./linux-hardening-script.sh --interactive

# 配置服务器安全策略，并更改 SSH 端口
sudo ./linux-hardening-script.sh --profile server --ssh-port 2222

# 跳过防火墙和 DNS 组件的配置
sudo ./linux-hardening-script.sh --skip firewall --skip dns

# 从备份恢复系统配置
sudo ./linux-hardening-script.sh --restore /root/security_backup_20230101_010101/restore.sh
```

## 加固内容概述

脚本执行的安全加固包括但不限于：

1. **系统更新** - 更新系统软件包
2. **密码策略** - 配置强密码策略
3. **SSH 加固** - 加强 SSH 服务安全配置
4. **防火墙配置** - 设置基本防火墙规则
5. **服务管理** - 禁用不必要的服务
6. **SUID/SGID 控制** - 限制敏感文件的特殊权限
7. **日志安全** - 配置安全日志记录
8. **内核安全** - 优化内核安全参数
9. **PAM 安全** - 加强 PAM 认证模块配置
10. **账户管理** - 锁定系统账户、检查空密码
11. **文件系统安全** - 设置安全挂载选项
12. **审计系统** - 配置系统审计规则（可选）
13. **网络安全** - 安装配置 fail2ban 防暴力破解
14. **DNS 安全** - 优化 DNS 配置

## 恢复方法

脚本在执行过程中会创建备份和恢复脚本。如需恢复原始配置：

```bash
# 执行备份目录中的恢复脚本
sudo /root/security_backup_日期_时间/restore.sh
```

## 日志和报告

- 详细日志保存在 `/var/log/security_hardening_日期_时间.log`
- 安全基线报告保存在 `/root/security_backup_日期_时间/security_baseline_report.txt`

## 注意事项

1. **备份重要性** - 建议在生产环境使用前先在测试环境验证
2. **登录问题** - 如遇登录问题，脚本已默认保留 root 本地登录能力
3. **恢复命令** - 如遇紧急问题，可尝试以下命令：
   - `chmod u+s /bin/su /usr/bin/passwd` (恢复必要 SUID 权限)
   - `faillock --user root --reset` (解锁 root 账户)
   - `usermod -s /bin/bash root` (恢复 root 正确 shell)
4. **重启建议** - 加固完成后建议重启系统以应用所有更改

## 常见问题

**Q: 执行脚本后无法通过 SSH 登录怎么办？**  
A: 默认情况下脚本不会禁用 root SSH 登录。如果使用了 `--no-root-login` 选项，请使用普通用户登录。如果仍有问题，通过物理控制台登录并执行恢复脚本。

**Q: 加固后系统性能是否会受影响？**  
A: 加固主要针对安全配置，对系统性能影响极小，部分网络参数优化可能略微提升性能。

**Q: 是否支持所有 Linux 发行版？**  
A: 脚本设计兼容大多数主流 Linux 发行版，但某些特定功能可能因发行版差异而有所不同，脚本会自动检测并适配。

**Q: 如何验证加固是否成功？**  
A: 请查看生成的安全基线报告，或使用第三方安全扫描工具进行验证。
# linux-harden-script

