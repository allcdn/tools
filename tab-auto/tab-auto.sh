#!/bin/bash

# 首先，更新系统软件列表
sudo apt-get update

# 安装 bash-completion
sudo apt-get install -y bash-completion

# 检查是否存在 bash-completion 初始化脚本
grep -q "^\. /etc/bash_completion$" ~/.bashrc || echo ". /etc/bash_completion" >> ~/.bashrc

# 重新加载 bash 配置以使改变生效
source ~/.bashrc

# 打印完成信息
echo "bash completion configured successfully"
