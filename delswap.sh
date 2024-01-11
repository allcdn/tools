#!/bin/bash

# 安装sudo工具
apt install sudo -y

# 关闭所有swap分区
sudo swapoff -a

# 获取swap分区信息
swap_line=$(grep "swap" /etc/fstab)

# 检查UUID存在与否
if [[ $swap_line =~ UUID=(.+)[[:space:]] ]]; then
  swap_uuid=${BASH_REMATCH[1]}
  swap_dev=$(findmnt -no SOURCE -U UUID=$swap_uuid)
else
  swap_dev=$(echo $swap_line | awk '{print $1}')
fi

# 从/etc/fstab中删除swap分区
sudo sed -i "/swap/d" /etc/fstab

# 删除物理swap分区
swap_dev_prefix=$(echo $swap_dev | rev | cut -c 2- | rev)
echo -e "d\nw\n" | sudo fdisk $swap_dev_prefix
