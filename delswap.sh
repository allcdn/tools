#!/bin/bash

# 关闭所有swap分区
apt install sudo -y
sudo swapoff -a

# 选择swap分区
swap_line=$(cat /etc/fstab | grep swap)
swap_id=$(echo $swap_line | awk '{print $1}')

# 如果swap分区被UUID标识
if [[ $swap_id =~ UUID=(.+) ]]
then
    swap_part=$(lsblk -no NAME,UUID | grep ${BASH_REMATCH[1]} | awk '{print \$1}')
    sudo sed -i "/UUID=${BASH_REMATCH[1]}/d" /etc/fstab
else
    # 否则，swap分区被设备名如/dev/sdaX标识
    swap_part=${swap_id/\/dev\//}
    sudo sed -i "/${swap_id/\\/\\\\/}/d" /etc/fstab
fi

# 删除物理swap分区
echo -e "d\nw\n" | sudo fdisk /dev/${swap_part::-1}
