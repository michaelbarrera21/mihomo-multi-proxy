#!/bin/bash
set -e

echo "=== Proxy Manager 部署脚本 ==="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
APP_ROOT="/opt/proxy-manager"
APP_DIR="$APP_ROOT/mihomo-multi-proxy"

copy_app_source() {
    mkdir -p "$APP_ROOT"

    if [ "$SCRIPT_DIR" == "$APP_DIR" ]; then
        echo "   代码已在目标目录，跳过复制"
        return
    fi

    cp -a "$SCRIPT_DIR" "$APP_ROOT/"
}

install_requirements() {
    cd "$APP_ROOT"

    if [ ! -x ./venv/bin/python ]; then
        echo "   虚拟环境不存在或已损坏，正在重建..."
        rm -rf ./venv
        python3 -m venv venv
    fi

    if ! ./venv/bin/python -m pip --version >/dev/null 2>&1; then
        echo "   pip 不可用，正在初始化..."
        ./venv/bin/python -m ensurepip --upgrade
    fi

    if [ "$1" == "--upgrade-pip" ]; then
        ./venv/bin/python -m pip install --upgrade pip
    fi

    ./venv/bin/python -m pip install -r "$APP_DIR/requirements.txt"
}

if [ "$1" == "upgrade" ]; then
    echo "=== 升级模式 ==="
    echo "[1/4] 停止服务..."
    systemctl stop proxy-manager || true
    
    echo "[2/4] 备份数据库..."
    if [ -f /opt/proxy-manager/data.db ]; then
        cp /opt/proxy-manager/data.db /opt/proxy-manager/data.db.bak
        echo "   数据库已备份至 data.db.bak"
    fi
    
    echo "[3/4] 更新代码..."
    copy_app_source
    
    echo "[4/4] 更新依赖并重启..."
    install_requirements
    
    systemctl start proxy-manager
    systemctl status proxy-manager --no-pager
    echo "=== 升级完成 ==="
    exit 0
fi

# 1. 创建目录
echo "[1/5] 创建目录..."
mkdir -p "$APP_ROOT"

# 2. 复制文件 (假设你已经用 scp 把 mihomo-multi-proxy 目录传到 /tmp/mihomo-multi-proxy)
echo "[2/5] 复制文件..."
copy_app_source

# 3. 安装依赖 (使用虚拟环境)
echo "[3/5] 创建虚拟环境并安装依赖..."
cd "$APP_ROOT"
python3 -m venv venv
install_requirements --upgrade-pip

# 4. 安装 systemd 服务
echo "[4/5] 配置 systemd 服务..."
cp "$APP_DIR/proxy-manager.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable proxy-manager
systemctl start proxy-manager

# 5. 检查状态
echo "[5/5] 检查服务状态..."
systemctl status proxy-manager --no-pager

echo ""
echo "=== 部署完成 ==="
echo "访问地址: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "常用命令:"
echo "  查看日志: journalctl -u proxy-manager -f"
echo "  重启服务: systemctl restart proxy-manager"
