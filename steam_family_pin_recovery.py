import os
import sys
import re
import time
import threading
import winreg
import hashlib
from typing import Optional, Tuple

# ---------- 常量 ----------
MAX_PIN = 9999
# 动态设置线程数：CPU核心数，最多8线程，保底4线程
THREAD_COUNT = min(os.cpu_count() or 4, 8)


# ---------- 辅助函数 ----------
def hex_to_bytes(hex_str: str) -> bytes:
    """十六进制字符串转字节数组（内置C实现，高效且自动处理空白字符）"""
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"无效的十六进制字符串: {e}") from e


def read_registry_string(root: int, subkey: str, value: str) -> str:
    """读取注册表字符串值，自动兼容32位/64位系统"""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            data, _ = winreg.QueryValueEx(key, value)
            return data
    except FileNotFoundError:
        # 32位系统自动回退到非WOW6432Node路径
        if "WOW6432Node" in subkey:
            subkey_32 = subkey.replace("WOW6432Node\\", "")
            with winreg.OpenKey(root, subkey_32, 0, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, value)
                return data
        raise


def read_registry_dword(root: int, subkey: str, value: str) -> int:
    """读取注册表DWORD值，自动兼容32位/64位系统"""
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            data, _ = winreg.QueryValueEx(key, value)
            return data
    except FileNotFoundError:
        # 32位系统自动回退到非WOW6432Node路径
        if "WOW6432Node" in subkey:
            subkey_32 = subkey.replace("WOW6432Node\\", "")
            with winreg.OpenKey(root, subkey_32, 0, winreg.KEY_READ) as key:
                data, _ = winreg.QueryValueEx(key, value)
                return data
        raise


def parse_parental_settings(vdf_path: str) -> str:
    """从localconfig.vdf中提取家庭监护设置的十六进制字符串"""
    if not os.path.exists(vdf_path):
        raise RuntimeError(f"文件不存在: {vdf_path}")

    with open(vdf_path, 'rb') as f:
        content = f.read().decode('utf-8', errors='ignore')

    # 使用正则表达式匹配，支持任意空白字符（空格、制表符、换行）
    pattern = r'"ParentalSettings"\s*{\s*"settings"\s*"([^"]+)"'
    match = re.search(pattern, content)
    if not match:
        raise RuntimeError("未找到家庭监护设置，请确认已开启家庭视图")

    return match.group(1)


def parse_protobuf_settings(data: bytes) -> Tuple[bytes, bytes, Optional[str]]:
    """简易Protobuf解析，提取盐值、目标哈希和恢复邮箱"""
    i = 0
    salt = None
    target_hash = None
    email = None

    while i < len(data):
        key_byte = data[i]
        i += 1

        field_num = key_byte >> 3
        wire_type = key_byte & 0x07

        if wire_type != 2:  # 跳过非length-delimited类型
            # 读取并跳过varint（最多10字节）
            shift = 0
            while i < len(data) and shift < 70 and (data[i] & 0x80):
                i += 1
                shift += 7
            i += 1  # 跳过最后一个字节
            continue

        # 读取字段长度（varint最多10字节）
        length = 0
        shift = 0
        while i < len(data) and shift < 70:
            b = data[i]
            i += 1
            length |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        else:
            raise RuntimeError("Protobuf数据损坏：无效的变长整数")

        if i + length > len(data):
            raise RuntimeError("Protobuf数据损坏：字段长度超出范围")

        value = data[i:i + length]
        if field_num == 7:
            salt = value
        elif field_num == 8:
            target_hash = value
        elif field_num == 11:
            email = value.decode('utf-8', errors='ignore')

        i += length

    if salt is None or target_hash is None:
        raise RuntimeError("Protobuf数据中缺少盐值或目标哈希")

    return salt, target_hash, email


# ---------- scrypt验证 ----------
def verify_scrypt(password: str, salt: bytes, target_hash: bytes,
                  n: int = 8192, r: int = 8, p: int = 1) -> bool:
    """验证scrypt哈希，使用常量时间比较防止侧信道攻击"""
    derived = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=len(target_hash))
    return hashlib.compare_digest(derived, target_hash)


# ---------- 多线程暴力破解 ----------
def brute_force(salt: bytes, target_hash: bytes) -> Optional[str]:
    total = MAX_PIN + 1
    found_event = threading.Event()
    result_pin = None
    progress = 0
    progress_lock = threading.Lock()
    start_time = time.time()

    def worker(start: int, end: int):
        nonlocal result_pin, progress
        local_progress = 0
        BATCH_SIZE = 100  # 每100个PIN批量更新一次进度，减少锁竞争

        for pin in range(start, end + 1):
            if found_event.is_set():
                break

            pin_str = f"{pin:04d}"
            if verify_scrypt(pin_str, salt, target_hash):
                found_event.set()
                result_pin = pin_str
                print(f"\n Found: {pin_str}")
                break

            local_progress += 1
            if local_progress >= BATCH_SIZE:
                with progress_lock:
                    progress += local_progress
                local_progress = 0

        # 处理最后一批不足100个的进度
        if local_progress > 0 and not found_event.is_set():
            with progress_lock:
                progress += local_progress

    # 分配任务区间
    step = (MAX_PIN + 1) // THREAD_COUNT
    threads = []
    for t in range(THREAD_COUNT):
        start = t * step
        end = (t + 1) * step - 1 if t != THREAD_COUNT - 1 else MAX_PIN
        th = threading.Thread(target=worker, args=(start, end), daemon=True)
        th.start()
        threads.append(th)

    # 进度显示
    while not found_event.is_set() and progress < total:
        percent = 100.0 * progress / total
        print(f"\r暴力破解进度: {percent:.2f}%", end='', flush=True)
        time.sleep(0.2)

    # 等待所有线程结束
    for th in threads:
        th.join()

    elapsed = time.time() - start_time
    print(f"\n耗时: {elapsed:.2f} 秒")
    return result_pin


# ---------- 主函数 ----------
def main():
    vdf_path = None
    if len(sys.argv) > 1:
        vdf_path = sys.argv[1]
        print(f"使用文件: {vdf_path}")
    else:
        print("正在从注册表获取Steam安装路径...")
        try:
            install_path = read_registry_string(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\WOW6432Node\Valve\Steam",
                "InstallPath"
            )
            print(f"Steam安装路径: {install_path}")
        except Exception as e:
            print(f"读取注册表失败: {e}")
            print("请将localconfig.vdf文件拖放到本脚本上运行")
            return

        print("正在获取活跃用户...")
        try:
            active_user = read_registry_dword(
                winreg.HKEY_CURRENT_USER,
                r"Software\Valve\Steam\ActiveProcess",
                "ActiveUser"
            )
            if active_user:
                print(f"活跃用户好友代码: {active_user}")
            else:
                raise ValueError("活跃用户ID为0")
        except Exception:
            while True:
                print("未找到活跃用户，请输入你的Steam好友代码:")
                try:
                    active_user = int(input().strip())
                    if active_user > 0:
                        break
                    print("好友代码必须是正整数")
                except ValueError:
                    print("输入无效，请输入数字")

        vdf_path = os.path.join(install_path, "userdata", str(active_user), "config", "localconfig.vdf")
        print(f"localconfig.vdf路径: {vdf_path}")

    print("正在解析家庭监护设置...")
    try:
        parental_hex = parse_parental_settings(vdf_path)
    except Exception as e:
        print(f"错误: {e}")
        return

    print("正在转换十六进制数据...")
    settings_bytes = hex_to_bytes(parental_hex)

    print("正在解析Protobuf字段...")
    try:
        salt, target_hash, email = parse_protobuf_settings(settings_bytes)
    except Exception as e:
        print(f"错误: {e}")
        return

    if email:
        print(f"恢复邮箱: {email}")

    print(f"开始暴力破解（{THREAD_COUNT}线程）...")
    pin = brute_force(salt, target_hash)
    if pin:
        print(f"\n家庭视图PIN码是: {pin}")
    else:
        print("\n未找到PIN码，可能数据已损坏")

    input("按回车键退出...")


if __name__ == "__main__":
    main()