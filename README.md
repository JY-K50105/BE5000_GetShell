# Mi Router BE5000 (RD18) Get SSH Tool / 小米路由器 BE5000 (RD18) 获取 SSH 权限

## Legal Disclaimer / 法律声明

> [!WARNING]
> This program is for educational and research purposes only. All devices must be legally owned by you. Unauthorized access to public facilities or network infrastructure may violate cybersecurity laws and regulations.
>
> 本程序仅供学习与交流，所有的设备均为私人合法持有，对公共设施实施本文所述的相关操作造成公共安全损失有机会触犯《网络安全法》。

## Description / 描述

> This tool only tested with Python 3.8.20 on macOS, and may not work with other versions. Windows has known issues, use at your own risk.
>
> 本工具仅在 macOS 的 Python 3.8.20 上测试，其他版本可能无法正常工作。（Windows已知存在字符编码问题）
> 请提前安装好以下模块

```bash
pip install requests -i https://mirrors.aliyun.com/pypi/simple
```

A tool designed to exploit vulnerabilities in Mi Router BE5000 with 1.0.53 firmware, enabling SSH access through command injection. The tool consists of three main components:
- Initial exploitation and file transfer
- SSH service deployment
- SSH persistence mechanism

这是一个针对小米路由器 BE5000 1.0.53 固件的漏洞利用工具，通过命令注入实现 SSH 访问。工具包含三个主要组件：
- 初始漏洞利用和文件传输
- SSH 服务部署
- SSH 持久化机制

## Usage / 使用方法

1. Configure the following variables in the script:
   - `LOCAL_IP`: Your local machine's IP address
   - `ROUTER_IP`: Target router's IP address
   - `TOKEN`: Router's authentication token (can be found in the router's web interface after login, the 32-bit string after `stok=`)
   - `PORT`: Local HTTP server port (default: 8888)

2. Run the initial exploitation:

```bash
python crack.py
```

Now you can access the router via SSH through 23323 port using the root account and the password calculated from https://mi.tellme.top/.

3. For SSH persistence (optional):

```bash
python persist.py
```


1. 配置脚本中的以下变量：
   - `LOCAL_IP`：本地机器的 IP 地址
   - `ROUTER_IP`：目标路由器的 IP 地址
   - `TOKEN`：路由器的认证令牌（可以在路由器登陆之后的 Web 界面中找到，32 位字符串，`stok=` 之后的部分）
   - `PORT`：本地 HTTP 服务器端口（默认：8888）

2. 运行初始漏洞利用：

```bash
python crack.py
```

现在你可以通过 23323 端口使用 root 账户和从 https://mi.tellme.top/ 计算出的密码通过 SSH 访问路由器。

3. SSH 持久化：

```bash
python persist.py
```


## Credits / 致谢

Special thanks to Bhao for the original research and documentation:  
特别感谢 Bhao 的原创研究和文档：  
[https://dwd.moe/p/mi-router-be5000.html](https://dwd.moe/p/mi-router-be5000.html)

Thanks to lschg for providing a solution to the Windows encoding issue:
感谢 lschg 提供的 Windows 编码问题解决方案：
[https://github.com/z-jack/BE5000_GetShell/issues/5](https://github.com/z-jack/BE5000_GetShell/issues/5)

## Technical Details / 技术细节

The tool uses a command injection vulnerability in the router's binding API endpoint. It deploys a modified dropbear SSH server and establishes persistence through the router's firewall configuration.
 
该工具利用路由器绑定 API 端点中的命令注入漏洞。部署修改版的 dropbear SSH 服务器，并通过路由器的防火墙配置建立持久性访问。

## Disclaimer / 免责声明

The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk and only on devices you legally own.

作者不对此工具的任何滥用或造成的损害负责。使用风险自负，且仅限用于您合法拥有的设备。
