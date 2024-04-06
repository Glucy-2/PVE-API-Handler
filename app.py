#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote, unquote
import urllib3
from proxmoxer import ProxmoxAPI, ResourceException
from flask import Flask, request, jsonify
from threading import Thread
import ipaddress
import requests
import asyncio
import logging
import re


# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)


class ProxmoxData:
    api_baseurl = "https://192.168.0.11:8006"
    ipv4_network = ipaddress.IPv4Network("172.18.0.0/16")
    ipv4_gateway = ipaddress.IPv4Address("172.18.0.1")
    first_ipv4 = ipaddress.IPv4Address("172.18.1.0")
    ipv6_network = ipaddress.IPv6Network("ac12::/64")
    ipv6_gateway = ipaddress.IPv6Address("ac12::1")
    first_ipv6 = ipaddress.IPv6Address("ac12::1:0")
    first_vmid = 1000
    taken_vmids = set()


class LXCTemplates:
    templates = {
        "82rg": [
            {
                "name": "UbuntuKylin (优麒麟) 22.04 精简版",
                "description": "优麒麟是由麒麟软件有限公司主导开发的全球开源项目，专注于研发“友好易用，简单轻松”的桌面环境，"
                + "致力为全球用户带来更智能的用户体验，成为Linux开源桌面操作系统新领航！",
                "ostemplate": "local:vztmpl/ubuntukylin-22.04-mini-20240329.tar.zst",
                "ostype": "ubuntukylin",
            },
            {
                "name": "Debian 12 (Bookworm) XFCE4 桌面环境",
                "description": "Debian 由自由开源软件组成，提供了每个软件包合理的默认配置以及软件包生命周期内的定期安全更新，"
                + "附带了速度快、占用系统资源少，同时仍然具有视觉吸引力和用户友好性的 XFCE4 桌面环境。",
                "ostemplate": "local:vztmpl/debian-12-xfce4-20240331.tar.zst",
                "ostype": "debian-xfce4",
            },
        ]
    }


proxmox = ProxmoxAPI(
    "192.168.0.11:8006",
    user="test@pve",
    password="d-c.t_pve",
    backend="https",
    verify_ssl=False,
)

# proxmox = ProxmoxAPI(
#    backend="local",
# )

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)


def start_background_loop(loop: asyncio.AbstractEventLoop) -> None:
    asyncio.set_event_loop(loop)
    loop.run_forever()


async def refresh_ticket_loop() -> None:
    """
    刷新 Proxmox API 会话
    """
    while True:
        await asyncio.sleep(1800)
        proxmox.access.users.get()


async def start_refresh_ticket():
    loop = asyncio.new_event_loop()
    t = Thread(target=start_background_loop, args=(loop,), daemon=True)
    t.start()
    task = asyncio.run_coroutine_threadsafe(refresh_ticket_loop(), loop)
    return


asyncio.run(start_refresh_ticket())


async def userid_exists(userid: str) -> bool:
    """
    检查用户 ID 是否存在
    """
    users = proxmox.access.users.get()
    if users is None:
        return False
    for user in users:
        if user["userid"] == userid:
            return True
    else:
        return False


async def email_exists(email: str) -> bool:
    """
    检查邮箱是否存在
    """
    users = proxmox.access.users.get()
    if users is None:
        return False
    for user in users:
        if user["email"].lower() == email.lower():
            return True
    else:
        return False


async def run_command(cmd: str) -> dict:
    """
    运行命令
    """
    app.logger.debug(f"运行命令：{cmd}")
    proc = await asyncio.create_subprocess_shell(
        cmd=cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    app.logger.debug(
        f"命令：{cmd} 返回：{proc.returncode}, stdout：{stdout}, stderr：{stderr}"
    )
    return {
        "returncode": proc.returncode,
        "stdout": stdout.decode() if stdout else "",
        "stderr": stderr.decode() if stderr else "",
    }


async def get_lxc_username(vmid: int) -> str:
    """
    获取 LXC 容器用户名
    """
    output = await run_command(f"pct exec {vmid} -- id -un 1000")
    if output["returncode"]:
        app.logger.warning(f"获取 {vmid} 容器的用户名失败：{output['stderr']}")
        return ""
    return output["stdout"].strip()


@app.route("/api2/json/access/users", methods=["GET", "POST"])
async def register_handler():
    """
    注册用户 (POST) 和 获取用户列表 (GET)
    """
    if request.method == "POST":
        try:
            if (
                request.json["userid"].endswith("@pve")
                and len(request.json["password"]) > 5
            ):
                app.logger.info(f"接收到用户 {request.json['userid']} 的注册请求")
                # 检查用户 ID 和邮箱是否已被占用
                for user in proxmox.access.users.get():
                    if user["userid"] == request.json["userid"]:
                        return jsonify(
                            {
                                "data": None,
                                "success": 0,
                                "status": 500,
                                "message": f"创建用户失败：用户 {request.json['userid']} 已被注册\n",
                            }
                        )
                    if (
                        request.json.get("email") is not None
                        and user.get("email", "").lower()
                        == request.json.get("email", "").lower()
                    ):
                        return jsonify(
                            {
                                "data": None,
                                "success": 0,
                                "status": 500,
                                "message": f"创建用户失败：邮箱 {request.json['email']} 已被注册\n",
                            }
                        )

                # 注册用户
                try:
                    proxmox.access.users.post(
                        userid=request.json["userid"],
                        password=request.json["password"],
                        groups="CD_Users",
                        expire=request.json.get("expire"),
                        enable=request.json.get("enable"),
                        firstname=request.json.get("firstname"),
                        lastname=request.json.get("lastname"),
                        email=request.json.get("email"),
                        comment=request.json.get("comment"),
                        keys=request.json.get("keys"),
                    )
                    if await userid_exists(request.json["userid"]):
                        return jsonify({"success": 1, "data": None})
                    else:
                        return (
                            jsonify({"success": 0, "data": "注册失败：内部错误\n"}),
                            500,
                        )
                except ResourceException as e:
                    return (
                        jsonify(
                            {
                                "success": 0,
                                "data": "注册失败：资源错误\n"
                                + f"错误消息：{e.status_message}\n"
                                + f"错误内容：{e.content}\n错误：{e.errors}\n",
                            }
                        ),
                        e.status_code,
                    )
            else:
                return jsonify(
                    {"success": 0, "data": "注册失败：用户名或密码格式错误\n"}
                )
        except KeyError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "注册失败：缺少必要参数\n"
                    + f"错误消息：{e.args} 是必填参数\n",
                }
            )
    elif request.method == "GET":
        response = requests.get(
            ProxmoxData.api_baseurl + "/api2/json/access/users",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        )
        try:
            return jsonify(response.json()), response.status_code
        except requests.exceptions.JSONDecodeError:
            return response.text, response.status_code


async def post_create_lxc_handler(
    node: str, taskid: str, vmid: int, userid: str, userpasswd: str, vncpasswd: str
) -> None:
    """
    创建容器后处理
    """
    app.logger.info(
        f"接收到用户 {userid} 在节点 {node} 上的容器 {vmid} 创建任务：{taskid}，设置的用户密码为 {userpasswd}，VNC 密码为 {vncpasswd}，等待容器创建完成"
    )
    # 等待容器创建
    task_stopped = False
    while not task_stopped:
        task_status = proxmox.nodes(node).tasks(taskid).status.get()
        task_stopped = task_status["status"] == "stopped"
        app.logger.debug(
            f"等待用户 {userid} 在节点 {node} 上的容器 {vmid} 创建任务：{taskid} 完成..."
        )
        await asyncio.sleep(1)
    if task_status["exitstatus"] != "OK":
        # 容器创失败了呢不管了
        app.logger.info(
            f"用户 {userid} 在节点 {node} 上的容器 {vmid} 创建任务 {taskid} 失败"
        )
        return
    # 等待容器启动
    app.logger.info(
        f"用户 {userid} 在节点 {node} 上的容器 {vmid} 创建任务 {taskid} 成功，等待容器启动"
    )
    lxc_started = False
    try:
        while lxc_started != "running":
            lxc_status = proxmox.nodes(node).lxc(vmid).status.current.get()
            lxc_started = lxc_status["status"]
            app.logger.debug(f"等待用户 {userid} 在节点 {node} 上的容器 {vmid} 启动...")
            await asyncio.sleep(1)
    except ResourceException as e:
        app.logger.info(f"用户 {userid} 在节点 {node} 上的容器 {vmid} 启动失败：{e}")
        if e.content.startswith("Configuration file ") and e.content.endswith(
            " does not exist"
        ):
            # 容器不存在了呢不管了
            return
    # 设置容器防火墙规则
    app.logger.info(
        f"用户 {userid} 在节点 {node} 上的容器 {vmid} 启动成功，准备设置防火墙规则"
    )
    for source in {"172.18.0.0/24", "ac12::/112"}:
        proxmox.nodes(node).lxc(vmid).firewall.rules.post(
            type="in",
            enable=1,
            action="ACCEPT",
            source=source,
            log="nolog",
        )
    username = get_lxc_username(vmid)
    # 设置用户密码
    app.logger.info(f"设置用户 {userid} 在节点 {node} 上的容器 {vmid} 的用户密码")
    data = await run_command(
        f"echo -e '{userpasswd}\n{userpasswd}\n' | pct exec {vmid} -- passwd {username}",
    )
    app.logger.debug(
        {
            "command": f"echo -e '{userpasswd}\n{userpasswd}\n' | pct exec {vmid} -- passwd {username}",
            "data": data,
        }
    )
    app.logger.info(f"设置用户 {userid} 在节点 {node} 上的容器 {vmid} 的 VNC 密码")
    data = await run_command(
        f"echo -e '{vncpasswd}\n{vncpasswd}\nn\n' | pct exec {vmid} -- sudo -u {username} vncpasswd"
    )
    app.logger.debug(
        {
            "command": f"echo -e '{vncpasswd}\n{vncpasswd}\nn\n' | pct exec {vmid} -- sudo -u {username} vncpasswd",
            "data": data,
        }
    )
    app.logger.info(f"设置用户 {userid} 在节点 {node} 上的容器 {vmid} 的用户权限")
    try:
        proxmox.access.acl.put(
            path=f"/vms/{vmid}",
            users=userid,
            roles="ContainerDesktopUser",
        )
    except ResourceException as e:
        app.logger.info(
            f"设置用户 {userid} 在节点 {node} 上的容器 {vmid} 的用户权限失败：{e}"
        )
        if e.content.startswith("Configuration file ") and e.content.endswith(
            " does not exist"
        ):
            # 容器不存在了呢不管了
            return


@app.route("/api2/json/nodes/<node>/lxc", methods=["GET", "POST"])
async def create_lxc(node: str):
    """
    创建和恢复 LXC 容器 (POST) 和 获取 LXC 容器列表 (GET)
    """
    if request.method == "POST":
        # 验证用户权限
        try:
            requests.get(
                ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc",
                headers=request.headers,
                cookies=request.cookies,
                verify=False,
            )
        except ResourceException as e:
            return (
                jsonify(
                    {
                        "success": 0,
                        "data": "修改失败：资源错误\n"
                        + f"错误消息：{e.status_message}\n"
                        + f"错误内容：{e.content}\n"
                        + f"错误：{e.errors}\n",
                    }
                ),
                e.status_code,
            )
        app.logger.info(
            f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器创建请求"
        )
        # 获取用户 ID
        try:
            userid = unquote(request.cookies["PVEAuthCookie"]).split(":")[1]
        except IndexError:
            return jsonify({"success": 0, "data": "创建失败：登录凭据无效\n"})
        # 检查必需参数
        try:
            ostemplate = request.json["ostemplate"]
            userpasswd = request.json["userpasswd"]
            vncpasswd = request.json["vncpasswd"]
        except KeyError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "创建失败：缺少必要参数\n"
                    + f"错误消息：{e.args}是必填参数\n",
                }
            )
        # 获取可用的容器 ID
        expected_vmid = max(ProxmoxData.taken_vmids) + 1
        available_vmid = 0
        while not available_vmid:
            try:
                available_vmid = int(proxmox.cluster.nextid.get(vmid=expected_vmid))
                ProxmoxData.taken_vmids.add(available_vmid)
            except ResourceException:
                expected_vmid += 1
        try:
            # 根据容器模板名称判断操作系统类型
            if "debian" in ostemplate:
                os_type = "debian"
            elif "ubuntukylin" in ostemplate:
                os_type = "ubuntukylin"
            elif "ubuntu" in ostemplate:
                os_type = "ubuntu"
            elif "kylinos" in ostemplate:
                os_type = "kylinos"
            elif "deepin" in ostemplate:
                os_type = "deepin"
            elif "archlinux" in ostemplate:
                os_type = "archlinux"
            else:
                return jsonify(
                    {
                        "success": 0,
                        "data": "创建失败：未知的操作系统类型\n",
                    }
                )
            # 创建容器
            task_id = proxmox.nodes(node).lxc.post(
                # 容器 ID
                vmid=available_vmid,
                # I/O 限制 (KiB/s)
                bwlimit=request.json.get("bwlimit", 131072),  # 128 MiB/s
                # 容器模板
                ostemplate=ostemplate,
                # 容器主机名
                hostname=request.json.get("hostname"),
                # CPU 核心数
                cores=request.json.get("cores", 4),
                # CPU 最大使用率
                cpulimit=request.json.get("cpulimit", 0),
                # 内存大小 (MB)
                memory=int(request.json.get("memory", 4096)),  # 4 GB
                # 交换空间大小 (MB)
                swap=int(
                    request.json.get("swap", request.json.get("memory", 4096) / 2)
                ),
                # root 密码
                password=request.json.get("password"),
                # 标签
                tags=os_type,
                # 根文件系统
                rootfs=request.json.get("rootfs", "local-lvm:8"),
                # 存储位置
                storage=request.json.get("storage", "local"),
                # 网卡
                net0=f"name=eth0,bridge=vmbr1,firewall=1,"
                + f"ip={ProxmoxData.first_ipv4 + available_vmid - ProxmoxData.first_vmid}"
                + f"/{ProxmoxData.ipv4_network.prefixlen},gw={ProxmoxData.ipv4_gateway},"
                + f"ip6={ProxmoxData.first_ipv6 + available_vmid - ProxmoxData.first_vmid}"
                + f"/{ProxmoxData.ipv6_network.prefixlen},gw6={ProxmoxData.ipv6_gateway},"
                + "rate=10",  # 网络限速 (MB/s)
                # DNS 服务器
                nameserver=request.json.get("nameserver"),
                # 创建成功后启动
                start=1,
                # 节点启动时自启
                onboot=1,
                # 描述
                description=f"<UserID: {userid}>\n" + request.json.get("description"),
            )
            app.logger.info(
                f"提交用户 {userid} 在节点 {node} 上的容器 {available_vmid} 创建任务 {task_id}"
            )
            loop = asyncio.new_event_loop()
            t = Thread(target=start_background_loop, args=(loop,), daemon=True)
            t.start()
            task = asyncio.run_coroutine_threadsafe(
                post_create_lxc_handler(
                    node=node,
                    taskid=task_id,
                    vmid=available_vmid,
                    userid=userid,
                    userpasswd=userpasswd,
                    vncpasswd=vncpasswd,
                ),
                loop,
            )
            return jsonify({"success": 1, "data": task_id})
        except ResourceException as e:
            return (
                jsonify(
                    {
                        "success": 0,
                        "data": "创建失败：资源错误\n"
                        + f"错误消息：{e.status_message}\n"
                        + f"错误内容：{e.content}\n"
                        + f"错误：{e.errors}\n",
                    }
                ),
                e.status_code,
            )
        except KeyError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "创建失败：缺少必要参数\n"
                    + f"错误消息：{e.args} 是必填参数\n",
                }
            )
        except ValueError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "创建失败：参数格式错误\n"
                    + f"错误消息：{e.args} 不是有效的数字\n",
                }
            )
    elif request.method == "GET":
        app.logger.info(
            f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器列表请求"
        )
        response = requests.get(
            ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        )
        try:
            return jsonify(response.json()), response.status_code
        except requests.exceptions.JSONDecodeError:
            return response.text, response.status_code


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/config", methods=["GET", "PUT"])
async def config_lxc(node: str, vmid: int):
    """
    修改 LXC 容器配置 (PUT) 和 获取 LXC 容器配置 (GET)
    """
    if request.method == "PUT":
        # 验证用户权限
        try:
            requests.get(
                ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc/{vmid}/config",
                headers=request.headers,
                cookies=request.cookies,
                verify=False,
            )
        except ResourceException as e:
            return (
                jsonify(
                    {
                        "success": 0,
                        "data": "修改失败：资源错误\n"
                        + f"错误消息：{e.status_message}\n"
                        + f"错误内容：{e.content}\n"
                        + f"错误：{e.errors}\n",
                    }
                ),
                e.status_code,
            )
        app.logger.info(
            f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} 配置修改请求"
        )
        # 获取用户 ID
        try:
            userid = unquote(request.cookies["PVEAuthCookie"]).split(":")[1]
        except IndexError:
            return jsonify({"success": 0, "data": "修改失败：登录凭据无效\n"})
        try:
            # 修改容器配置
            proxmox.nodes(node).lxc(vmid).config.put(
                # 配置文件 SHA1
                digest=request.json["digest"],
                # 需要删除的配置列表
                delete=request.json.get("delete"),
                # 主机名
                hostname=request.json.get("hostname"),
                # CPU 核心数
                cores=request.json.get("cores"),
                # CPU 最大使用率
                cpulimit=request.json.get("cpulimit"),
                # 内存大小 (MB)
                memory=int(request.json.get("memory")),
                # 交换空间大小 (MB)
                swap=int(request.json.get("swap")),
                # 开启的 LXC 功能
                features=request.json.get("features"),
                # DNS 服务器
                nameserver=request.json.get("nameserver"),
                # 节点启动时自启
                onboot=request.json.get("onboot"),
                # 回滚未应用的更改
                revert=request.json.get("revert"),
                # 描述
                description=f"<UserID: {userid}>\n" + request.json.get("description"),
            )
            return jsonify({"success": 1, "data": None})
        except ResourceException as e:
            return (
                jsonify(
                    {
                        "success": 0,
                        "data": "修改失败：资源错误\n"
                        + f"错误消息：{e.status_message}\n"
                        + f"错误内容：{e.content}\n"
                        + f"错误：{e.errors}\n",
                    }
                ),
                e.status_code,
            )
        except KeyError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "修改失败：缺少必要参数\n"
                    + f"错误消息：{e.args} 是必填参数\n",
                }
            )
        except ValueError as e:
            return jsonify(
                {
                    "success": 0,
                    "data": "修改失败：参数格式错误\n"
                    + f"错误消息：{e.args} 不是有效的数字\n",
                }
            )
    elif request.method == "GET":
        try:
            response = requests.get(
                ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc/{vmid}/config",
                headers=request.headers,
                cookies=request.cookies,
                verify=False,
            )
            result = response.json()
            app.logger.info(
                f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} 配置获取请求"
            )
            # 处理描述信息 (移除开头的<>行)
            if result["data"].get("description") is None:
                return jsonify(result), response.status_code
            lines = result["data"].get("description").split("\n")
            if lines is not None:
                for i, line in enumerate(lines):
                    if not line.startswith("<") or not line.endswith(">"):
                        result["data"]["description"] = "\n".join(lines[i:])
                        break
            return jsonify(result), response.status_code
        except ResourceException as e:
            return (
                jsonify(
                    {
                        "success": 0,
                        "data": "获取失败：资源错误\n"
                        + f"错误消息：{e.status_message}\n"
                        + f"错误内容：{e.content}\n"
                        + f"错误：{e.errors}\n",
                    }
                ),
                e.status_code,
            )
        except requests.exceptions.JSONDecodeError:
            return jsonify({"success": 0, "data": response.text}), response.status_code


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/resize", methods=["PUT"])
async def resize_lxc_disk(node: str, vmid: int):
    """
    扩容 LXC 容器硬盘
    """
    # 验证必需参数
    try:
        if "rootfs" != request.json["disk"] and not re.match(
            r"mp\d+", request.json["disk"]
        ):
            return jsonify(
                {
                    "success": 0,
                    "data": "扩容失败：硬盘名格式错误\n"
                    + f"错误消息：{request.json['disk']} 不是有效的硬盘名\n",
                }
            )
        if not re.match(r"\+?\d+(\.\d+)?[KMGT]?", request.json["size"]):
            return jsonify(
                {
                    "success": 0,
                    "data": "修改扩容失败：硬盘名格式错误\n"
                    + f"错误消息：{request.json['size']} 不是有效的扩容大小\n",
                }
            )
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "修改失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    # 验证用户权限和硬盘存在
    try:
        lxc_config = requests.get(
            ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc/{vmid}/config",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        )
        if lxc_config.json().get(request.json["disk"]) is None:
            return jsonify(
                {
                    "success": 0,
                    "data": "扩容失败：硬盘不存在\n"
                    + f"错误消息：{request.json['disk']} 不是有效的硬盘名\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "扩容失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    try:
        # 扩容
        task_id = (
            proxmox.nodes(node)
            .lxc(vmid)
            .resize.put(
                # 硬盘名
                disk=request.json["disk"],
                # 硬盘大小
                size=request.json["size"],
            )
        )
        return jsonify({"success": 1, "data": task_id})
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "修改失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "修改失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/userpasswd", methods=["PUT"])
async def change_lxc_userpasswd(node: str, vmid: int):
    """
    更改容器用户密码
    """
    # 验证必需参数
    try:
        userpasswd = request.json["userpasswd"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "修改失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "修改失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "修改失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    # 获取容器内用户名
    username = get_lxc_username(vmid)
    # 更改密码
    output = await run_command(
        f"echo -e '{userpasswd}\n{userpasswd}\n' | pct exec {vmid} -- passwd {username}",
    )
    return jsonify(
        {
            "success": 0 if output["returncode"] else 1,
            "data": None,
            "output": output,
        }
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/passwd", methods=["PUT"])
async def change_lxc_vncpasswd(node: str, vmid: int):
    """
    更改容器 VNC 密码
    """
    # 验证必需参数
    try:
        vncpasswd = request.json["vncpasswd"]
        if not re.match(r"^[a-zA-Z0-9]{6,8}$", vncpasswd):
            return jsonify(
                {
                    "success": 0,
                    "data": "修改失败：VNC 密码格式错误\n"
                    + f"错误消息：您输入的内容不是有效的 VNC 密码\n",
                }
            )
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "修改失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "修改失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "修改失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    app.logger.info(
        f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} VNC 密码修改请求"
    )
    # 获取容器内用户名
    username = get_lxc_username(vmid)
    app.logger.debug(f"容器 {vmid} 的用户名为 {username}")
    # 更改 VNC 密码
    output = await run_command(
        f"echo -e '{vncpasswd}\n{vncpasswd}\nn\n' | pct exec {vmid} -- sudo -u {username} vncpasswd"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc", methods=["GET"])
async def get_lxc_vnc_services(node: str, vmid: int):
    """
    获取容器 VNC 服务列表
    """
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "获取失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "获取失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    app.logger.info(
        f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} VNC 服务列表请求"
    )
    # 获取 VNC 服务列表
    output = await run_command(
        f"pct exec {vmid} -- systemctl list-units -t service --all --full vncserver@*"
    )
    if output["returncode"] != 0:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "获取 VNC 服务列表失败",
                    "output": output,
                }
            ),
            500,
        )
    service_list = output["stdout"].split("\n\n")[0]

    # 匹配每行的服务信息
    pattern = r"[*●\s]*vncserver@(\d+)(.service)*\s+(\S+)\s+(\S+)\s+(\S+)\s+(.+)"
    matches = re.findall(pattern, service_list)

    # 解析每个服务的详细信息
    services = []
    for match in matches:
        id, _, load, active, sub, description = match
        service = {
            "id": id,
            "load": load,
            "active": active,
            "sub": sub,
            "description": description.strip(),
        }
        services.append(service)
    return jsonify(
        {
            "success": 1,
            "data": None,
            "services": services,
        }
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/restart", methods=["POST"])
async def lxc_vnc_service_restart(node: str, vmid: int):
    """
    重启容器 VNC 服务
    """
    # 验证必需参数
    try:
        ids: list = request.json["ids"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "重启失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    except TypeError as e:
        return jsonify(
            {
                "success": 0,
                "data": "重启失败：参数格式错误\n"
                + f"错误消息：{e.args} 不是有效的列表\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "重启失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "重启失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    app.logger.info(
        f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} VNC 服务重启请求"
    )
    # 重启 VNC 服务
    output = await run_command(
        f"pct exec {vmid} -- systemctl restart vncserver@{' vncserver@'.join(str(id) for id in ids)}"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/start", methods=["POST"])
async def lxc_vnc_service_start(node: str, vmid: int):
    """
    启动容器 VNC 服务
    """
    # 验证必需参数
    try:
        ids: list = request.json["ids"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "启动失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    except TypeError as e:
        return jsonify(
            {
                "success": 0,
                "data": "启动失败：参数格式错误\n"
                + f"错误消息：{e.args} 不是有效的列表\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "启动失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "启动失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    app.logger.info(
        f"接收到用户 {unquote(request.cookies['PVEAuthCookie']).split(':')[1]} 在节点 {node} 上的容器 {vmid} VNC 服务启动请求"
    )
    # 开启 VNC 服务
    output = await run_command(
        f"pct exec {vmid} -- systemctl start vncserver@{' vncserver@'.join(str(id) for id in ids)}"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/stop", methods=["POST"])
async def lxc_vnc_service_stop(node: str, vmid: int):
    """
    关闭容器 VNC 服务
    """
    # 验证必需参数
    try:
        ids: list = request.json["ids"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "关闭失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    except TypeError as e:
        return jsonify(
            {
                "success": 0,
                "data": "关闭失败：参数格式错误\n"
                + f"错误消息：{e.args} 不是有效的列表\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "关闭失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "关闭失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    # 关闭 VNC 服务
    output = await run_command(
        f"pct exec {vmid} -- systemctl stop vncserver@{' vncserver@'.join(str(id) for id in ids)}"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/enable", methods=["POST"])
async def lxc_vnc_service_enable(node: str, vmid: int):
    """
    启用容器 VNC 服务
    """
    app.logger.info(f"启用节点 {node} 上的容器 {vmid} 的 VNC 服务")
    # 验证必需参数
    try:
        ids: list = request.json["ids"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "启用失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    except TypeError as e:
        return jsonify(
            {
                "success": 0,
                "data": "启用失败：参数格式错误\n"
                + f"错误消息：{e.args} 不是有效的列表\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "启用失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "启用失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    # 启用 VNC 服务
    now = "--now" if request.json.get("ids") else ""
    output = await run_command(
        f"pct exec {vmid} -- systemctl enable {now} vncserver@{' vncserver@'.join(str(id) for id in ids)}"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/lxc/<int:vmid>/vnc/disable", methods=["POST"])
async def lxc_vnc_service_disable(node: str, vmid: int):
    """
    禁用容器 VNC 服务
    """
    app.logger.info(f"禁用容器 {vmid} 的 VNC 服务")
    # 验证必需参数
    try:
        ids: list = request.json["ids"]
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "禁用失败：缺少必要参数\n" + f"错误消息：{e.args} 是必填参数\n",
            }
        )
    except TypeError as e:
        return jsonify(
            {
                "success": 0,
                "data": "禁用失败：参数格式错误\n"
                + f"错误消息：{e.args} 不是有效的列表\n",
            }
        )
    # 验证用户权限和容器状态
    try:
        current_status = requests.get(
            ProxmoxData.api_baseurl
            + f"/api2/json/nodes/{node}/lxc/{vmid}/status/current",
            headers=request.headers,
            cookies=request.cookies,
            verify=False,
        ).json()
        if current_status["status"] != "running":
            return jsonify(
                {
                    "success": 0,
                    "data": "禁用失败：容器未运行\n"
                    + f"错误消息：容器状态为 {current_status['status']}\n",
                }
            )
    except ResourceException as e:
        return (
            jsonify(
                {
                    "success": 0,
                    "data": "禁用失败：资源错误\n"
                    + f"错误消息：{e.status_message}\n"
                    + f"错误内容：{e.content}\n"
                    + f"错误：{e.errors}\n",
                }
            ),
            e.status_code,
        )
    # 禁用 VNC 服务
    now = "--now" if request.json.get("ids") else ""
    output = await run_command(
        f"pct exec {vmid} -- systemctl disable {now} vncserver@{' vncserver@'.join(str(id) for id in ids)}"
    )
    return (
        jsonify(
            {
                "success": 0 if output["returncode"] else 1,
                "data": None,
                "output": output,
            }
        ),
        500 if output["returncode"] else 200,
    )


@app.route("/api2/json/nodes/<node>/vztmpl", methods=["GET"])
async def get_lxc_templates(node: str):
    """
    获取节点上的 LXC 模板列表
    """
    try:
        return jsonify(LXCTemplates.templates[node])
    except KeyError as e:
        return jsonify(
            {
                "success": 0,
                "data": "获取失败：节点不存在\n"
                + f"错误消息：{e.args} 不是有效的节点名\n",
            }
        ), 404


resources = proxmox.cluster.resources.get(type="vm")
if resources:
    for resource in resources:
        try:
            ProxmoxData.taken_vmids.add(int(resource["vmid"]))
        except KeyError:
            continue

if __name__ == "__main__":
    app.run(debug=True, port=5000)
