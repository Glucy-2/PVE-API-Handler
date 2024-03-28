#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from proxmoxer import ProxmoxAPI, ResourceException
from flask import Flask, request, jsonify
from urllib.parse import quote, unquote
import subprocess
import ipaddress
import requests
import asyncio
import re


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


async def userid_exists(userid: str) -> bool:
    """
    检查用户 ID 是否存在
    """
    for user in proxmox.access.users.get():
        if user["userid"] == userid:
            return True
    else:
        return False


async def email_exists(email: str) -> bool:
    """
    检查邮箱是否存在
    """
    for user in proxmox.access.users.get():
        if user["email"].lower() == email.lower():
            return True
    else:
        return False


@app.route("/api2/json/access/users", methods=["GET", "POST"])
async def register_handler():
    """
    注册用户 (POST) 和 获取用户列表 (GET)
    """
    if request.method == "POST":
        try:
            print(request.json)
            if (
                request.json["userid"].endswith("@pve")
                and len(request.json["password"]) > 5
            ):
                # 检查用户 ID 和邮箱是否已被占用
                for user in proxmox.access.users.get():
                    if user["userid"] == request.json["userid"]:
                        return jsonify(
                            {
                                "data": None,
                                "success": 0,
                                "status": 500,
                                "message": f"创建用户失败：用户{request.json['userid']}已被注册\n",
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
                                "message": f"创建用户失败：邮箱{request.json['email']}已被注册\n",
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
):
    task_stopped = False
    while not task_stopped:
        status = proxmox.nodes(node).tasks(taskid).status.get()
        task_stopped = status["status"] == "stopped"
        await asyncio.sleep(1)
    if status["exitstatus"] != "OK":
        return
    # 设置容器防火墙规则
    for source in {"172.18.0.0/24", "ac12::/112"}:
        proxmox.nodes(node).lxc(vmid).firewall.rules.post(
            type="in",
            enable=1,
            action="ACCEPT",
            source=source,
            log="nolog",
        )
    # TODO: 判断用户名
    username = "kylin"
    for command in [
        # 进入容器 shell
        f"pct enter {vmid}",
        # 设置用户密码
        f"echo -e '{userpasswd}\n{userpasswd}\n' | passwd {username}",
        # 设置 VNC 密码
        f"echo -e '{vncpasswd}\n{vncpasswd}\nn\n' | vncpasswd /home/{username}/.vnc/passwd",
        # 重启所有 VNC 服务
        "systemctl restart vncserver@*",
        # 退出容器 shell
        "exit",
    ]:
        subprocess.run(command, shell=True)
    # 设置容器权限
    proxmox.access.acl.put(
        path=f"/vms/{vmid}",
        users=userid,
        roles="PVEVMUser",
    )


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
                memory=request.json.get("memory", 4096),  # 4 GB
                # 交换空间大小 (MB)
                swap=request.json.get("swap", request.json.get("memory", 4096) / 2),
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
                # 节点启动时自启
                onboot=1,
                # 描述
                description=f"<UserID: {userid}>\n" + request.json.get("description"),
            )
            asyncio.create_task(
                post_create_lxc_handler(
                    node=node,
                    taskid=task_id,
                    vmid=available_vmid,
                    userid=userid,
                    userpasswd=userpasswd,
                    vncpasswd=vncpasswd,
                )
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
    elif request.method == "GET":
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
                memory=request.json.get("memory"),
                # 交换空间大小 (MB)
                swap=request.json.get("swap"),
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
    elif request.method == "GET":
        try:
            response = requests.get(
                ProxmoxData.api_baseurl + f"/api2/json/nodes/{node}/lxc/{vmid}/config",
                headers=request.headers,
                cookies=request.cookies,
                verify=False,
            )
            result = {"data": response.json()}
            lines = result["data"].get("description")
            if lines is not None:
                for i, line in enumerate(lines):
                    if not line.startswith('<') or not line.endswith('>'):
                        result["data"]["description"] = '\n'.join(lines[i:])
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


for resource in proxmox.cluster.resources.get(type="vm"):
    try:
        ProxmoxData.taken_vmids.add(int(resource["vmid"]))
    except KeyError:
        continue

if __name__ == "__main__":
    app.run(debug=True, port=5000)
