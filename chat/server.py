# -*- coding: utf-8 -*-

import tkinter
import socket, threading
import os
import json
import time
import base64
import tkinter.font as tkFont
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tkinter import filedialog, messagebox


win = tkinter.Tk()  # 创建主窗口
win.title('服务器')
win.geometry("800x500+200+200")  # 宽x长+x坐标+y坐标
users = {}  # 用户字典，也可以连接数据库
users_l = {}
users_p = {}
CHAT_HISTORY_FILE = "./textfile/chat_history.json" # 全局变量，用于存储聊天记录
chat_history = []
# 定义一个全局变量用于存储加密密钥
KEY = os.urandom(32)  # AES-256需要32字节的密钥
IV = os.urandom(16)   # AES需要16字节的初始化向量
# 用户消息计数字典
user_message_counts = {}
# 读取用户数据
size = os.path.getsize("./textfile/password.json")
if size != 0:
    with open('./textfile/password.json', 'r', encoding='utf-8') as f:
        users_p = json.load(f)
# 定义字体
label_font = tkFont.Font(family="Arial", size=12, weight="bold")  # 使用 Arial 字体，字号 12，加粗
entry_font = tkFont.Font(family="Helvetica", size=12)  # 使用 Helvetica 字体，字号 10
button_font = tkFont.Font(family="Arial", size=11, weight="bold")  # 按钮字体，字号 10，加粗

def edit_guide():
    """打开新窗口以编辑指南文件"""
    try:
        # 打开文件读取内容
        with open('./textfile/guide.txt', 'r', encoding='utf-8') as file:
            content = file.read()
    except FileNotFoundError:
        content = "未能找到帮助文件。\n"

    # 创建顶层窗口
    editor_window = tkinter.Toplevel(win)
    editor_window.title("编辑手册")
    editor_window.geometry("550x400")  # 设置窗口大小

    # 添加 Text 小部件以编辑指南内容
    text_editor = tkinter.Text(editor_window, wrap=tkinter.WORD, undo=True)
    text_editor.insert(tkinter.END, content)
    text_editor.pack(expand=True, fill=tkinter.BOTH)

    def save_changes():
        """保存对指南文件的修改"""
        try:
            new_content = text_editor.get(1.0, tkinter.END)
            with open('./textfile/guide.txt', 'w', encoding='utf-8') as file:
                file.write(new_content)
            messagebox.showinfo("保存成功", "您的更改已成功保存。")
        except Exception as e:
            messagebox.showerror("保存失败", f"保存时发生错误: {str(e)}")

    # 添加保存按钮
    save_button = tkinter.Button(editor_window, text="保存", command=save_changes)
    save_button.pack(pady=5)

def get_key_iv():
    """获取密钥和初始化向量"""
    return KEY, IV

def decrypt_message(encrypted_message): # 将聊天记录以明文方式保存
    """解密消息"""
    if KEY is None or IV is None:
        return encrypted_message  # 如果密钥未设置，则不解密消息
    
    try:
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
        decryptor = cipher.decryptor()
        
        encrypted_data = base64.b64decode(encrypted_message)
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return decrypted_data.decode('utf-8')
    except Exception as e:
        return f"解密失败: {str(e)}"
    
# 检查并初始化聊天记录文件
if not os.path.exists(CHAT_HISTORY_FILE) or os.path.getsize(CHAT_HISTORY_FILE) == 0:
    with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(chat_history, f, ensure_ascii=False, indent=4)
else:
    with open(CHAT_HISTORY_FILE, 'r', encoding='utf-8') as f:
        chat_history = json.load(f)

def save_chat_record(sender, receiver, message):
    global chat_history
    record = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        "sender": sender,
        "receiver": receiver,
        "message": message
    }
    chat_history.append(record)
    with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as f:
        json.dump(chat_history, f, ensure_ascii=False, indent=4)

def clear_chat_history():
    """清空 chat_history.json 文件的内容"""
    try:
        # 如果文件存在，则打开并清空
        if os.path.exists(CHAT_HISTORY_FILE):
            with open(CHAT_HISTORY_FILE, 'w', encoding='utf-8') as file:
                json.dump([], file)  # 清空为一个空列表
            print("聊天记录已成功清空。")
        else:
            print("聊天记录文件不存在，无需清空。")
    except Exception as e:
        print(f"清空聊天记录时出错: {e}")

def show_message_statistics():
    """显示每个用户发送消息的次数，并找到发送消息最多的用户"""
    stats_window = tkinter.Toplevel(win)
    stats_window.title("聊天数据统计")
    stats_window.geometry("400x350+200+20")  # 增加窗口高度以适应新的文本

    text_widget = tkinter.Text(stats_window, height=20, width=50)
    scrollbar = tkinter.Scrollbar(stats_window, command=text_widget.yview)

    text_widget.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")

    text_widget.config(state=tkinter.NORMAL)
    text_widget.delete(1.0, tkinter.END)

    if not user_message_counts:
        text_widget.insert(tkinter.END, "暂无聊天记录。\n")
    else:
        # 找到发送消息次数最多的用户
        max_user = max(user_message_counts, key=user_message_counts.get)
        max_count = user_message_counts[max_user]

        for user, count in user_message_counts.items():
            text_widget.insert(tkinter.END, f"用户: {user}, 发送消息次数: {count}\n")

        # 添加祝贺语
        text_widget.insert(tkinter.END, f"\n恭喜{max_user}成为本次聊天室的龙王！\n")

    text_widget.config(state=tkinter.DISABLED)

    stats_window.grid_rowconfigure(0, weight=1)
    stats_window.grid_columnconfigure(0, weight=1)

def run(connect, addrss):   # address0：发送地的IP、
    # 接收客户端登陆的信息
    userdatab = connect.recv(2048)  # 关于connect.recv()，参数默认值是1024，为了测试改成2048
    userdata = userdatab.decode("utf-8")
    datalist = userdata.split(":")  # 以冒号分割接收的消息
    username = datalist[0]  # 提取用户名用于计数

    if datalist[2] == "0": # 对应“登录”按钮
        if datalist[0] in users_p:
            if users_p[datalist[0]] == datalist[1]:
                # 储存用户的信息
                users[datalist[0]] = connect
                users_l[datalist[0]] = 1
                # 发送密钥和初始化向量
                key_iv_data = base64.b64encode(KEY + IV).decode('utf-8')
                connect.send(f"<系统>密钥已发送: {key_iv_data}\n".encode("utf-8"))
                # 在连接显示框中显示是否连接成功
                printStr = "" + "用户" + datalist[0] + "连接：ip=" + datalist[3] + "\n"
                text.insert(tkinter.INSERT, printStr)
                time.sleep(1)
                printStr = "当前在线的用户：" + str(list(users.keys())) + "\n"
                text.insert(tkinter.INSERT, printStr)
                # 向当前登录的客户端反馈登录信息并提供在线用户列表
                printStr = "<系统>登录成功! 欢迎！\n"
                connect.send(printStr.encode("utf"))
                printStr = "<系统>当前在线的好友有：" + str(list(users.keys())) + "\n"
                connect.send(printStr.encode("utf"))
                # 向所有在线的客户端反馈新的好友登录信息并提供在线用户列表
                printStr = "<系统>欢迎" + datalist[0] + "上线(IP地址：" + addrss[0] + ")\n" + "当前在线的好友有：" + str(list(users.keys())) + "\n"
                for key in users:
                    if key != datalist[0]:
                        users[key].send(printStr.encode("utf"))
            else:
                connect.send("<系统>密码错误，登录失败！\n".encode("utf"))

        else:
            connect.send("<系统>用户名不存在，登录失败！\n".encode("utf"))

    elif datalist[2] == "1":
        if datalist[0] not in users_p:
            users_p[datalist[0]] = datalist[1]

            with open('./textfile/password.json', 'w', encoding='utf-8') as f:
                json.dump(users_p, f, ensure_ascii=False, indent=4)

            connect.send("<系统>注册成功！\n".encode("utf"))
            text.insert(tkinter.INSERT, "IP: " + addrss[0] + " 注册新账号：" + datalist[0] + "\n")
        else:
            connect.send("<系统>用户名已存在！\n".encode("utf"))

    elif datalist[2] == "2":
        del users_p[datalist[0]]
        with open('./textfile/password.json', 'w', encoding='utf-8') as f:
            json.dump(users_p, f, ensure_ascii=False, indent=4)
        connect.send("<系统>您已成功注销账户。\n".encode("utf-8"))

        del users[datalist[0]]
        text.insert(tkinter.INSERT, "用户" + datalist[0] + "已注销账户。\n")

    while True:
        rData = connect.recv(2048)
        dataStr = rData.decode("utf-8")
        # 分割字符串得到所要发送的用户名和客户端所发送的信息
        infolist = dataStr.split(":")

        if datalist[0] in users:
            if users_l[datalist[0]] == 1:
                if infolist[0] == "":
                    for key in users:
                        if key != datalist[0]:
                            users[key].send((datalist[0] + "说（群发）:" + infolist[1]).encode("utf"))
                            save_chat_record(datalist[0], "群发", decrypt_message(infolist[1]))
                            # 更新消息计数
                            user_message_counts[username] = user_message_counts.get(username, 0) + 1
                elif infolist[0] == "exit":
                    del users[datalist[0]]
                    printStr = "" + "用户" + datalist[0] + "下线\n"
                    text.insert(tkinter.INSERT, printStr)
                    for key in users:
                        printStr = "<系统>用户" + datalist[0] + "已下线\n" + "当前在线的好友有：" + str(
                            list(users.keys())) + "\n"
                        users[key].send(printStr.encode("utf"))
                else:
                    if infolist[0] in users and infolist[0] != datalist[0]:
                        users[infolist[0]].send((datalist[0] + "说(私聊):" + infolist[1]).encode("utf"))
                        save_chat_record(datalist[0], infolist[0], decrypt_message(infolist[1]))
                        # 更新消息计数
                        user_message_counts[username] = user_message_counts.get(username, 0) + 1
                    elif infolist[0] not in users:
                        printStr = "<系统>用户" + infolist[0] + "不在线，上条消息未发出" + "\n"
                        connect.send(printStr.encode("utf"))


# 界面启动按钮连接的函数
def startSever():
    # 启用一个线程开启服务器
    s = threading.Thread(target=start)
    s.start()
    user_message_counts.clear()

# 开启线程


def start():
    # 从输入端中获取ip和端口号
    ipStr = eip.get()
    portStr = eport.get()
    # 为方便测试，加入一键部署服务器端，项目完成后酌情保留
    if portStr.isspace() or portStr == "":
        portStr = 88
    if ipStr.isspace() or ipStr == "":
        ipStr = socket.gethostbyname(socket.gethostname())
    # socket嵌套字TCP的ipv4和相关协议
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 绑定ip和端口号
    server.bind((ipStr, int(portStr)))
    # 设置监听和连接的最大的数量
    server.listen(10)
    # 服务器启动信息显示在信息窗口中
    printStr = "服务器启动成功！ip=" + str(ipStr) + "\n"    #+ "，端口：" + str(portStr) + "\n" dyx:保留这一段会导致特定时刻的乱序输出
    text.insert(tkinter.INSERT, printStr)
    # 模拟服务器要一直运行所以使用死循环
    while True:
        # 接受所连接的客户端的信息
        connect, addrss = server.accept()
        # 每连接一个客户端就开启一个线程
        t = threading.Thread(target=run, args=(connect, addrss))
        t.start()


def closeServer():
    # 通知所有用户服务器正在关闭
    for user in users:
        users[user].send("<系统>服务器正在关闭，已断开连接。\n".encode("utf"))

    for user in users:
        users[user].close()

        # 清理全局变量
    users.clear()
    users_l.clear()
    with open('./textfile/password.json', 'w', encoding='utf-8') as f:
        json.dump(users_p, f, ensure_ascii=False, indent=4)
    users_p.clear()

    os._exit(0)


def Switch(name):
    global users_l

    if users_l[name] == 0:
        users_l[name] = 1
        users[name].send("<系统>您的禁言被解除或已结束。\n".encode("utf"))


def SetShutUp():
    def ShutUp():
        global users_l
        isStr = 0
        if name.get().isspace() or name.get() == "":
            text.insert(tkinter.INSERT, "未输入所需禁言用户名。\n")
        elif name.get() in users_l:
            if users_l[name.get()] == 0:
                text.insert(tkinter.INSERT, "用户" + name.get() + "已被禁言。\n")
            else:
                if time.get().isspace() or time.get() == "":
                    text.insert(tkinter.INSERT, "未输入禁言时长，默认禁言15分钟。\n")
                    _time = 15
                    time1 = str(_time)

                else:
                    try:
                        _time = float(time.get())
                    except ValueError:
                        text.insert(tkinter.INSERT, "请输入正确的时间。\n")
                        isStr = 1
                    time1 = time.get()

                if isStr == 0:
                    users_l[name.get()] = 0
                    text.insert(tkinter.INSERT, "用户" + name.get() + "禁言成功。\n")
                    sendStr = "禁言时长为：" + time1 + "分钟。\n"
                    users[name.get()].send("<系统>您已被禁言，".encode("utf-8"))
                    users[name.get()].send("<系统>".encode("utf-8") + sendStr.encode("utf-8"))

                    # 设置定时器来调用 Switch 函数
                    def delayed_switch():
                        Switch(name.get())

                    # 使用 threading.Timer 来定时执行 delayed_switch
                    timer = threading.Timer(_time * 60, delayed_switch)
                    timer.start()
        else:
            text.insert(tkinter.INSERT, "该用户不存在！\n")

        sub_win.destroy()

    def ShutUp_free():
        if name.get().isspace() or name.get() == "":
            text.insert(tkinter.INSERT, "未输入所需禁言用户名。\n")
        elif name.get() in users_l:
            if users_l[name.get()] == 1:
                text.insert(tkinter.INSERT, "用户" + name.get() + "未被禁言。\n")
            else:
                Switch(name.get())
                text.insert(tkinter.INSERT, "用户" + name.get() + "解禁成功！\n")
        else:
            text.insert(tkinter.INSERT, "该用户不存在！\n")

        sub_win.destroy()

    sub_win = tkinter.Toplevel()    # 窗口置顶
    sub_win.title("禁言控制台")
    sub_win.geometry("300x100+200+20")

    Labelname = (tkinter.Label(sub_win, text="输入用户名")
                 .grid(row=0, column=0))
    name = tkinter.Variable()

    Labeltime = (tkinter.Label(sub_win, text="禁言时长(分钟)")
                 .grid(row=1, column=0))
    time = tkinter.Variable()

    entry_name = (tkinter.Entry(sub_win, textvariable=name)
                  .grid(row=0, column=1))
    entry_time = (tkinter.Entry(sub_win, textvariable=time)
                  .grid(row=1, column=1))

    button_shutup = (tkinter.Button(sub_win, text="禁言", command=ShutUp)
                     .grid(row=0, column=2))
    button_free = (tkinter.Button(sub_win, text="解禁", command=ShutUp_free)
                   .grid(row=1, column=2))

    sub_win.mainloop()

def viewChatHistory():
    history_window = tkinter.Toplevel(win)
    history_window.title("聊天记录")
    history_window.geometry("600x400+200+20")

    try:
        with open(CHAT_HISTORY_FILE, 'r', encoding='utf-8') as f:
            chat_history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        chat_history = []

    # 创建搜索框和按钮
    search_label = tkinter.Label(history_window, text="搜索内容:")
    search_label.grid(row=0, column=0, padx=10, pady=10)

    search_entry = tkinter.Entry(history_window, width=50)
    search_entry.grid(row=0, column=1, padx=10, pady=10)

    def search_history():
        search_text = search_entry.get()
        if not search_text:
            return

        # 清空文本框
        text_widget.config(state=tkinter.NORMAL)
        text_widget.delete(1.0, tkinter.END)
        text_widget.config(state=tkinter.DISABLED)

        # 搜索并显示匹配的聊天记录
        for entry in chat_history:
            entry_str = json.dumps(entry, ensure_ascii=False)
            if search_text.lower() in entry_str.lower():
                text_widget.config(state=tkinter.NORMAL)
                # text_widget.insert(tkinter.END, f"ID: {entry['id']}\n")
                text_widget.insert(tkinter.END, f"时间: {entry['timestamp']}\n")
                text_widget.insert(tkinter.END, f"发送者: {entry['sender']}\n")
                text_widget.insert(tkinter.END, f"接收者: {entry['receiver']}\n")
                text_widget.insert(tkinter.END, f"消息: {entry['message']}\n")
                text_widget.config(state=tkinter.DISABLED)

    search_button = tkinter.Button(history_window, text="搜索", command=search_history)
    search_button.grid(row=0, column=2, padx=10, pady=10)

    button_clear_history = (tkinter.Button(history_window, text="清空聊天记录", command=clear_chat_history)
                            .grid(row=2, column=1))

    # 创建文本框和滚动条
    text_widget = tkinter.Text(history_window, height=20, width=80)
    scrollbar = tkinter.Scrollbar(history_window, command=text_widget.yview)

    # 使用 grid 布局管理器
    text_widget.grid(row=1, column=0, columnspan=3, sticky="nsew")
    scrollbar.grid(row=1, column=3, sticky="ns")

    # 设置文本框只读
    text_widget.config(state=tkinter.DISABLED)

    # 初始化显示所有聊天记录
    text_widget.config(state=tkinter.NORMAL)
    text_widget.delete(1.0, tkinter.END)
    for entry in chat_history:
        entry_str = json.dumps(entry, ensure_ascii=False)
        # text_widget.insert(tkinter.END, f"ID: {entry['id']}\n")
        text_widget.insert(tkinter.END, f"时间: {entry['timestamp']}\n")
        text_widget.insert(tkinter.END, f"发送者: {entry['sender']}\n")
        text_widget.insert(tkinter.END, f"接收者: {entry['receiver']}\n")
        text_widget.insert(tkinter.END, f"消息: {entry['message']}\n")
    text_widget.config(state=tkinter.DISABLED)

    # 设置窗口的行和列权重，使文本框和滚动条能够扩展
    history_window.grid_rowconfigure(1, weight=1)
    history_window.grid_columnconfigure(0, weight=1)
    history_window.grid_columnconfigure(1, weight=1)
    history_window.grid_columnconfigure(2, weight=1)

def SetAutoAnswer():
    def setans():
        # 获取问题和回答并存储到字典中
        question = qs.get().strip()
        answer = ans.get().strip()
        if not question or not answer:
            text.insert(tkinter.INSERT, "问题或回答不能为空！\n")
            return

        with open('./textfile/robot.json', 'r', encoding='utf-8') as f_r:
            try:
                qa_pairs = json.load(f_r)
            except json.JSONDecodeError:
                qa_pairs = {}

        qa_pairs[question] = answer  # 将问题和回答添加到字典中

        with open('./textfile/robot.json', 'w', encoding='utf-8') as f_w:
            json.dump(qa_pairs, f_w, ensure_ascii=False, indent=4)

        text.insert(tkinter.INSERT, "自动回复设置成功。\n")
    def unsetans():
        question = qs.get().strip()

        if not question:
            text.insert(tkinter.INSERT, "请提供要取消的问题！\n")
            return

        with open('./textfile/robot.json', 'r', encoding='utf-8') as f_r:
            qa_pairs = json.load(f_r)

        if question in qa_pairs:
            del qa_pairs[question]

            with open('./textfile/robot.json', 'w', encoding='utf-8') as f_w:
                json.dump(qa_pairs, f_w, ensure_ascii=False, indent=4)

            text.insert(tkinter.INSERT, "自动回复取消成功。\n")
        else:
            text.insert(tkinter.INSERT, "该问题不存在。\n")

    robot_table = tkinter.Toplevel()
    robot_table.title("自动回复设置")
    robot_table.geometry("300x100+200+20")
    label_qs = (tkinter.Label(robot_table, text="设置问题", width=10, height=2)
                .grid(row=0, column=0))
    qs = tkinter.Variable()
    entry_qs = (tkinter.Entry(robot_table, textvariable=qs)
                .grid(row=0, column=1))

    label_ans = (tkinter.Label(robot_table, text="设置回答")
                 .grid(row=1, column=0))
    ans = tkinter.Variable()
    entry_ans = (tkinter.Entry(robot_table, textvariable=ans)
                 .grid(row=1, column=1))
    button_set = (tkinter.Button(robot_table, text="确认设定", command=setans)
                  .grid(row=2, column=0))
    button_unset = (tkinter.Button(robot_table, text="取消设定", command=unsetans)
                    .grid(row=2, column=1))

    robot_table.mainloop()

# 配置行和列的权重，使得特定行和列能够随窗口大小改变而扩展
for i in range(8):  # 设置行权重
    win.grid_rowconfigure(i, weight=1)
for i in range(3):  # 设置列权重
    win.grid_columnconfigure(i, weight=1)

# 创建并布置组件，同时为每个组件添加 padding
labelIp = tkinter.Label(win, text='ip (default: self.ip)', width=20, font=label_font)
labelIp.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)  # 添加外部填充

eip = tkinter.StringVar()
entryIp = tkinter.Entry(win, textvariable=eip, width=40, fg='red')
entryIp.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

labelPort = tkinter.Label(win, text='port (default: 88)', width=20, font=label_font)
labelPort.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

eport = tkinter.StringVar()
entryPort = tkinter.Entry(win, textvariable=eport, width=40, fg='red')
entryPort.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

button = tkinter.Button(win, text="启动", command=startSever, bg="light green", font=button_font)
button.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)

text = tkinter.Text(win, height=20, width=50, font=entry_font)
labeltext = tkinter.Label(win, text='服务器消息', font=label_font)
labeltext.grid(row=3, column=0, sticky='nsew', padx=5, pady=5)
text.grid(row=3, column=1, sticky='nsew', padx=5, pady=5)

button2 = tkinter.Button(win, text="关闭", command=closeServer)
button2.grid(row=1, column=2, sticky='nsew', padx=5, pady=5)

button3 = tkinter.Button(win, text="禁言控制", command=SetShutUp)
button3.grid(row=3, column=2, sticky='nsew', padx=25, pady=25)

button_robot = tkinter.Button(win, text="自动回复设置", command=SetAutoAnswer)
button_robot.grid(row=4, column=1, sticky='nsew', padx=5, pady=5)

button_view_history = tkinter.Button(win, text="查看聊天记录", command=viewChatHistory)
button_view_history.grid(row=5, column=1, sticky='nsew', padx=5, pady=5)

button_stats = tkinter.Button(win, text="聊天数据统计", command=show_message_statistics)
button_stats.grid(row=6, column=1, sticky='nsew', padx=5, pady=5)

button_editguide = tkinter.Button(win, text="修改用户手册", command=edit_guide)
button_editguide.grid(row=7, column=1, sticky='nsew', padx=5, pady=5)

win.mainloop()
