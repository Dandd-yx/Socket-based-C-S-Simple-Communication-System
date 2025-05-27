# -*- coding: utf-8 -*-

import tkinter
import socket
import threading
import time
import json
import base64
import tkinter.font as tkFont
from tkinter import filedialog
from PIL import Image, ImageTk
import io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from tkinter import scrolledtext

win = tkinter.Tk()
win.title("客户端")
win.geometry("800x600+300+200")
ck = None
online = 0
isShutup = 0
# 定义全局变量用于存储加密密钥和初始化向量
KEY = None
IV = None
# 定义字体
label_font = tkFont.Font(family="Arial", size=12, weight="bold")  # 使用 Arial 字体，字号 12，加粗
entry_font = tkFont.Font(family="Helvetica", size=12)  # 使用 Helvetica 字体，字号 10
button_font = tkFont.Font(family="Arial", size=11, weight="bold")  # 按钮字体，字号 10，加粗

def show_emoji_window():
    """显示表情选择窗口"""
    emoji_window = tkinter.Toplevel(win)
    emoji_window.title("选择表情")
    emoji_window.geometry("560x260")  # 设置窗口大小

    # 定义一些UTF-8表情符号
    emojis = [
        "😊", "😂", "😍", "🤔", "😎", "😉", "😭", "😡", "😂", "😅",
        "🤩", "🥳", "😘", "🥰", "🤔", "🤔", "😴", "🤣", "😉", "😜",
        "👍", "👎", "👏", "🙌", "🤝", "✊", "✋", "👌", "👈", "👉",
        "🎉", "🎈", "🎁", "🎂", "🌜", "🌛", "🔥", "🌈", "🌞", "🌟",
        "🌷", "🍉", "🍊", "🍎", "💯", "👀", "🍒", "💖", "🐶", "🐹",
    ]
    def insert_emoji(emoji):
        """将选中的表情插入到消息输入框中"""
        current_text = esend.get()
        esend.set(current_text + emoji)

    # 创建按钮以显示表情，并绑定点击事件
    for i, emoji in enumerate(emojis):
        button = tkinter.Button(
            emoji_window,
            text=emoji,
            font=("Arial", 16),  # 字体大小调整为16号
            command=lambda e=emoji: insert_emoji(e),
            width=3,  # 设置按钮宽度，使表情符号居中显示
            height=1  # 设置按钮高度
        )
        button.grid(row=i // 10, column=i % 10, padx=5, pady=5)  # 每行10个表情，共5行


def show_guide():
    """显示用户手册"""
    # 创建顶层窗口
    guide_window = tkinter.Toplevel(win)
    guide_window.title("使用手册")
    guide_window.geometry("550x400")  # 设置窗口大小

    # 添加滚动文本框以显示指南内容
    guide_text = scrolledtext.ScrolledText(guide_window, wrap=tkinter.WORD, width=70, height=22)
    guide_text.grid(row=0, column=0, padx=10, pady=10)

    try:
        with open('./textfile/guide.txt', 'r', encoding='utf-8') as file:
            content = file.read()
            guide_text.insert(tkinter.INSERT, content)
    except FileNotFoundError:
        guide_text.insert(tkinter.INSERT, "未能找到帮助文件。")

    # 禁止编辑文本框中的内容
    guide_text.config(state=tkinter.DISABLED)

def encrypt_message(message):
    """加密消息"""
    if KEY is None or IV is None:
        return message  # 如果密钥未设置，则不加密消息
    
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode('utf-8')) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(encrypted_message):
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
    
def getInfo():
    global online, isShutup, KEY, IV # online对应在线状态，isShutup对应禁言状态
    while True:
        data = ck.recv(2048)  # 用于接受服务器发送的信息
        message = data.decode("utf-8")
        if message.startswith("<系统>密钥已发送:"):
            # 提取并解析密钥和初始化向量
            key_iv_data = message.split(": ")[1].strip()
            key_iv_bytes = base64.b64decode(key_iv_data)
            KEY = key_iv_bytes[:32]
            IV = key_iv_bytes[32:]
            continue
        # 接收消息时同步获取系统时间并显示在消息显示框上
        text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n')
        text.insert(tkinter.INSERT, message)
        #如果不是系统消息，则额外输出解密后的消息
        if not message.startswith("<系统>") and message != "":
            decrypted_message = decrypt_message(message.split(":")[1].strip())
            text.insert(tkinter.INSERT, "解密后: " + decrypted_message + "\n")

        if data.decode("utf-8") == "<系统>服务器正在关闭，所有用户已断开连接。\n":
            online = 0
        if data.decode("utf-8") == "<系统>您已被禁言，":
            isShutup = 1
        if data.decode("utf-8") == "<系统>您的禁言被解除或已结束。\n":
            isShutup = 0
        if data.decode("utf-8") == "<系统>登录成功! 欢迎！\n":
            online = 1
        if data.decode("utf-8") == "<系统>您已成功注销账户。\n":
            online = 0

def connectServer(num):
    global ck, online  # 全局
    ipStr = eip.get()   # 目标服务器IP
    self_ip = socket.gethostbyname(socket.gethostname())    # 本机IP地址
    portStr = eport.get()   # 选择的端口
    userStr = euser.get()   # 登录用户名
    password = epassWord.get()  # 密码
    if portStr.isspace() or portStr == "":  # 默认端口 88
        portStr = 88
    if userStr.isspace() or userStr == "" or ipStr.isspace() or ipStr == "" or password.isspace() or password == "":
        text.insert(tkinter.INSERT, "<系统>请完整填写登录信息！\n")
    else:
        if num == "2" and online == 0:  # num == 2对应“注销”
            text.insert(tkinter.INSERT, "<系统>您尚未登录！\n")
        else:
            if num == "1":  # num == 1对应“注册”
                online = 0
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # socked所准守ipv4相关协议
            client.connect((ipStr, int(portStr)))  # 连接服务器，注意参数为服务器IP：“ipStr”
            sendStr = userStr + ":" + password + ":" + num + ":" + self_ip  # 这里传输的是本机IP
            client.send(sendStr.encode("utf-8"))
            ck = client
            t = threading.Thread(target=getInfo)
            t.start()

def sendMail():
    friend = None
    friend = efriend.get()  # 信息发送的目标
    sendStr = esend.get()   # 消息
    if online == 0:
        text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                    + '<系统>您未连接至服务器，消息无法发送\n')
    elif isShutup == 1:
        text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                    + '<系统>您已被禁言，无法发送消息\n')
    else:
        # 加载自动回复问题
        with open('./textfile/robot.json', 'r', encoding='utf-8') as f_r:
            qa_pairs = json.load(f_r)
            # 检查消息是否是自动回复设置中的问题
        if sendStr in qa_pairs:
            answer = qa_pairs[sendStr]
            text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                        + '<系统>自动回复：' + answer + '\n')
            # 不发送给服务器
            return
        # 自己发出的消息服务器不会重发会给自己，所以在客户端定义界面显示自己发送的消息
        if friend != "" and friend != euser.get():
            text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                        + '我对' + friend + '说：' + sendStr + '\n')
        elif friend == euser.get():
            text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                        + '我对自己说：' + sendStr + '\n')
        else:
            text.insert(tkinter.INSERT, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()) + '\n'
                        + '我(群发）说：' + sendStr + '\n')
        # 加密消息
        encrypted_sendStr = encrypt_message(sendStr)
        # 将消息发给服务器，添加“：”分割是要方便服务器端用正则表达式分出要发送的用户名和要发送的消息
        sendStr = friend + ":" + encrypted_sendStr + "\n"
        ck.send(sendStr.encode("utf-8"))


def Exit():
    global online
    # 在服务器端定义了接收到“exit”就判定该用户下线，并删掉该用户的资料
    sendStr = "exit" + ":" + ""
    ck.send(sendStr.encode("utf-8"))
    if online == 1:
        text.insert(tkinter.INSERT, "<系统>您已下线，如需接收信息请重新登录。\n")
        online = 0
    else:
        text.insert(tkinter.INSERT, "<系统>尚未连接至服务器。\n")

# 配置所有行和列的权重，以使它们能够随窗口大小改变而扩展
for i in range(8):  # 设置行权重
    win.grid_rowconfigure(i, weight=1)
for i in range(3):  # 设置列权重
    win.grid_columnconfigure(i, weight=1)

# 创建并布置组件，同时为每个组件添加 padding
labelUser = tkinter.Label(win, text="用户名", font=label_font)
labelUser.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

euser = tkinter.StringVar()
entryUser = tkinter.Entry(win, textvariable=euser, font=entry_font)
entryUser.grid(row=0, column=1, sticky='ew', padx=5, pady=5)

labelPassword = tkinter.Label(win, text="密码", font=label_font)
labelPassword.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)

epassWord = tkinter.StringVar()
entryPassword = tkinter.Entry(win, textvariable=epassWord, show="*")  # 使用 show 参数隐藏密码输入
entryPassword.grid(row=1, column=1, sticky='ew', padx=5, pady=5)

labelIp = tkinter.Label(win, text="服务器ip", font=label_font)
labelIp.grid(row=2, column=0, sticky='nsew', padx=5, pady=5)

eip = tkinter.StringVar()
entryIp = tkinter.Entry(win, textvariable=eip, font=entry_font)
entryIp.grid(row=2, column=1, sticky='ew', padx=5, pady=5)

labelPort = tkinter.Label(win, text="端口(默认:88)", font=label_font)
labelPort.grid(row=3, column=0, sticky='nsew', padx=5, pady=5)

eport = tkinter.StringVar()
entryPort = tkinter.Entry(win, textvariable=eport, font=entry_font)
entryPort.grid(row=3, column=1, sticky='ew', padx=5, pady=5)

button_register = tkinter.Button(win, text="注册", command=lambda: connectServer("1"), font=button_font)
button_register.grid(row=0, column=2, sticky='nsew', padx=5, pady=5)

button_login = tkinter.Button(win, text="登录", bg="cyan", command=lambda: connectServer("0"), font=button_font)
button_login.grid(row=1, column=2, sticky='nsew', padx=5, pady=5)

button_logoff = tkinter.Button(win, text="注销", command=lambda: connectServer("2"), font=button_font)
button_logoff.grid(row=3, column=2, sticky='nsew', padx=5, pady=5)

text = tkinter.Text(win, height=18, width=40, font=entry_font)
labeltext = tkinter.Label(win, text="显示消息", font=label_font)
labeltext.grid(row=5, column=0, sticky='nsew', padx=5, pady=5)
text.grid(row=5, column=1, sticky='nsew', padx=5, pady=5)

esend = tkinter.StringVar()
labelesend = tkinter.Label(win, text="发送的消息", font=label_font)
labelesend.grid(row=6, column=0, sticky='nsew', padx=5, pady=5)
entrySend = tkinter.Entry(win, textvariable=esend, font=entry_font)
entrySend.grid(row=6, column=1, sticky='ew', padx=5, pady=5)

efriend = tkinter.StringVar()
labelefriend = tkinter.Label(win, text="发给谁", font=label_font)
labelefriend.grid(row=7, column=0, sticky='nsew', padx=5, pady=5)
entryFriend = tkinter.Entry(win, textvariable=efriend, font=entry_font)
entryFriend.grid(row=7, column=1, sticky='ew', padx=5, pady=5)

button_send = tkinter.Button(win, text="发送", bg="light green", command=sendMail, font=button_font)
button_send.grid(row=6, column=2, sticky='nsew', padx=5, pady=5)

button_offline = tkinter.Button(win, text="下线", bg="pink", command=Exit, font=button_font)
button_offline.grid(row=2, column=2, sticky='nsew', padx=5, pady=5)

button_guide = tkinter.Button(win, text="手册", command=show_guide, font=button_font)
button_guide.grid(row=7, column=2, sticky='nsew', padx=5, pady=5)

button_emoji = tkinter.Button(win, text="表情", command=show_emoji_window, font=button_font)
button_emoji.grid(row=8, column=2, sticky='nsew', padx=5, pady=5)

win.mainloop()
