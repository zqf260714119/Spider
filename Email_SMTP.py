
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
import smtplib

def _format_addr(s):
    name, addr = parseaddr(s)
    return formataddr((Header(name, 'utf-8').encode(), addr))

class Email:
    def __init__(self,from_addr,pwd,to_addr,smtp_server):
        # 发送方地址
        self.from_addr=from_addr
        # 邮箱授权码(SMTP)
        self.pwd=pwd
        # 接收方邮箱
        self.to_addr=to_addr
        # 使用的SMTP服务器地址
        self.smtp_server=smtp_server

        self.server = smtplib.SMTP(self.smtp_server, 25)
    # 登录功能
    def login_Email(self):

        self.server.login(self.from_addr, self.pwd)

        self.server.set_debuglevel(1)

    # msgtext传入邮件内容，error
    # 发送邮件
    def send_Email(self,msg_text,error):
        msg = MIMEText(msg_text, 'plain', 'utf-8')

        msg['From'] = _format_addr('公司日志报警<%s>' % self.from_addr)
        # 接受方ID
        msg['To'] = _format_addr('管理员 <%s>' % self.to_addr)
        # 标题
        msg['Subject'] = Header(error, 'utf-8').encode()
        # 发送
        self.server.sendmail(self.from_addr, [self.to_addr], msg.as_string())

    # 退出
    def quit(self):
        self.server.quit()





