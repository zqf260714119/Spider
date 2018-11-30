import logging
import sys


class Logger:
    # 创建日志对象时，使用默认日志格式
    def __init__(self):
        self.logger=logging.getLogger() #创建日志对象
        self.formatter =self.formatter()
        self.log_setlevel()

    def log_setlevel(self):
        self.logger.setLevel(logging.DEBUG)

    # 创建文件输出流
    def file_handler(self,filename,formatter=None):
        fh = logging.FileHandler(filename)  # 创建一个文件输出流；
        fh.setLevel(logging.DEBUG)  # 定义文件输出流的告警级别；
        if formatter ==None:
            formatter = self.formatter()
            # 设置输出到文件的格式
            fh.setFormatter(formatter)
        else:
            fh.setFormatter(formatter)
        return fh

    # 创建控制台输出流
    def console_handler(self,formatter=None):
        ch = logging.StreamHandler()  # 创建一个屏幕输出流；
        ch.setLevel(logging.DEBUG)  # 定义屏幕输出流的告警级别；
        # 设置输出到控制台格式
        if formatter ==None:
            formatter = self.formatter()
            # 设置输出到文件的格式
            ch.setFormatter(formatter)
        else:
            ch.setFormatter(formatter)
        return ch

    # 默认定义日志格式
    def formatter(self):

        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        return formatter

    # 设置输出格式
    def set_formatter(self,format):

        formatter = logging.Formatter(format)

        return formatter

    # 添加输出流
    def addhandler(self,handler):

        self.logger.addHandler(handler)

    # 输出格式内容
    def format(self):
        print(
"""
 format参数中可能用到的格式化串:
     1>.%(name)s
          Logger的名字
     2>.%(levelno)s
         数字形式的日志级别
     3>.%(levelname)s
         文本形式的日志级别
     4>.%(pathname)s
         调用日志输出函数的模块的完整路径名，可能没有
     5>.%(filename)s
         调用日志输出函数的模块的文件名
     6>.%(module)s
         调用日志输出函数的模块名
     7>.%(funcName)s
         调用日志输出函数的函数名
     8>.%(lineno)d
         调用日志输出函数的语句所在的代码行
     9>.%(created)f
         当前时间，用UNIX标准的表示时间的浮 点数表示
     10>.%(relativeCreated)d
         输出日志信息时的，自Logger创建以 来的毫秒数
     11>.%(asctime)s
         字符串形式的当前时间。默认格式是 “2003-07-08 16:49:45,896”。逗号后面的是毫秒
     12>.%(thread)d
         线程ID。可能没有
     13>.%(threadName)s
         线程名。可能没有
     14>.%(process)d
         进程ID。可能没有
     15>.%(message)s
         用户输出的消息
 """)


