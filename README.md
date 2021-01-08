# CvePush
2021年1月8日更新：
优化了推送代码，实现自动化推送
微信推送：
需要自己注册一个企业微信，并取得机器人的key，类似这样的格式
“
wx_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=********-****-****-****-0*********7"
”
将key填入config中的key值
具体获取方式看企业微信使用手册
https://work.weixin.qq.com/api/doc/90000/90136/91770

邮箱推送：
根据配置文件，设置好邮箱相关参数即可
