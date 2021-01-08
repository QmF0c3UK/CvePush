#-*- coding:utf-8 -*-
banner = """
        888888ba             dP                     
        88    `8b            88                     
       a88aaaa8P' .d8888b. d8888P .d8888b. dP    dP 
        88   `8b. 88'  `88   88   Y8ooooo. 88    88 
        88    .88 88.  .88   88         88 88.  .88 
        88888888P `88888P8   dP   `88888P' `88888P' 
   ooooooooooooooooooooooooooooooooooooooooooooooooooooo 
                @time:2021/01/07 cvealert.py
                C0de by NebulabdSec - @batsu                  
 """
print(banner)
import configparser
import smtplib
from email.mime.text import MIMEText
import random
import datetime
import httpx
import time
import requests
import json

config_dict = {}
data_list = []  # 准备存取数据
proxies = {'http': "http://127.0.0.1:8080",
           'https': "http://127.0.0.1:8001"
           }

url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'


def get_ua():
    first_num = random.randint(55, 62)
    third_num = random.randint(0, 3200)
    fourth_num = random.randint(0, 140)
    os_type = [
        '(Windows NT 6.1; WOW64)', '(Windows NT 10.0; WOW64)', '(X11; Linux x86_64)',
        '(Macintosh; Intel Mac OS X 10_12_6)'
    ]
    chrome_version = 'Chrome/{}.0.{}.{}'.format(first_num, third_num, fourth_num)

    ua = ' '.join(['Mozilla/5.0', random.choice(os_type), 'AppleWebKit/537.36',
                   '(KHTML, like Gecko)', chrome_version, 'Safari/537.36']
                  )
    return ua


headers = {
    'User-Agent': get_ua(),
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language': 'zh,en;q=0.5',
    'Content-Type': 'application/json',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close',
    'Upgrade-Insecure-Requests': '1',
}


def get_config(mail_setting):
    try:
        config = configparser.ConfigParser()
        config.read("config.ini", encoding='UTF-8')
        data = {
            'mail_setting': int(mail_setting),
            'care': int(config.get('Config', 'care')),
            'vul_like': config.get('Config', 'vul_like').split(','),
            'risk_like': config.get('Config', 'risk_like').split(',')
        }
        config_dict.update(data)
        if mail_setting == 0:#更新微信企业的key值
            data = {'key': config.get('Wxqy_config', 'key')}
            config_dict.update(data)
        elif mail_setting == 1:# 更新邮件推送的值
            data = {
                'smtp_server': config.get('Mail_config', 'smtp_server'),
                'smtp_port': config.get('Mail_config', 'smtp_port'),
                'mail_addr': config.get('Mail_config', 'mail_addr'),
                'auth_code': config.get('Mail_config', 'auth_code'),
                'mail_to': config.get('Mail_config', 'mail_to'),
                'Recipient': config.get('Mail_config', 'Recipient').split(',')
            }
            config_dict.update(data)
        # print(config_dict)
    except Exception as e:
        exit('[+]获取配置文件失败:%s' % str(e))


def get_cve():
    # 时间比我们晚，#取三天前的漏洞才有cvss评分
    today = datetime.date.today()
    pubStartDate = str(today - datetime.timedelta(days=3)) + 'T00:00:00:000 UTC-05:00'
    pubEndtDate = str(today - datetime.timedelta(days=2)) + 'T00:00:00:000 UTC-05:00'
    params = {
        'pubStartDate': pubStartDate,
        'pubEndDate': pubEndtDate,
        'resultsPerPage': 2000
    }
    try:
        if config_dict["care"] == 0:
            for risk in config_dict["risk_like"]:
                for vul in config_dict["vul_like"]:
                    params.update({'cvssV3Severity': risk, 'keyword': vul})
                    with httpx.Client(headers=headers, params=params, verify=False) as client:
                        res = client.get(url).json()
                        print(res['totalResults'])
                        insert_data(risk, res)
        elif config_dict["care"] == 1:
            for risk in config_dict["risk_like"]:
                params.update({'cvssV3Severity': risk})
                with httpx.Client(headers=headers, params=params, verify=False) as client:
                    res = client.get(url).json()
                    print(res['totalResults'])
                    insert_data(risk, res)

        # print(data_list)
    except Exception as e:
        print("[-]1、兄弟,获取cve漏洞的时候报错了:%s" % e)
        get_cve()

def insert_data(risk,res):
    for i in range(res['totalResults']):
        cve_url = ''
        for j in range(len(res['result']['CVE_Items'][i]['cve']['references']['reference_data'])):
            cve_url =cve_url + "[漏洞参考链接%s](%s)\n" % (j, str(res['result']['CVE_Items'][i]['cve']['references']['reference_data'][j]['url']))
        requests_data = {
            'risk': risk,
            'CVE编号': res['result']['CVE_Items'][i]['cve']['CVE_data_meta']['ID'],
            '公开时间': res['result']['CVE_Items'][i]['publishedDate'][0:10],
            '漏洞描述': tranlate(res['result']['CVE_Items'][i]['cve']['description']['description_data'][0]['value']),
            '漏洞参考链接': cve_url
        }
        data_list.append(requests_data)


def tranlate(context):
    try:
        direction = "auto2zh"
        tranlate_url = "http://api.interpreter.caiyunai.com/v1/translator"
        token = "3975l6lr5pcbvidl6jl2"#建议使用自己的apikey
        payload = {
            "source": context,
            "trans_type": direction,
            "request_id": "demo",
            "detect": True,
        }
        headers = {
            'content-type': "application/json",
            'x-authorization': "token " + token,
        }
        response = requests.request("POST", tranlate_url, data=json.dumps(payload), headers=headers)
        return json.loads(response.text)['target']
    except Exception as e:
        print("[-]2、兄弟,翻译报错了:%s" % e)
        time.sleep(5)
        tranlate(context)
        # return context


def deal_content(content):
    message = "**%s漏洞**" %  datetime.date.today()
    for data in content:

        message = message + "<font color='warning'>[%s]</font>%s\n<font color='info'>%s</font>\n%s" \
                  % (data['risk'], data['CVE编号'], data['漏洞描述'], data['漏洞参考链接'])
    return message

def send_mail(content):
    message = MIMEText(content, 'html', 'utf-8')
    message['From'] = config_dict["mail_addr"]
    message['To'] = config_dict["mail_to"]
    message['Subject'] = '最新CVE漏洞'

    try:
        stmp = smtplib.SMTP_SSL(config_dict["smtp_server"], config_dict["smtp_port"])
        stmp.login(config_dict["mail_addr"], config_dict["auth_code"])
        try:
            stmp.sendmail(config_dict["mail_addr"], config_dict["Recipient"], message.as_string())
            print('[+]发送成功')
        except Exception as e:
            exit('邮件发送失败--' + str(e))
        else:
            stmp.quit()
    except Exception as e:
        exit('登陆失败--' + str(e))


def send_wx(content):
    message = ''
    wx_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + config_dict['key'] +"&debug=1"
    message = deal_content(content)
    print(len(message))
    # print(message)
    data = {"msgtype": "markdown",
            "markdown": {
            "content": message
            }}
    # print(data)
    res = httpx.post(wx_url, headers=headers, json=data).json()
    errcode = res['errcode']
    if errcode == 0:
        print('[+]发送成功')
    else:
        print('something wrong:\nyou can see:%s' % res)
        # print('something wrong:\nyou can see: https://open.work.weixin.qq.com/devtool/query?e=' + str(errcode))



def main():
    mail_setting = int(input("漏洞爬取默认是当天最新全部的CVE漏洞，如需更改请修改config文件。\n0、微信企业账户\n1、邮箱发送\n请输入想要发送数据的方式:"))
    # mail_setting = 0
    if mail_setting == 0:
        get_config(mail_setting)
        get_cve()
        send_wx(data_list)
    elif mail_setting == 1:
        get_config(mail_setting)
        get_cve()
        print(data_list)
    else:
        print("[+]兄弟你这个输入是错误的，不符合规范，请重新输入")

if __name__ == '__main__':
    while 1:
        data_list = []  # 初始化
        main()
        time.sleep(86400)
