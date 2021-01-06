# -*- coding:utf-8 -*-
banner = """
        888888ba             dP                     
        88    `8b            88                     
       a88aaaa8P' .d8888b. d8888P .d8888b. dP    dP 
        88   `8b. 88'  `88   88   Y8ooooo. 88    88 
        88    .88 88.  .88   88         88 88.  .88 
        88888888P `88888P8   dP   `88888P' `88888P' 
   ooooooooooooooooooooooooooooooooooooooooooooooooooooo 
                @time:2020/12/30 attac_push.py
                C0de by NebulabdSec - @batsu                  
 """
print(banner)

import configparser
import smtplib
from email.mime.text import MIMEText
from translate import Translator
import random
import datetime
import httpx
import time
import requests
import json

config_dict = {}

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


def get_config():
    try:
        config = configparser.ConfigParser()
        config.read("config.ini",encoding='UTF-8')
        data = {
            'smtp_server': config.get('Mail_config', 'smtp_server'),
            'smtp_port': config.get('Mail_config', 'smtp_port'),
            'mail_addr': config.get('Mail_config', 'mail_addr'),
            'auth_code': config.get('Mail_config', 'auth_code'),
            'mail_to': config.get('Mail_config', 'mail_to'),
            'Recipient': config.get('Mail_config', 'Recipient').split(','),
            'care': int(config.get('Config', 'care')),
            'vul_like': config.get('Config', 'vul_like').split(','),
            'risk_like': config.get('Config', 'risk_like').split(',')
            # 'cpid':config.get('Server_config', 'cpid'),
            # 'cpsecret': config.get('Server_config', 'cpsecret')
        }
        config_dict.update(data)
        # print(config_dict)
    except Exception as e:
        exit('[获取配置文件失败:%s]' % str(e))

def get_cve():
    # 时间比我们晚，#取三天前的漏洞才有cvss评分
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=3)  # 3
    pubStartDate = str(yesterday) + 'T00:00:00:000 UTC-05:00'
    print(pubStartDate)
    try:
        if config_dict["care"] == 1:
            for risk in config_dict["risk_like"]:
                params = {'pubStartDate': pubStartDate, 'cvssV3Severity': risk}
                # with httpx.Client(headers=headers, params=params, proxies=proxies) as client:
                with httpx.Client(headers=headers, params=params, verify=False) as client:
                # res = httpx.Client(headers=headers, params=params, proxies=proxies).get(url).json()
                    res = client.get(url).json()
                    if res['totalResults'] > 0:
                        message = "[+] %s号共有`%s`个%s漏洞\n<font color=\"info\"><br>下面是漏洞简介-></font><br>\n" % (
                            time.strftime("%Y-%m-%d", time.localtime()), str(res['totalResults']), risk)
                        res_Formatted_output(res, message)
        elif config_dict["care"] == 0:
            for risk in config_dict["risk_like"]:
                for vul in config_dict["vul_like"]:
                    params = {'pubStartDate': pubStartDate, 'keyword': vul, 'cvssV3Severity': risk}
                    with httpx.Client(headers=headers, params=params, verify=False) as client:
                        res = client.get(url).json()
                        if res['totalResults'] > 0:
                            message = "[+] %s号%s共有`%s`个%s漏洞\n<font color=\"info\"><br>下面是漏洞简介-></font><br>\n" % (
                                time.strftime("%Y-%m-%d", time.localtime()), vul, str(res['totalResults']), risk)
                            res_Formatted_output(res, message)
        else:
            print("[+]今天没发现新的CVE")
    except Exception as e:
        print("[-]1、报错了兄弟:%s" % e)


def res_Formatted_output(res, message):
    print(message)
    global baseSeverity, score
    for i in range(res['totalResults']):
        # print(i)
        id = '漏洞编号：%s' % res['result']['CVE_Items'][i]['cve']['CVE_data_meta']['ID']
        pubdate = '公开日期：%s' % res['result']['CVE_Items'][i]['publishedDate'][0:10]
        # reference_data = '漏洞参考链接：<a href="%s">漏洞来源</a>' % \
                         # str(res['result']['CVE_Items'][i]['cve']['references']['reference_data'][0]['url'])
        reference_data = '漏洞参考链接：[漏洞来源](%s)' % \
                         str(res['result']['CVE_Items'][i]['cve']['references']['reference_data'][0]['url'])
        try:
            baseSeverity = '<font color="warning">漏洞等级：%s</font>' % \
                           res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            score = '<font color="warning">CVSSV3：%s</font>' % str(res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseScore'])
            print(baseSeverity,score)
        finally:
            print(i)
            description = res['result']['CVE_Items'][i]['cve']['description']['description_data'][0]['value']
            # description = translat(description)  # 谷歌翻译
            print(description)
            description = tranlate(description)#其他翻译
            description = '漏洞描述：<font color=\"info\">' + description + '</font>'
            content = '**【新增漏洞告警】**\n%s\n%s\n%s\n%s\n%s\n%s' % (
            id, pubdate, baseSeverity, score, description, reference_data)
            try:
                send_wx(content)
            except Exception as e:
                print("[-]2、报错了兄弟:%s" % e)
        continue


# def translat(context):  # 翻译描述信息
#     if len(context) >= 500:
#         return context
#     else:
#         translator = Translator(service_urls=['translate.google.com', ], to_lang="chinese", proxies=proxies)
#         translation = translator.translate(context)
#         return translation

def tranlate(context):
    try:
        direction = "auto2zh"
        tranlate_url = "http://api.interpreter.caiyunai.com/v1/translator"
        token = "3975l6lr5pcbvidl6jl2"
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
    except:
        # print(context)
        return context
    # text = json.loads(response.text)['target']
    # return text

def send_mail(data):
    message = MIMEText(data, 'html', 'utf-8')
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
    wx_url = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=********-****-****-****-0*********7"
    data = {"msgtype": "markdown",
            "markdown": {
                "content": content
            }}
    res = httpx.post(wx_url, headers=headers, json=data).json()
    errcode = res['errcode']
    if errcode == 0:
        print('[+]发送成功')
    else:
        print('something wrong:\nyou can see: https://open.work.weixin.qq.com/devtool/query?e=' + str(errcode))


def main():
    get_cve()

if __name__ == '__main__':
    get_config()
    main()
