#!/usr/bin/env python
# coding: utf-8

# In[1]:


import socket
import ssl
import datetime
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import requests
import re
import pandas as pd



# In[2]:



class ssl_check():

    #returns the duration of the ssl certificate
    def getDuration(self,hostname):

        self.duration = 0
        ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET),server_hostname=hostname,)
        conn.settimeout(3.0)
        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()
        Start_ON = datetime.datetime.strptime(ssl_info['notBefore'], ssl_date_fmt)
        Exp_ON = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
        Days_Remaining = Exp_ON - datetime.datetime.utcnow()
        self.duration = Exp_ON-Start_ON
        return self.duration


# In[3]:



class URL():

    """
    class to extract all the eight features we need

    """

    def __init__(self,url):


        """

        Features we need to find value of:
        'SSLfinal_State',  'URL_of_Anchor',  'Prefix_Suffix',  'web_traffic',
        'having_Sub_Domain', 'Request_URL', 'Links_in_tags', 'SFH'.

        """
        #attributes
        self.flag = False
        self.SSLfinal_State = -2
        self.URL_of_Anchor = -2
        self.Prefix_Suffix = -2
        self.web_traffic = -2
        self.having_Sub_Domain = -2
        self.Request_URL = -2
        self.Links_in_tags = -2
        self.SFH = -2

        #methods
        url = self.findHREF(url)
        if url:
            self.flag = True
            self.findSSLPreSufSubDomain(url)          #gets the value of features: 'SSLfinal_state' , 'Prefix_Suffix', 'having_Sub_Domain'.
            self.findWebTraffic(url)                  #gets the value of feature: 'web_traffic'.
            self.findRequestURLandURLofAnchor(url)    #gets the value of features: 'Request_URL' , 'URL_of_Anchor'
            self.findLinksInTags(url)                 #gets the value of feature: 'Links_in_tags'
            self.findSFH(url)                          #gets the value of feature: 'SFH'

        else:
            return

    def getFlag(self):
        return self.flag
    def findDomain(self,url):

        """
        returns the domain name in url
        Example: https://www.netflix.com/watch/80028080?trackId=155573560
        output: netflix.com

        """
        parsed_uri = urlparse(url)
        #a URL consists: scheme://netloc/path;parameters?query#fragment
        #the netloc part contains what we need: domain
        result =  '{uri.netloc}'.format(uri=parsed_uri)
        if 'www' in result:
            result = result.split('www.')[1]
        return result


    def findHREF(self,string):

        """
        finds link in a string using regular expression and returns it.

        """

        regex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"
        url = re.findall(regex,string)
        #print(url)
        if url:
            url =  [x[0] for x in url]
            url = str(url[0])
            return url


    def findSSLPreSufSubDomain(self,url):

        """
        For feature 'SSLfinal_State' :
        Use https and Issuer Is Trusted and Age of Certificate ≥ 1 Years → Legitimate : 1
        Using https and Issuer Is Not Trusted → Suspicious : 0
        Otherwise → Phishing : -1

        """

        """
        For feature 'having_Sub_Domain' :
        Dots In Domain Part = 2 → Legitimate : 1
        Dots In Domain Part = 3 → Suspicious : 0
        Otherwise → Phishing : -1

        """

        """
        For feature 'Prefix_Suffix' :
        Domain Name Part Includes (−) Symbol → Phishing : -1
        Otherwise → Legitimate : 1

        """

        result = self.findDomain(url)
        #print(result)
        if result:
            #print("flag1")
            #print(result)
            if 'https' in result or 'http' in result:
                #if http/http is present in domain name (which should not be present as protocols are not included in domain)
                SSLfinal_State = -1
                sub_domain = -1
                prefix_suffix = -1
                #print("flag2")

            else:
                try:
                    ssl = ssl_check()
                    #getting the duration of the ssl certificate
                    duration = ssl.getDuration(result)
                    #print(duration.days)
                    if duration.days >= 365:
                        SSLfinal_State = 1
                    else:
                        SSLfinal_State = 0
                    if '-' in result:
                        prefix_suffix = -1
                    else:
                        prefix_suffix = 1
                    if result.count('.') > 3:
                        sub_domain = -1
                    elif result.count('.') == 3:
                        sub_domain = 0
                    else:
                        sub_domain = 1
                    #print("flag3")
                except:
                    SSLfinal_State = -1
                    prefix_suffix = -1
                    sub_domain = 0


        else:
            SSLfinal_State = -1
            prefix_suffix = -1
            sub_domain = 0

        #print('SSLfinal_State',SSLfinal_State)
        #print('Prefix-Suffix',prefix_suffix)
        #print('Sub_Domain',sub_domain)

        self.SSLfinal_State = SSLfinal_State
        self.Prefix_Suffix = prefix_suffix
        self.having_Sub_Domain = sub_domain

    def findWebTraffic(self, url):

        """
        Website Rank < 100,000 → Legitimate : 1
        Website Rank > 100,000 → Suspicious : 0
        Otherwise → Phishing : -1

        """

        #print(url)
        domain = self.findDomain(url)
        #print(domain)
        try:
            request = requests.get("https://www.alexa.com/siteinfo/" +domain+'#section_traffic')
            soup = BeautifulSoup(request.content,'html.parser')
            content = str(soup.head.script)
            #global contains the rank of the website. Hence, extracting the value of 'global'
            content = content.split("global")[1]
            content = content.split(' ')[1]
            content = content.split(',')
            rank = content[0]
            #print(rank)

            if rank != 'false':
                rank = int(rank)
                if rank <= 100000:
                    web_traffic = 1
                else:
                    web_traffic = 0
            else:
                web_traffic = -1
        except:
            web_traffic = -1

        self.web_traffic = web_traffic


    def findRequestURLandURLofAnchor(self, url):

        """
        For feature 'Request_URL' :
        % of Request URL < 22% → Legitimate : 1
        % of Request URL ≥ 22% and 61% → Suspicious : 0
        Otherwise → feature = Phishing : -1

        """
        """
        For feature 'URL_of_Anchor' :
        % of URL Of Anchor < 31% → 𝐿𝑒𝑔𝑖𝑡𝑖𝑚𝑎𝑡𝑒 : 1
        % of URL Of Anchor ≥ 31% And ≤ 67% → Suspicious : 0
        Otherwise → Phishing : -1

        """
        #Checking Request URLs
        domain = self.findDomain(url)
        #print(domain)
        try:
            req = requests.get(url)
            soup = BeautifulSoup(req.content, 'html.parser',from_encoding="iso-8859-1")
            #from_encoding="iso-8859-1"
            images = soup.find_all('img')
            videos = soup.find_all('video')
            audios = soup.find_all('audio')
            sources = soup.find_all('source')

            anchors = soup.find_all('a')
            anchor_count = len(anchors)
            anchor_phish = 0

            count = len(images) + len(videos) + len(audios) + len(sources)
            phish = 0

            for i in images:
                try:
                    ans = self.findHREF(i['src'])
                    if ans:
                        ans = self.findDomain(ans)
                        #print(ans)
                        if domain not in ans:
                            phish += 1
                except:
                    continue

            for i in videos:
                try:
                    ans = self.findHREF(i['src'])
                    ans = self.findDomain(ans)
                    #print(ans)
                    if domain not in ans:
                        phish += 1
                except:
                    continue

            for i in audios:
                try:
                    ans = self.findHREF(i['src'])
                    ans = self.findDomain(ans)
                    #print(ans)
                    if domain not in ans:
                        phish += 1
                except:
                    continue

            for i in sources:
                try:
                    ans = self.findHREF(i['src'])
                    ans = self.findDomain(ans)
                    #print(ans)
                    if domain not in ans:
                        phish += 1
                except:
                    continue

            #calculating percentage of phishing Request_URL
            try:
                percent = (phish/count)*100
                if percent < 22:
                    Request_URL = 1
                elif percent < 61:
                    Request_URL = 0
                else:
                    Request_URL = -1

            except ZeroDivisionError:
                Request_URL = 0


            for link in anchors:
                hrf = link.get('href')
                #print(hrf)
                hrf = self.findHREF(url)
                if hrf != []:
                    hrf = self.findDomain(hrf)
                    if domain not in hrf:
                        anchor_phish += 1

            #Calculating percentage of phishing URLs in anchor tags
            try:
                anchor_phish_percent = (anchor_phish/anchor_count)*100
                if anchor_phish_percent < 31:
                    URL_of_Anchor = 1
                elif anchor_phish_percent < 68:
                    URL_of_Anchor = 0
                else:
                    URL_of_Anchor = -1

            except ZeroDivisionError:
                URL_of_Anchor = 0

        except:
            Request_URL = -1
            URL_of_Anchor = -1

        #print(Request_URL)
        #print(URL_of_Anchor)
        self.Request_URL = Request_URL
        self.URL_of_Anchor = URL_of_Anchor
        #print(count,anchor_count)


    def findLinksInTags(self, url):

        """
        % of Links in " < Meta > "," < Script > " and " < Link>" < 17% → Legitimate
        % of Links in < Meta > "," < Script > " and " < Link>" ≥ 17% And ≤ 81% → Suspicious
        Otherwise → Phishing

        """
        domain = self.findDomain(url)
        try:
            req = requests.get(url)
            soup = BeautifulSoup(req.content, 'html.parser',from_encoding="iso-8859-1")
            links  = soup.find_all('link')
            scripts = soup.find_all('script')
            metas = soup.find_all('meta')
            metas_count = 0
            phish_tags = 0

            for i in links:
                hrf = i.get('href')
                hrf = self.findHREF(str(hrf))
                #print(hrf)
                if hrf:
                    hrf = self.findDomain(hrf)
                    if domain not in hrf:
                        phish_tags += 1



            for i in scripts:
                try:
                    hrf = i.get('src')
                    hrf = self.findHREF(str(hrf))
                    #print(hrf)
                    if hrf:
                        hrf = self.findDomain(hrf)
                        if domain not in hrf:
                            phish_tags += 1
                except:
                    continue



            for i in metas:
                try:
                    hrf = i.get('content')
                    hrf = self.findHREF(str(hrf))
                    #print(hrf)
                    if hrf:
                        metas_count += 1
                        hrf = self.findDomain(hrf)
                        if domain not in hrf:
                            phish_tags += 1
                except:
                    continue

            total_link = len(links) + len(scripts) + metas_count
            #print(total_link)
            try:
                Links_in_tag_percent = (phish_tags/total_link)*100
                if Links_in_tag_percent < 17:
                    Links_in_tag = 1
                elif Links_in_tag_percent <= 81:
                    Links_in_tag = 0
                else:
                    Links_in_tag = -1

            except ZeroDivisionError:
                Links_in_tag = 0

        except:
            Links_in_tag = -1


        self.Links_in_tags = Links_in_tag

    def findSFH(self,url):

        """
        SFH is "about: blank" Or Is Empty → Phishing : -1
        SFH Refers To A Different Domain → Suspicious : 0
        Otherwise → Legitimate : 1

        """
        domain = self.findDomain(url)
        try:
            req = requests.get(url)
            soup = BeautifulSoup(req.content, 'html.parser',from_encoding="iso-8859-1")
            form = soup.find_all('form')
            #print(form)
            for i in form:
                hrf = i.get('action')
                if not hrf or hrf.lower() == 'empty':
                    SFH = -1
                else:
                    hrf = self.findHREF(hrf)
                    if hrf:
                        hrf = self.findDomain(hrf)
                        if domain in hrf:
                            SFH = 1
                        else:
                            SFH = 0
                    else:
                        SFH = 1
            if form == []:
                SFH = 0

        except:
            SFH = -1

        self.SFH = SFH

    def getAllFeatures(self):

        custom = [{ 'SSLfinal_State': self.SSLfinal_State,
         'URL_of_Anchor':self.URL_of_Anchor,
         'Prefix_Suffix': self.Prefix_Suffix,
         'web_traffic': self.web_traffic,
         'having_Sub_Domain': self.having_Sub_Domain,
         'Request_URL': self.Request_URL,
         'Links_in_tags': self.Links_in_tags,
         'SFH':self.SFH }]
        to_predict = pd.DataFrame.from_dict(custom)
        #print(to_predict.to_string())
        return to_predict


# In[6]:


from MajorApp import Algorithm
def predictURL(input_url):
    #num = int(input("Enter number of websites you want to check: "))
    #for i in range(num):
        #input_url = input()
    url = URL(input_url)
    flag = url.getFlag()
    if flag:
        to_predict = url.getAllFeatures()
        predicted = Algorithm.rfc.predict(to_predict)
        if predicted[0] == 1:
            predictedURL = '|| Legitimate ||'
        else:
            predictedURL = "XX Phishing XX "
        #print()
        return predictedURL
    else:
        return "Please enter a proper URL!"

#if __name__ == "__main__":
#    main()


# In[4]:


#http://www.paypal.com.cgi.bin.webscr.cmd.login.submit.dispatch.5885d80a13c03faee8dcbcd55a50598f04d34b4bf5tt1.mediareso.com/secure-code90/security/
#http://www.everythinggoingon.net/~gpeveryt/home/Email/
#http://www.revitolcream.org/wp-content/plugins/all-in-one-seo-pack/rex/secure-code5/security/login.php
#http://www.avedeoiro.com/site/plugins/chase/

#https://www.netflix.com/browse?jbv=70281562
#https://www.geeksforgeeks.org/heap-sort/
#https://www.pythonistaplanet.com/how-to-create-a-django-project-in-anaconda-very-easily/
