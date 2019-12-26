"""
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.If not, see 
<https://www.gnu.org/licenses/>.
"""
import argparse
from xlutils.copy import copy
import subprocess
import xlsxwriter
import xlrd
import os
import os.path
import sys
if sys.version[0] == '2':
	reload(sys)
	sys.setdefaultencoding("utf-8")
else:
	from importlib import reload
import re
from bs4 import BeautifulSoup
from netaddr import *
import pprint
import requests
from googlesearch import search
import time
import datetime
from datetime import date
import shutil
import glob

def gcookie():
	for item in os.listdir(os.getcwd()):
		if item.endswith(".google-cookie"):
			os.remove( os.path.join(os.getcwd(), item ) )
	return "working"
def internet(url='http://www.google.com/', timeout=5):
	try:
		req = requests.get(url, timeout=timeout)
		req.raise_for_status()
		return True
	except requests.ConnectionError:
		print ("\033[1;31;40mError:\033[0;0m Can you please check your Internet Connection?")
		sys.exit()
def torstatuss():
	p =  subprocess.Popen(["systemctl", "is-active",  "tor"], stdout=subprocess.PIPE)
	(output, err) = p.communicate()
	output = output.decode('utf-8')
	return output

def awsmPoc(awpoc):
	awm=[]
	#Thank you "Syue Siang Su" for Awsome POC collection repository
	if (os.path.isdir(str(os.getcwd())+"/"+"awesome-cve-poc")):
		if str((datetime.datetime.fromtimestamp(os.path.getctime(str(os.getcwd())+"/"+"awesome-cve-poc/README.md"))).strftime('%Y-%m-%d')).strip() == str(date.today()).strip():
			print ("\033[1;31;40mAwsome CVE POC:\033[0;0mGreat you have updated Awsome-CVE-POC Data")
			intxt=open(str(os.getcwd())+"/"+"awesome-cve-poc/README.md", "r")
			intxtout=intxt.readlines()
			intxt.close
		else:
			print ("\033[1;31;40mAwsome CVE POC:\033[0;0mUpdating CVE POC Data")
			shutil.rmtree("awesome-cve-poc")
			os.system("git clone https://github.com/qazbnm456/awesome-cve-poc.git")
			intxt=open(str(os.getcwd())+"/"+"awesome-cve-poc/README.md", "r")
			intxtout=intxt.readlines()
			intxt.close
	else:
		try:
			print ("\033[1;31;40mAwsome CVE POC:\033[0;0mClonning is in Process..!")
			os.system("git clone https://github.com/qazbnm456/awesome-cve-poc.git")
			intxt=open(str(os.getcwd())+"/"+"awesome-cve-poc/README.md", "r")
			intxtout=intxt.readlines()
			intxt.close
		except:
			print ("\033[1;31;40mGit reposetory issue or internet is not working..skipping Awsome CVE POC checks\033[0;0m")
			return "Awsome POC CVE-Skipped"
				
	for jk in intxtout:
		if re.search(r"\[CVE.*\]",str(jk)) is not None:
			if str(awpoc).strip() == str(re.search(r"\[CVE.*\]",str(jk)).group().replace("[","").replace("]","")).strip():
				if re.search(r"\[CVE.*\(http",str(jk)) is not None:
					print ("\033[1;32;40mAwsome POC:\033[0;0m"+str(re.search(r"\(http.*\)",str(jk)).group().replace("(","").replace(")","")))
					return str(re.search(r"\(http.*\)",str(jk)).group().replace("(","").replace(")",""))
				else :
					for fl in glob.glob(str(os.getcwd())+"/"+"awesome-cve-poc/*.md"):
						if str(os.getcwd())+"/"+"awesome-cve-poc/"+str(awpoc).strip()+".md" == str(fl).strip():
							
							awm.append(str(fl).strip())
			else:
				pass
	if awm:
		awm2=list(set(awm))
		print ("\033[1;32;40mAwsome POC System Path:\033[0;0m")
		print ("\n".join(awm2))
		print ("====================================================")
		return ("\n".join(awm2))
	else:
		print ("Awsome POC: no Data")		
		return ("Awsome POC: no Data")

def googleActiver(clist,cfile):
	if clist is not None:
		print ("\033[1;31;40mManual Mode enabled.\033[0;0m")
		book = xlsxwriter.Workbook('raw_data.xlsx', {'strings_to_urls': False})
		sheet1 = book.add_worksheet("XplointHunter")
		for cvee in clist.split(","):
			Fcvs,Fauth,Fvultype,Fmetaexploit,FreferB,Fexploitcollect,Fdesc,Fvult= detailfinder(str(cvee.strip()))
			sheet1.write(clist.split(",").index(cvee),0,cvee)
			sheet1.write(clist.split(",").index(cvee),1,Fvult)
			sheet1.write(clist.split(",").index(cvee),2,Fdesc)
			sheet1.write(clist.split(",").index(cvee),3,Fcvs)
			sheet1.write(clist.split(",").index(cvee),4,Fauth)
			sheet1.write(clist.split(",").index(cvee),5,Fvultype)
			sheet1.write(clist.split(",").index(cvee),6,Fmetaexploit)
			sheet1.write(clist.split(",").index(cvee),7,FreferB)
			sheet1.write(clist.split(",").index(cvee),8,Fexploitcollect)
			if (str(googlestatus)=="on"):
				Gexpl=googlefinder(str(cvee.strip()))
			else:
				Gexpl="Google search option is not enabled"			
			sheet1.write(clist.split(",").index(cvee),9,Gexpl)
			if (str(odaystatus)=="on"):
				Odayexp=odayDetailfinder(str(cvee.strip()))
			else:
				Odayexp="0day search option is not enabled"
			sheet1.write(clist.split(",").index(cvee),10,Odayexp)
		book.close()
		raw_data1=xlrd.open_workbook("raw_data.xlsx")
		sheet1=raw_data1.sheet_by_index(0)
		fs_num_of_col1=sheet1.ncols
		fs_num_of_row1=sheet1.nrows
		book2 = xlsxwriter.Workbook('CVE-Exploit-Map.xlsx', {'strings_to_urls': False})
		sheet2 = book2.add_worksheet("XplointHunter")
		j=1
		for i in range(0,fs_num_of_row1):
			sheet2.write(j,0,str(sheet1.cell(i,0).value).strip())
			sheet2.write(j,1,str(sheet1.cell(i,1).value).strip())
			sheet2.write(j,2,str(sheet1.cell(i,2).value).strip())
			sheet2.write(j,3,str(sheet1.cell(i,3).value).strip())
			sheet2.write(j,4,str(sheet1.cell(i,4).value).strip())
			sheet2.write(j,5,str(sheet1.cell(i,5).value).strip())
			sheet2.write(j,6,str(sheet1.cell(i,6).value).strip())
			sheet2.write(j,7,str(sheet1.cell(i,7).value).strip())
			sheet2.write(j,8,str(sheet1.cell(i,8).value).strip())
			sheet2.write(j,9,str(sheet1.cell(i,9).value).strip())
			sheet2.write(j,10,str(sheet1.cell(i,10).value).strip())
			j=j+1
		sheet2.write(0,0,"CVE-ID")
		sheet2.write(0,1,"Title")
		sheet2.write(0,2,"Description")
		sheet2.write(0,3,"CVSscore")
		sheet2.write(0,4,"Authenticaton")
		sheet2.write(0,5,"Vulnerability Type")
		sheet2.write(0,6,"Metasploit Module")
		sheet2.write(0,7,"References")
		sheet2.write(0,8,"Exploit List")
		sheet2.write(0,9,"Google Results")
		sheet2.write(0,10,"0day Results")
		book2.close()
		os.remove('raw_data.xlsx')
	elif cfile is not None:
			print ("\n\033[1;31;40mFile Mode:\033[1;32;40m Don\'t worry i will take care of all CVE-IDs. Go and have some coffee!\033[0;0m\n")
			intxt=open(cfile, "r")
			intxtout=intxt.readlines()
			intxt.close
			book3 = xlsxwriter.Workbook('raw_data1.xlsx', {'strings_to_urls': False})
			sheet3 = book3.add_worksheet("XplointHunter")
			for j in intxtout:
				Fcvs,Fauth,Fvultype,Fmetaexploit,FreferB,Fexploitcollect,Fdesc,Fvult=detailfinder(str(j).strip())
				sheet3.write(intxtout.index(j),0,str(j).strip())
				sheet3.write(intxtout.index(j),1,Fvult)
				sheet3.write(intxtout.index(j),2,Fdesc)
				sheet3.write(intxtout.index(j),3,Fcvs)
				sheet3.write(intxtout.index(j),4,Fauth)
				sheet3.write(intxtout.index(j),5,Fvultype)
				sheet3.write(intxtout.index(j),6,Fmetaexploit)
				sheet3.write(intxtout.index(j),7,FreferB)
				sheet3.write(intxtout.index(j),8,Fexploitcollect)
				if (str(googlestatus)=="on"):
					Gexpl=googlefinder(str(j).strip())
				else:
					Gexpl="Google search option is not enabled"
				sheet3.write(intxtout.index(j),9,Gexpl)
				if (str(odaystatus)=="on"):
					Odayexp=odayDetailfinder(str(j).strip())
				else:
					Odayexp="0day search option is not enabled"
				sheet3.write(intxtout.index(j),10,Odayexp)
			book3.close()
			time.sleep(2)
			raw_data3=xlrd.open_workbook("raw_data1.xlsx")
			sheet4=raw_data3.sheet_by_index(0)
			fs_num_of_col4=sheet4.ncols
			fs_num_of_row4=sheet4.nrows
			book4 = xlsxwriter.Workbook('CVE-Exploit-Map.xlsx', {'strings_to_urls': False})
			sheet5 = book4.add_worksheet("XplointHunter")
			j=1
			for i in range(0,fs_num_of_row4):
				sheet5.write(j,0,str(sheet4.cell(i,0).value).strip())
				sheet5.write(j,1,str(sheet4.cell(i,1).value).strip())
				sheet5.write(j,2,str(sheet4.cell(i,2).value).strip())
				sheet5.write(j,3,str(sheet4.cell(i,3).value).strip())
				sheet5.write(j,4,str(sheet4.cell(i,4).value).strip())
				sheet5.write(j,5,str(sheet4.cell(i,5).value).strip())
				sheet5.write(j,6,str(sheet4.cell(i,6).value).strip())
				sheet5.write(j,7,str(sheet4.cell(i,7).value).strip())
				sheet5.write(j,8,str(sheet4.cell(i,8).value).strip())
				sheet5.write(j,9,str(sheet4.cell(i,9).value).strip())
				sheet5.write(j,10,str(sheet4.cell(i,10).value).strip())
				j=j+1
			sheet5.write(0,0,"CVE-ID")
			sheet5.write(0,1,"Title")
			sheet5.write(0,2,"Description")
			sheet5.write(0,3,"CVSscore")
			sheet5.write(0,4,"Authenticaton")
			sheet5.write(0,5,"Vulnerability Type")
			sheet5.write(0,6,"Metasploit Module")
			sheet5.write(0,7,"References")
			sheet5.write(0,8,"Exploit List")
			sheet5.write(0,9,"Google Results")
			sheet5.write(0,10,"0day Results")
			book4.close()
			os.remove('raw_data1.xlsx')
	else:
		print ("\033[1;31;40mUsage: XploitHunt.py -h\033[0;0m")
def googlefinder(cve):
	print ("=======================================================================================")
	#query = ["site:exploit-db.com intext:"+str(cve),"intext:"+str(cve),str(cve)+" "+"POC",str(vult)+" "+"POC"]
	print ("\033[1;32;40mGoOgle BOT is ready to serve you....!! \033[0;0m")
	internet()
	expp=[]
	query=[]
	googletxt=open("google-payload.txt", "r")
	googlepay=googletxt.readlines()
	googletxt.close
	for g in googlepay:
		gg=g.replace("?",str(cve))
		query.append(str(gg))
	query.append(str(vult)+" "+"POC")
	print ("\033[1;30;40mCVE-ID:\033[0;0m"+str(cve))
	print ("\033[1;32;40mLapse to wait:\033[0;0m"+str(args.SleepTime))
	print ("\033[1;32;40mGoogle Search Count:\033[0;0m"+str(args.SearchCount))
	blackh = open("blacklist-host.txt", "r")
	blackhost=blackh.readlines()
	blackh.close
	for i in query:
		gcookie()
		#time.sleep(5)
		if "No title found in Description" in str(i):
			pass
		else:
			print ("\033[1;32;40mSearching for:\033[0;0m"+"\033[1;36;40m"+str(i)+"\033[0;0m")
			try:
				#Thank you "MarioVilas" for awsome work
				for j in search(i, tld="com", num=int(args.SearchCount), start=0,stop=int(args.SearchCount),pause=float(args.SleepTime), user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)"):
					#time.sleep(5)
					if any(str(bl).strip() in str(j).strip() for bl in blackhost):
						pass
					else:
						print (j)
						expp.append(j)
			except:
				IPB="Google Blocked requests"
				expp.append(IPB)
				print ("Unable to make request")
				expp3=list(set(expp))
				return "\n".join(expp3)

	expp2=list(set(expp))
	print ("=======================================================================================\n")
	print ("\033[1;32;40mGoogle Filter Results:\033[0;0m")
	print ("\n".join(expp2))
	return ("\n".join(expp2))

def odayDetailfinder(concve):
	print ("=======================================================================================\n")
	print ("\033[1;32;40mLets try luck at 0day..! \033[0;0m")
	print ("\033[1;30;40mCVE-ID: \033[0;0m"+str(concve))
	session = requests.session()
	oday=[]
	cvex=[]
	session.proxies = {}
	session.proxies['http'] = 'socks5h://localhost:9050'
	session.proxies['https'] = 'socks5h://localhost:9050'
	conurl="http://mvfjfugdwgc5uwho.onion"
	#concve=str(concve)
	value={'agree':'Yes, I agree'}
	while True:
		try:
			conr=session.post(conurl,data=value)
			conr.raise_for_status()
		except requests.ConnectionError:
			print ("\033[1;31;40mTOR Error:\033[0;0mRestarting Tor service")
			os.system("service tor restart")
			time.sleep(2)
			continue
		else:
			break
	url ="http://mvfjfugdwgc5uwho.onion/search?search_request=&search_type=1&category=-1&platform=-1&price_from=0&price_to=10000&author_login=&cve="+concve
	r = session.get(url)
	soup= BeautifulSoup(r.text, 'html.parser')
	right_table=soup.find_all('div',attrs={'class': re.compile("^ExploitTableContent")})
	if right_table is not None:
		for meta1 in right_table:
			for meta in meta1.find_all("a"):
				#print meta.get("href")
				if re.search(r"\/exploit.*",str(meta.get("href"))) is not None:
					rawexp=re.search(r"\/exploit.*",str(meta.get("href"))).group()
					rawexp1="http://mvfjfugdwgc5uwho.onion"+str(rawexp)
					print ("\033[1;31;40mVerifying URL:\033[0;0m"+str(rawexp1))
					right_table2=soup.findAll('div',attrs={'class': re.compile("^td allow_tip")})
					if right_table2 is not None:
						for jk in right_table2:
							if re.search(r"\n\t\t\t\t\t*CVE",str(jk)) is not None:
								wrk=re.search(r"CVE.*",str(jk.find('div',attrs={'class': re.compile("^TipText")}))).group()
								cvex=wrk.split("<br/>")
								for cved in cvex:
									if str(cved)==str(concve):
										oday.append(rawexp1)
		oday1=list(set(oday))
		if oday1:
			print ("\033[1;32;40mExploit Confirmed:\033[0;0m")
			print ("\n".join(oday1))
			return ("\n".join(oday1))
		else:
			print ("\033[1;32;40m0Day Says: The Exploit URL does not contain mentioned CVE-Id \033[0;0m")
			return "No Exploit found"

def CsvDloader(cscve):
	explo=""
	csdesc=""
	csscore=""
	auth=""
	refer=[]
	exploitt=[]
	
	r= requests.get("https://cxsecurity.com/cveshow/"+str(cscve))
	r.text[0:]
	soup=BeautifulSoup(r.text,'html.parser')
	
	csdesc=soup.find('td',attrs={'width': re.compile("^258"),'bgcolor': re.compile("^#202020"),'align': re.compile("^left")}).get_text()
	center_table=soup.find_all('table',attrs={'width': re.compile("^100%"),'border': re.compile("^0"),'cellpadding': re.compile("^0"),'style': re.compile("^border-collapse: collapse;")})
	
	refer_table=soup.find_all('table',attrs={'width': re.compile("^70%"),'border': re.compile("^0"),'cellpadding': re.compile("^0"),'style': re.compile("^border-collapse: collapse;"),'cellspacing': re.compile("^0")})
	adv_table=soup.find_all('table',attrs={'width': re.compile("^100%"),'border': re.compile("^0"),'cellpadding': re.compile("^0"),'style': re.compile("^border-collapse: collapse;"),'cellspacing': re.compile("^0")})
	print ("\033[1;32;40mDescription:\033[0;0m \n"+str(csdesc)+"\n")
	if "aka" in str(csdesc):
		try:
			akf=str(csdesc).replace("\'","\"")
			print ("\033[1;32;40mVulnerability Title:\033[0;0m"+str(re.search(r"aka.*\"",str(akf)).group().replace("aka",""))+"\n")
			vult=re.search(r"aka.*\"",str(akf)).group().replace("aka","")
			#print "Title:"+str(vult)
		except:
			print ("\033[1;32;40mVulnerability Title:\033[0;0m No title Found in Description")
			vult="No title found in Description"
			pass
	else:
		print ("\033[1;32;40mVulnerability Title:\033[0;0m No title Found in Description")
		vult="No title found in Description"
	if adv_table is not None:
		for j in range(len(adv_table)):
			if adv_table[j].find_all('a') is not None:
				for meta in adv_table[j].find_all('a'):
					if "https://cxsecurity.com/issue" in str(meta.get("href")):
						exploitt.append(meta.get("href"))

	if center_table is not None:
		for i in range(len(center_table)):
			#print center_table[i].find('h6')
			cen2=center_table[i].find('td',attrs={'width': re.compile("^258"),'bgcolor': re.compile("^#202020")})
			if cen2 is not None:
				if cen2.find('span') is not None:
					#print cen2.find('span').get_text()
					csscore=cen2.find('span').get_text()
					print ("\033[1;32;40mCVSS Score:\033[0;0m"+str(csscore))
			cen3=center_table[i].find('td',attrs={'width': re.compile("^258"),'bgcolor': re.compile("^#1B1B1B")})
			if cen3 is not None:
				if cen3.find('center') is not None:
					if "<span" in str(cen3.find('center')):
						pass
					else:
						explo=cen3.find('center').get_text()
						print ("\033[1;32;40mVulnerability Type:\033[0;0m"+str(explo))
			cen4=center_table[i].find('td',attrs={'width': re.compile("^259"),'bgcolor': re.compile("^#1B1B1B")})
			if cen4 is not None:
				if cen4.find('center') is not None:
					if "<span" in str(cen4.find('center')):
						pass
					else:
						auth=cen4.find('center').get_text()
						print ("\033[1;32;40mAuthentication Type:\033[0;0m "+str(auth))

	if refer_table is not None:
		for i in range(len(refer_table)):
			tmp=refer_table[i].find_all('div',attrs={'onclick': re.compile("^window.open")})
			if tmp is not None:
				for ii in range(len(tmp)):
					refer.append(str(tmp[ii].get_text()))
	print ("\033[1;32;40mReferences:\033[0;0m")
	exploittmp=list(set(exploitt))
	refertmp=list(set(refer))
	for link in refer:
		print (link)
			#Analyzing url for exploits
		if "www.exploit-db.com/exploits" in str(link):
			print ("Exploit-db link:"+str(link))
			exploittmp.append(link)
		elif "www.rapid7.com/db" in str(link):
			print ("Rapid7 Link: "+str(link))
			exploittmp.append(link)
		elif "packetstormsecurity.com/files" in str(link):
			print ("PacketStrom Advisories: "+str(link))
			exploittmp.append(link)
		elif "www.tenable.com/security/research" in str(link):
			print ("Tenable Advisories: "+str(link))
			exploittmp.append(link)
		elif "hackerone.com" in str(link):
			print ("HackerOne Reports: "+str(link))
			exploittmp.append(link.get("href"))
		elif "seclists.org/fulldisclosure" in str(link):
			print ("Seclist Archives: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.cloudfoundry.org/blog/" in str(link):
			print ("Need to verify: "+str(link))
			exploittmp.append(link.get("href"))
		elif "iwantacve.cn/index.php/archives" in str(link):
			print ("Need to verify: "+str(link))
			exploittmp.append(link.get("href"))
		elif "ssd-disclosure.com/archives/" in str(link):
			print ("POC : "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.youtube.com" in str(link):
			print ("Video POC : "+str(link))
			exploittmp.append(link.get("href"))
		elif "youtu.be" in str(link):
			print ("Video POC : "+str(link))
			exploittmp.append(link.get("href"))
		elif "twitter.com" in str(link):
			print ("Twitter POC : "+str(link))
			exploittmp.append(link.get("href"))
		elif "blog.0x42424242.in" in str(link):
			print ("Blog : "+str(link))
			exploittmp.append(link.get("href"))
		elif "medium.com" in str(link):
			print ("POC on Medium: "+str(link))
			exploittmp.append(link.get("href"))
		elif "pentest.com.tr/exploits" in str(link):
			print ("POC on unknwon blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "rhinosecuritylabs.com" in str(link):
			print ("Security Vendor Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "zer0-day.pw/articles" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "research.digitalinterruption.com" in str(link):
			print ("Securit Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "neetech18.blogspot.com" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.vulnerability-lab.com" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "armin.dev/blog" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "lists.openwall.net/full-disclosure" in str(link):
			print ("Openwall Disclosure: "+str(link))
			exploittmp.append(link.get("href"))
		elif "vdalabs.com" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.nccgroup.trust/uk/our-research" in str(link):
			print ("Security Vendor Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "pastebin.com" in str(link):
			print ("Pastebin: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.detack.de/en" in str(link):
			print ("Security Vendor Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.detack.de/en" in str(link):
			print ("Security Vendor Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "www.pluginvulnerabilities.com" in str(link):
			print ("Wordpress Plugin: "+str(link))
			exploittmp.append(link.get("href"))
		elif "talosintelligence.com/vulnerability_reports" in str(link):
			print ("Security Vendor Blog: "+str(link))
			exploittmp.append(link.get("href"))
		elif "blog.hivint.com" in str(link):
			print ("Security Blog: "+str(link))
			exploittmp.append(link)
		
		elif "www.securityfocus.com/bid/" in str(link):
			Lurl=str(link)+"/exploit"
			print ("\033[1;30;40mChecking exploit details in: \033[0;0m"+str(link))
			hurl=requests.get(Lurl)
			hurl.text[0:]
			soup2= BeautifulSoup(hurl.text, 'html.parser')
			is_present = bool(re.search('You have entered a malformed request',hurl.text))
			if is_present == True:
				print ("\033[1;31;40mSecurityfocuse found autobot request, Check URL manually  \033[0;0m")
				time.sleep(2)
				exploittmp.append("Not Confirm:"+str(link))
			else:
				right_table5=soup2.find('div',attrs={'id': re.compile("^vulnerability")})
				if right_table5 is not None:
					right_table6=right_table5.find_all('a')
					if right_table6 is not None:
						for link2 in right_table6:
							exploittmp.append("https://www.securityfocus.com/"+str(link2.get('href')))
					if any("Reports indicate" in s for s in right_table5):
						print ("Exploit found:"+str(link))
						exploittmp.append(link.get("href"))
					elif any("An attacker can" in s for s in right_table5):
						print ("Exploit found:"+str(link))
						exploittmp.append(link.get("href"))
					elif any("researchers" in s for s in right_table5):
						print ("Exploit found:"+str(link))
						exploittmp.append(link.get("href"))
					elif any("Metasploit" in s for s in right_table5):
						print ("Exploit found:"+str(link))
						exploittmp.append(link.get("href"))
					elif any("we are not aware of any working exploits" in s for s in right_table5):
						print ("Scurityfocus: No exploit detail found")
					elif any("Please see the references" in s for s in right_table5):
						print ("POC found:"+str(link))
						exploittmp.append(link)
					else:
						print ("\033[1;31;40mNo Exploit found\033[0;0m \n")
		else:
			refertmp.append(link)
	exploittmp.append(awsmPoc(str(cscve)))
	print ("\n")
	print ("\033[1;31;40mExploit Details:\033[0;0m")
	exploittmp2=list(set(exploittmp))
	for ii in exploittmp2:
		print (ii)
	refertmp2=list(set(refertmp))
	return explo,csdesc,csscore,auth,"\n".join(refertmp2),"\n".join(exploittmp2),vult

def detailfinder(x):
	print ("=======================================================================================")
	print ("\033[1;32;40mCVE-ID:\033[0;0m "+str(x))
	D=[]
	cvcnum=[]
	referB=[]
	metaexploit=[]
	exploitcollect=[]
	global vult
	#user URL 
	r=requests.get('https://www.cvedetails.com/cve-details.php?t=1&cve_id='+str(x))
	r.text[0:]
	soup= BeautifulSoup(r.text, 'html.parser')
	#print soup
	if "This site only contains valid CVE entries" in str(soup):
		return "No data","No data","No data","No data","No data","No data","No data","No data"
	elif "Unknown CVE ID" in str(soup):
		exp,csde,cdsc,authh,referr,exppext,vult=CsvDloader(x)
		exploitrang="Exploit Range("+str(exp)+")"
		return cdsc,authh,exploitrang,"No data",referr,exppext,csde,vult
	else:
		print ("Hunting for Exploit:\n")
	right_table=soup.find('table',class_='details')
	right_table2=soup.find('table',id='vulnrefstable')
	right_table3=soup.find('div',attrs={'style': re.compile("^background-color:")})
	right_table4=soup.find('div',attrs={'id': re.compile("^metasploitmodstable")})
	right_table7=soup.find('div',attrs={'class': re.compile("^cvedetailssummary")})
	
	#Description_gathering
	desc1=right_table7.get_text(strip=True)
	desc2=re.search(r"^.*Publish Date",str(desc1)).group().replace("Publish Date","")
	print ("\033[1;32;40mDescription:\033[0;0m \n"+str(desc2)+"\n")
	if any("aka" in s for s in right_table7):
		try:
			akf=str(desc2).replace("\'","\"")
			print ("\033[1;32;40mVulnerability Title:\033[0;0m"+str(re.search(r"aka.*\"",str(akf)).group().replace("aka",""))+"\n")
			vult=re.search(r"aka.*\"",str(akf)).group().replace("aka","")
			#print "Title:"+str(vult)
		except:
			print ("\033[1;32;40mVulnerability Title:\033[0;0m No title Found in Description")
			vult="No title found in Description"
			pass
	else:
		print ("\033[1;32;40mVulnerability Title:\033[0;0m No title Found in Description")
		vult="No title found in Description"
	#filter data-CVSscore-Auth status-vulnerability type
	for row in right_table.find_all("tr"):
		cells2=row.find_all('td')
		D.append(cells2[0].find('span'))
	
	for tt in right_table3:
		cvcnum.append(str(tt))
		print ("\033[1;32;40mCVSS Score:\033[0;0m"+str(tt))

	#D has all data which we required
	D=filter(None, D)
	#Authentication status
	try:
		auth=re.search(r">.*</",str(D[4])).group()
		auth=auth.replace('>','').replace('</','')
		print ("\033[1;32;40mAuthentication Type:\033[0;0m "+str(auth))
	except:
		print ("\033[1;32;40mAuthentication Type:\033[0;0m Not Define")
		auth="Not Define"
	#Vulnerability type
	try:
		vultype=re.search(r">.*</",str(D[6])).group()
		vultype=vultype.replace('>','').replace('</','')
		print ("\033[1;32;40mVulnerability Type:\033[0;0m"+str(vultype))
	except:
		print ("\033[1;32;40mVulnerability Type:\033[0;0m Not Define")
		vultype="Not Define"
		pass
	print ("\n")
	#Metasploit module details
	print ("\033[1;32;40mMetasploit Module Details:\033[0;0m")
	for meta in right_table4.find_all("a"):

		if str("http://www.metasploit.com")==str(meta.get("href")):
			metaexploit.append("No module Found")
			pass
		else:
			print ("Metasploit Module: "+str(meta.get("href")))
			metaexploit.append(meta.get("href"))
	print ("\n")
	#Reference Data
	print ("\033[1;32;40mReferences:\033[0;0m")
	if right_table2 is None:
		print ("\033[1;31;40mNo Reference found\033[0;0m")
		return ";".join(cvcnum),auth,vultype,"\n".join(metaexploit),"No Reference found","No Exploit found",desc2,vult
	else:
		print ("")
	for link in right_table2.find_all("a"):
		#Analyzing url for exploits
		if "www.exploit-db.com/exploits" in str(link.get("href")):
			print ("Exploit-db link:"+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.rapid7.com/db" in str(link.get("href")):
			print ("Rapid7 Link: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "packetstormsecurity.com/files" in str(link.get("href")):
			print ("PacketStrom Advisories: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.tenable.com/security/research" in str(link.get("href")):
			print ("Tenable Advisories: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "hackerone.com" in str(link.get("href")):
			print ("HackerOne Reports: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "seclists.org/fulldisclosure" in str(link.get("href")):
			print ("Seclist Archives: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.cloudfoundry.org/blog/" in str(link.get("href")):
			print ("Need to verify: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "iwantacve.cn/index.php/archives" in str(link.get("href")):
			print ("Need to verify: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "ssd-disclosure.com/archives/" in str(link.get("href")):
			print ("POC : "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.youtube.com" in str(link.get("href")):
			print ("Video POC : "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "youtu.be" in str(link.get("href")):
			print ("Video POC : "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "twitter.com" in str(link.get("href")):
			print ("Twitter POC : "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "blog.0x42424242.in" in str(link.get("href")):
			print ("Blog : "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "medium.com" in str(link.get("href")):
			print ("POC on Medium: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "pentest.com.tr/exploits" in str(link.get("href")):
			print ("POC on unknwon blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "rhinosecuritylabs.com" in str(link.get("href")):
			print ("Security Vendor Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "zer0-day.pw/articles" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "research.digitalinterruption.com" in str(link.get("href")):
			print ("Securit Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "neetech18.blogspot.com" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.vulnerability-lab.com" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "armin.dev/blog" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "lists.openwall.net/full-disclosure" in str(link.get("href")):
			print ("Openwall Disclosure: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "vdalabs.com" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.nccgroup.trust/uk/our-research" in str(link.get("href")):
			print ("Security Vendor Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "pastebin.com" in str(link.get("href")):
			print ("Pastebin: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif ("www.detack.de/en" in str(link.get("href"))):
			print ("Security Vendor Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.detack.de/en" in str(link.get("href")):
			print ("Security Vendor Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "www.pluginvulnerabilities.com" in str(link.get("href")):
			print ("Wordpress Plugin: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "talosintelligence.com/vulnerability_reports" in str(link.get("href")):
			print ("Security Vendor Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		elif "blog.hivint.com" in str(link.get("href")):
			print ("Security Blog: "+str(link.get("href")))
			exploitcollect.append(link.get("href"))
		
		elif "www.securityfocus.com/bid/" in str(link.get("href")):
			Lurl=str(link.get("href"))+"/exploit"
			print ("\033[1;30;40mChecking exploit details in: \033[0;0m"+str(link.get("href")))
			hurl=requests.get(Lurl)
			hurl.text[0:]
			soup2= BeautifulSoup(hurl.text, 'html.parser')
			is_present = bool(re.search('You have entered a malformed request',hurl.text))
			if is_present == True:
				print ("\033[1;31;40mSecurityfocuse found autobot request, Check URL manually  \033[0;0m")
				time.sleep(2)
				exploitcollect.append("Not Confirm:"+str(link.get("href")))
			else:
				right_table5=soup2.find('div',attrs={'id': re.compile("^vulnerability")})
				right_table6=right_table5.find_all('a')
				if right_table6 is not None:
					for link2 in right_table6:
						exploitcollect.append("https://www.securityfocus.com/"+str(link2.get('href')))
				if any("Reports indicate" in s for s in right_table5):
					print ("Exploit found:"+str(link.get("href")))
					exploitcollect.append(link.get("href"))
				elif any("An attacker can" in s for s in right_table5):
					print ("Exploit found:"+str(link.get("href")))
					exploitcollect.append(link.get("href"))
				elif any("researchers" in s for s in right_table5):
					print ("Exploit found:"+str(link.get("href")))
					exploitcollect.append(link.get("href"))
				elif any("Metasploit" in s for s in right_table5):
					print ("Exploit found:"+str(link.get("href")))
					exploitcollect.append(link.get("href"))
				elif any("we are not aware of any working exploits" in s for s in right_table5):
					print ("Scurityfocus: No exploit detail found")
				elif any("Please see the references" in s for s in right_table5):
					print ("POC found:"+str(link.get("href")))
					exploitcollect.append(link.get("href"))
				else:
					print ("\033[1;31;40mNo Exploit found\033[0;0m \n")
		else:
			print (link.get("href"))
		referB.append(link.get("href"))
	exploitcollect.append(awsmPoc(str(x)))
	print ("\n")
	print ("\033[1;31;40mExploit Details:\033[0;0m")
	
	for ii in exploitcollect:
		print (ii)
	print ("=======================================================================================")
	return ";".join(cvcnum),auth,vultype,"\n".join(metaexploit),"\n".join(referB),"\n".join(exploitcollect),desc2,vult
if __name__ == '__main__':
	print ("""
 /$$   /$$           /$$           /$$   /$$     /$$   /$$                       /$$    
| $$  / $$          | $$          |__/  | $$    | $$  | $$                      | $$    
|  $$/ $$/  /$$$$$$ | $$  /$$$$$$  /$$ /$$$$$$  | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$  
 \  $$$$/  /$$__  $$| $$ /$$__  $$| $$|_  $$_/  | $$$$$$$$| $$  | $$| $$__  $$|_  $$_/  
  >$$  $$ | $$  \ $$| $$| $$  \ $$| $$  | $$    | $$__  $$| $$  | $$| $$  \ $$  | $$    
 /$$/\  $$| $$  | $$| $$| $$  | $$| $$  | $$ /$$| $$  | $$| $$  | $$| $$  | $$  | $$ /$$
| $$  \ $$| $$$$$$$/| $$|  $$$$$$/| $$  |  $$$$/| $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/
|__/  |__/| $$____/ |__/ \______/ |__/   \___/  |__/  |__/ \______/ |__/  |__/   \___/  
          | $$                                                                          
          | $$                                                                          
          |__/""")
	print ("=======================================================================================")
	print ("        Coded By : Umang a.k.a H4ck3r B4b4")
	print ("        For Help : XploitHunt.py -h")
	print ("=======================================================================================")
	parser = argparse.ArgumentParser(description="XploitHunt is developed with the aim of automating the task to find public exploit details using CVE-ID/s. In the current version, it is capable of performing the search operation in various websites such as cvedetails, Google and ZeroDay(onion version).",add_help=True,conflict_handler='resolve')
	parser.add_argument("-c", "--cve", dest="cveList", default=None,help="Target CVE-ID/s (i.e. CVE-ID-XXXX-XXXX,CVE-ID-XXXX-XXXX)")
	parser.add_argument("-f", "--file", dest="cveFile", default=None,help="A file containing a list of CVE-IDs to search(i.e. CVE-ID-XXXX-XXXX). One CVE-ID per line. (.txt)")
	parser.add_argument("-g", "--google", dest="GoogleSearch", default="off",help="Google search option. (Default:off, To Enable: on)")
	parser.add_argument("-l", "--limit", dest="SearchCount", default="5",help="Number of results. (Default:5 Search Count)")
	parser.add_argument("-t", "--time", dest="SleepTime", default="15",help="Lapse to wait between HTTP requests. Lapse too short may cause Google to block your IP. Keeping significant lapse will make your program slow but its safe and better option. (Default:15sec)")
	parser.add_argument("-z", "--zeroday", dest="OdaySearch", default="off",help="0day search option. (Default:off, To Enable: on)")
	args = parser.parse_args()
	gcookie()
	internet()
	try:
		os.remove("CVE-Exploit-Map.xlsx")
	except:
		pass

	vult=""
	odaystatus=str(args.OdaySearch)
	if (odaystatus == "on"):
		if ("inactive" == str(torstatuss()).strip()):
			print ("\033[1;31;40mXploitHunt is in Process to start Tor Service...\033[0;0m\n")
			os.system("service tor start")
			time.sleep(2)
		else:
			print ("\033[1;31;40mTor is Installed and running\033[0;0m\n")
	googlestatus=str(args.GoogleSearch)
	googleActiver(args.cveList,args.cveFile)
	os.system("service tor stop")
"""Copyright (C) 2019 Umang Under GNU GPL V3 License"""
