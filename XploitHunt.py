"""
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.If not, see 
<https://www.gnu.org/licenses/>.
"""
import argparse
from xlutils.copy import copy
import subprocess
import xlwt
import xlrd
import os
import os.path
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import re
from bs4 import BeautifulSoup
from netaddr import *
reload(sys)
sys.setdefaultencoding('utf8')
import pprint
import requests
from googlesearch import search
import time
def gcookie():
	for item in os.listdir(os.getcwd()):
		if item.endswith(".google-cookie"):
			#os.remove(".google-cookie")
			os.remove( os.path.join(os.getcwd(), item ) )
	return "working"
def internet(url='http://www.google.com/', timeout=5):
	try:
		req = requests.get(url, timeout=timeout)
		req.raise_for_status()
		return True
	except requests.ConnectionError:
		print "Error: Can you please check your Internet Connection?"
		sys.exit()
def torstatuss():
	p =  subprocess.Popen(["systemctl", "is-active",  "tor"], stdout=subprocess.PIPE)
	(output, err) = p.communicate()
	output = output.decode('utf-8')
	return output

def googleActiver(clist,cfile):
	if clist is not None:
		print "Manual Mode enabled."
		book = xlwt.Workbook()
		sheet1 = book.add_sheet("XplointHunter")
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
				Gexpl="Google option is not enabled"			
			sheet1.write(clist.split(",").index(cvee),9,Gexpl)
			if (str(odaystatus)=="on"):
				Odayexp=odayDetailfinder(str(cvee.strip()))
			else:
				Odayexp="0day search option is not enabled"
			sheet1.write(clist.split(",").index(cvee),10,Odayexp)
		book.save('raw_data.xls')
		raw_data1=xlrd.open_workbook("raw_data.xls")
		sheet1=raw_data1.sheet_by_index(0)
		fs_num_of_col1=sheet1.ncols
		fs_num_of_row1=sheet1.nrows
		book2 = xlwt.Workbook()
		sheet2 = book2.add_sheet("XplointHunter")
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
		sheet2.write(0,0,"CVE")
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
		book2.save('CVE-Exploit-Map.xls')
		os.remove('raw_data.xls')
	elif cfile is not None:
			print "\nAuto File Mode on:\n"
			raw_data=xlrd.open_workbook(cfile)
			vr_raw_data=copy(raw_data)
			sheet=vr_raw_data.get_sheet(0)
			fs_sheet=raw_data.sheet_by_index(0)
			fs_num_of_col=fs_sheet.ncols
			fs_num_of_row=fs_sheet.nrows
			sheet.write(0,1,"Title")
			sheet.write(0,2,"Description")
			sheet.write(0,3,"CVSscore")
			sheet.write(0,4,"Authenticaton")
			sheet.write(0,5,"Vulnerability Type")
			sheet.write(0,6,"Metasploit Module")
			sheet.write(0,7,"References")
			sheet.write(0,8,"Exploit List")
			sheet.write(0,9,"Google Results")
			sheet.write(0,10,"0day Results")
			try:
				vr_raw_data.save("CVE-Exploit-Map.xls")	
			except:
				print "Can you please close the \"CVE-Exploit-Map.xls\" file?"
				sys.exit()
			for j in range(1,fs_num_of_row):
				Fcvs,Fauth,Fvultype,Fmetaexploit,FreferB,Fexploitcollect,Fdesc,Fvult=detailfinder(str(fs_sheet.cell(j,0).value).strip())
				sheet.write(j,1,Fvult)
				sheet.write(j,2,Fdesc)
				sheet.write(j,3,Fcvs)
				sheet.write(j,4,Fauth)
				sheet.write(j,5,Fvultype)
				sheet.write(j,6,Fmetaexploit)
				sheet.write(j,7,FreferB)
				sheet.write(j,8,Fexploitcollect)
				if (str(googlestatus)=="on"):
					Gexpl=googlefinder(str(fs_sheet.cell(j,0).value).strip())
				else:
					Gexpl="Google option is not enabled"
				sheet.write(j,9,Gexpl)
				if (str(odaystatus)=="on"):
					Odayexp=odayDetailfinder(str(fs_sheet.cell(j,0).value).strip())
				else:
					Odayexp="0day search option is not enabled"
				sheet.write(j,10,Odayexp)
					
				vr_raw_data.save("CVE-Exploit-Map.xls")
	else:
		print "Wrong Input"
def googlefinder(cve):
	print "========================================================"
	#query = ["site:exploit-db.com intext:"+str(cve),"intext:"+str(cve),str(cve)+" "+"POC",str(vult)+" "+"POC"]
	print "GoOgle BOT is ready to serve you....!!"
	expp=[]
	query=[]
	googletxt=open("google-payload.txt", "r")
	googlepay=googletxt.readlines()
	googletxt.close
	for g in googlepay:
		gg=g.replace("?",str(cve))
		query.append(str(gg))
	query.append(str(vult)+" "+"POC")
	print "CVE-ID:"+str(cve)
	print "Lapse to wait:"+str(args.SleepTime)
	print "Google Search Count:"+str(args.SearchCount)
	blackh = open("blacklist-host.txt", "r")
	blackhost=blackh.readlines()
	blackh.close
	for i in query:
		gcookie()
		#time.sleep(5)
		if "No title found in Description" in str(i):
			pass
		else:
			print "Searching for:"+str(i)
			try:
				for j in search(i, tld="com", num=int(args.SearchCount), start=0,stop=int(args.SearchCount),pause=float(args.SleepTime), user_agent="Googlebot/2.1"):
					#time.sleep(5)
					if any(str(bl).strip() in str(j).strip() for bl in blackhost):
						pass
					else:
						print j
						expp.append(j)
			except:
				IPB="Google Blocked requests"
				expp.append(IPB)
				print "Unable to make request"
				expp3=list(set(expp))
				return "\n".join(expp3)

	expp2=list(set(expp))
	print "========================================================"
	return "\n".join(expp2)
def odayDetailfinder(concve):
	print "========================================================\n"
	print "0day Search enabled...Entering into Dark web!"
	session = requests.session()
	oday=[]
	session.proxies = {}
	session.proxies['http'] = 'socks5h://localhost:9050'
	session.proxies['https'] = 'socks5h://localhost:9050'
	conurl="http://mvfjfugdwgc5uwho.onion"
	#concve=str(concve)
	value={'agree':'Yes, I agree'}
	conr=session.post(conurl,data=value)
	url ="http://mvfjfugdwgc5uwho.onion/search?search_request=&search_type=1&category=-1&platform=-1&price_from=0&price_to=10000&author_login=&cve="+concve
	r = session.get(url)
	soup= BeautifulSoup(r.text, 'html.parser')
	right_table=soup.find('div',attrs={'class': re.compile("^ExploitTableContent")})

	for meta in right_table.find_all("a"):
		#print meta.get("href")
		if re.search(r"\/exploit.*",str(meta.get("href"))) is not None:
			rawexp=re.search(r"\/exploit.*",str(meta.get("href"))).group()
			rawexp1="http://mvfjfugdwgc5uwho.onion"+str(rawexp)
			print rawexp1
			oday.append(rawexp1)
	return "\n".join(oday)

def detailfinder(x):
	print "========================================================"
	print "CVE-ID: "+str(x)
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
	else:
		print "CVE-Details are Present in Database\n"
	right_table=soup.find('table',class_='details')
	right_table2=soup.find('table',id='vulnrefstable')
	right_table3=soup.find('div',attrs={'style': re.compile("^background-color:")})
	right_table4=soup.find('div',attrs={'id': re.compile("^metasploitmodstable")})
	right_table7=soup.find('div',attrs={'class': re.compile("^cvedetailssummary")})
	
	#Description_gathering
	desc1=right_table7.get_text(strip=True)
	desc2=re.search(r"^.*Publish Date",str(desc1)).group().replace("Publish Date","")
	print "Description:\n"+str(desc2)+"\n"
	if any("aka" in s for s in right_table7):
		print "Vulnerability title:"+str(re.search(r"aka.*",str(desc2)).group().replace("aka",""))+"\n"
		vult=re.search(r"aka.*",str(desc2)).group().replace("aka","")
		#print "Title:"+str(vult)
	else:
		print "Title:No title Found in Description"
		vult="No title found in Description"
	#filter data-CVSscore-Auth status-vulnerability type
	for row in right_table.find_all("tr"):
		cells2=row.find_all('td')
		D.append(cells2[0].find('span'))
	
	for tt in right_table3:
		cvcnum.append(str(tt))
		print "CVSS Score: "+str(tt)

	#D has all data which we required
	D=filter(None, D)
	#Authentication status
	try:
		auth=re.search(r">.*</",str(D[4])).group()
		auth=auth.replace('>','').replace('</','')
		print "Authentication Type: "+str(auth)
	except:
		print "Authentication Type: Not Define"
		auth="Not Define"
	#Vulnerability type
	try:
		vultype=re.search(r">.*</",str(D[6])).group()
		vultype=vultype.replace('>','').replace('</','')
		print "Vulnerability Type: "+str(vultype)
	except:
		print "Vulnerability Type: Not Define"
		vultype="Not Define"
		pass
	print "\n"
	#Metasploit module details
	print "Metasploit Module:"
	for meta in right_table4.find_all("a"):
		metaexploit.append(meta.get("href"))
		print meta.get("href")
	print "\n"
	#Reference Data
	print "References:"
	if right_table2 is None:
		print "No Reference...Age Badhna Muskil hai!!"
		return ";".join(cvcnum),auth,vultype,"\n".join(metaexploit),"No Reference","No Luck",desc2,vult
	else:
		print ""
	for link in right_table2.find_all("a"):
		#Analyzing url for exploits
		if "www.exploit-db.com/exploits" in str(link.get("href")):
			print "Exploit-db link:"+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.rapid7.com/db" in str(link.get("href")):
			print "Rapid7 Link: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "packetstormsecurity.com/files" in str(link.get("href")):
			print "PacketStrom Advisories: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.tenable.com/security/research" in str(link.get("href")):
			print "Tenable Advisories: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "hackerone.com" in str(link.get("href")):
			print "HackerOne Reports: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "seclists.org/fulldisclosure" in str(link.get("href")):
			print "Seclist Archives: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.cloudfoundry.org/blog/" in str(link.get("href")):
			print "Need to verify: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "iwantacve.cn/index.php/archives" in str(link.get("href")):
			print "Need to verify: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "ssd-disclosure.com/archives/" in str(link.get("href")):
			print "POC : "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.youtube.com" in str(link.get("href")):
			print "Video POC : "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "youtu.be" in str(link.get("href")):
			print "Video POC : "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "twitter.com" in str(link.get("href")):
			print "Twitter POC : "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "blog.0x42424242.in" in str(link.get("href")):
			print "Blog : "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "medium.com" in str(link.get("href")):
			print "POC on Medium: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "pentest.com.tr/exploits" in str(link.get("href")):
			print "POC on unknwon blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "rhinosecuritylabs.com" in str(link.get("href")):
			print "Securit Vendor Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "zer0-day.pw/articles" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "research.digitalinterruption.com" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "neetech18.blogspot.com" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.vulnerability-lab.com" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "armin.dev/blog" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "lists.openwall.net/full-disclosure" in str(link.get("href")):
			print "Openwall Disclosure: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "vdalabs.com" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.nccgroup.trust/uk/our-research" in str(link.get("href")):
			print "Securit Vendor Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "pastebin.com" in str(link.get("href")):
			print "Pastebin: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.detack.de/en" in str(link.get("href")):
			print "Securit Vendor Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.detack.de/en" in str(link.get("href")):
			print "Securit Vendor Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "www.pluginvulnerabilities.com" in str(link.get("href")):
			print "Wordpress Plugin: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "talosintelligence.com/vulnerability_reports" in str(link.get("href")):
			print "Securit Vendor Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		elif "blog.hivint.com" in str(link.get("href")):
			print "Securit Blog: "+str(link.get("href"))
			exploitcollect.append(link.get("href"))
		
		elif "www.securityfocus.com/bid/" in str(link.get("href")):
			Lurl=str(link.get("href"))+"/exploit"
			#print "security:"+str(Lurl)
			hurl=requests.get(Lurl)
			hurl.text[0:]
			soup2= BeautifulSoup(hurl.text, 'html.parser')
			right_table5=soup2.find('div',attrs={'id': re.compile("^vulnerability")})
			right_table6=right_table5.find_all('a')
			if right_table6 is not None:
				for link2 in right_table6:
					exploitcollect.append("https://www.securityfocus.com/"+str(link2.get('href')))
			if any("Reports indicate" in s for s in right_table5):
				print "Exploit found:"+str(link.get("href"))
				exploitcollect.append(link.get("href"))
			elif any("An attacker can" in s for s in right_table5):
				print "Exploit found:"+str(link.get("href"))
				exploitcollect.append(link.get("href"))
			elif any("researchers" in s for s in right_table5):
				print "Exploit found:"+str(link.get("href"))
				exploitcollect.append(link.get("href"))
			elif any("Metasploit" in s for s in right_table5):
				print "Exploit found:"+str(link.get("href"))
				exploitcollect.append(link.get("href"))
			elif any("we are not aware of any working exploits" in s for s in right_table5):
				print "No Luck..! \n"
			elif any("Please see the references" in s for s in right_table5):
				print "POC found:"+str(link.get("href"))
				exploitcollect.append(link.get("href"))
			else:
				print "No Exploit found \n"
		else:
			print link.get("href")
		referB.append(link.get("href"))
	
	print "\n"
	print "Exploit details:"
	for ii in exploitcollect:
		print ii
	print "========================================================"
	return ";".join(cvcnum),auth,vultype,"\n".join(metaexploit),"\n".join(referB),"\n".join(exploitcollect),desc2,vult
if __name__ == '__main__':

	parser = argparse.ArgumentParser(description="Coded By : Umang a.k.a H4ck3r B4b4",add_help=True,conflict_handler='resolve')
	parser.add_argument("-c", "--cve", dest="cveList", default=None,help="Provide a list of CVE-IDs separated by commas, or a single CVE-ID")
	parser.add_argument("-f", "--file", dest="cveFile", default=None,help="Provide a excel file containing CVE-IDs, one per line and on column A")
	parser.add_argument("-g", "--google", dest="GoogleSearch", default="off",help="Provide a \"on\" or \"off\" option to enable or disable google search options. (Default:off)")
	parser.add_argument("-l", "--limit", dest="SearchCount", default="5",help="Limit the number of results. (Default:5)")
	parser.add_argument("-t", "--time", dest="SleepTime", default="15",help="Lapse to wait between HTTP requests. Lapse too short may cause Google to block your IP. Keeping significant lapse will make your program slow but its safe and better option. (Default:15)")
	parser.add_argument("-z", "--zeroday", dest="OdaySearch", default="off",help="Provide a \"on\" or \"off\" option to enable or disable 0day search options. (Default:off)")
	args = parser.parse_args()
	gcookie()
	internet()
	try:
		os.remove("CVE-Exploit-Map.xls")
	except:
		pass

	print "========================================================"
	print "        Coded By : Umang a.k.a H4ck3r B4b4"
	print "        For Help : XploitHunt.py -h"
	print "        Note:file.xls which has cve-id listed in column A"
	print "        Copyright (C) 2019 Umang, Under GNU GPL V3 License"
	print "========================================================"
	vult=""
	odaystatus=str(args.OdaySearch)
	if (odaystatus == "on"):
		print "Enabling Tor Service...\n"
		print "Welcom to the Dark Web"
		os.system("service tor start")
		time.sleep(5)
	googlestatus=str(args.GoogleSearch)
	googleActiver(args.cveList,args.cveFile)
	os.system("service tor stop")
"""Copyright (C) 2019 Umang Under GNU GPL V3 License"""
