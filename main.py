'''
If there is a problem like:
requests.exceptions.SSLError: [Errno 1] _ssl.c:510: error:14077410:SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure

Then install the following:
sudo apt-get install python-dev libssl-dev libffi-dev
pip install --user pyopenssl==0.13.1 pyasn1 ndg-httpsclient

'''

import sys
import argparse
import hashlib
import os
import os.path
import concurrent.futures
import multiprocessing
import requests
import random
from subprocess import Popen, PIPE
from datetime import datetime
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS

args = ""
tools = {}
user_agent_list = [
   #Chrome
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
	'Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
	'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36',
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36',
	#Firefox
	'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)',
	'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)',
	'Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)',
	'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
	'Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko',
	'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
	'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
	'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)'
]

def checkTools():
	mandatoryTools = ["apktool", "adb"]
	#optionalTools = [(["jd-gui", "--help"], "jadx"), ("d2j-dex2jar", "enjarify")]
	optionalTools = [("d2j-dex2jar", "enjarify")]

	#Check if mandatory tools are installed
	for tool in mandatoryTools:
		checkTool(tool)
	
	#Check if optional tools are installed (one of the options)
	for tup in optionalTools:
		check = False
		for tool in tup:
			if checkTool(tool):
				check = True
		if not check:
			print "[-] Tools " + str(tup) + " are not found in the system. At least on of them is necessary"
			sys.exit()
	
def checkTool(tool):
	ret, _ = executeCommand(tool)
	if isinstance(tool, list):
		tools[tool[0]] = ret
	else:
		tools[tool] = ret
	return ret

def parseArgs():
	global args
	parser = argparse.ArgumentParser(description='Basic tool for automating the initial tasks of Android pentesting')
	parser.add_argument('--apk', default="", help='Path of the apk (default: current path)', required=False)
	parser.add_argument('--playstore', default="", help='[EXPERIMENTAL] PACKAGE name of the app from Play Store (https://play.google.com/store/apps/details?id={PACKAGE_NAME}&hl=es)', required=False)
	parser.add_argument('--adb', default=False, help='Select the apk using adb', required=False, action='store_true')
	parser.add_argument('--device', default="", help='Device to connect to using adb', required=False)
	parser.add_argument('--outputdir', default=os.getcwd(), help='Directory for the output of tools (default: current directory)', required=False)
	parser.add_argument('--skipinfo', default=False, help='Skip info tasks (hash, version, etc)', required=False, action='store_true')

	args = parser.parse_args()
	if args.outputdir[-1:] != "/":
		args.outputdir += "/"

	if (args.apk != "" and (args.playstore != "" or args.adb)) or (args.playstore != "" and (args.apk != "" or args.adb)) or (args.adb and (args.playstore != "" or args.apk != "")):
		print "--apk, --playstore and --adb are mutually exclusive. Only one can be used"
	if args.apk == "" and args.playstore == "" and not args.adb:
		print "[-] No option has been selected."
		print parser.print_help()

	if args.apk != "" and not os.path.exists(args.apk):
		print "[-] File " + args.apk + " does not exist"
		sys.exit()

def unpackAndDecompile(apk):
	global args
	print "[+] Unpacking APK using Apktool"
	print "[+] Decompiling APK using enjarify"
	with concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
		executor.map(executeCommand, [["apktool", "d", apk, "-f", "-o", args.outputdir + getAPKName()], ["enjarify", apk, "-f", "-o", args.outputdir + getAPKName() + ".jar"]])

#Connect usign adb, show packages and download selected apk
def adb():
	global args
	_, output = executeCommand(["adb", "devices"])
	device = ""
	if args.device and output.find(args.device) != -1:
		device = args.device
	else:
		device = output.splitlines()[1].split(":")[0]
	if device:
		#list all installed packages
		_, output = executeCommand(["adb", "shell", "pm", "list", "packages"])
		packages = output.splitlines()

		packages = [package.split(':')[1].splitlines()[0] for package in packages]
		print "[+] Available packages:"
		prettyPrintPackages(packages)
		#get users choice
		selectedPackage = -1
		while True:
			try:
				selectedPackage = int(input("[+] Select package to download APK file (0 - " + str(len(packages) - 1) + "):"))
				break
			except KeyboardInterrupt as e:
				sys.exit()
			except:
				pass
		#Get full path for the APK file
		print "[+] Obtaining full path of selected APK"
		_, output = executeCommand(["adb", "shell", "pm", "path", packages[selectedPackage]])

		#Extract apk into destination
		print "[+] Extracting APK"
		args.apk = args.outputdir + output.split("/")[-1].splitlines()[0]
		_, output = executeCommand(["adb", "pull", output.split(":")[1].splitlines()[0], args.outputdir + output.split("/")[-1].splitlines()[0]])
		print "[+] APK extracted to " + args.apk
	else:
		print "[-] ADB: Specified device is not found or there is no device."

def prettyPrintPackages(packages):
	pt = PrettyTable()
	pt.set_style(PLAIN_COLUMNS)
	pt.header = False
	terminalWidth, _ = getTerminalSize()
	numberOfColumns = terminalWidth / (len(max(packages, key=len)) + 3)
	rest = terminalWidth % (len(max(packages, key=len)) + 3)
	headers = []
	for i in range(numberOfColumns):
		headers.append(str(i))
	pt.field_names = headers
	for i in range(numberOfColumns):
		pt.align[str(i)] = "l"
	i = 0
	while i < len(packages):
		row = []
		for j in range(0, numberOfColumns):
			try:
				row.append(" [" + str(i) +"]" + packages[i])
			except:
				row.append("")
			i += 1
		pt.add_row(row)
	print(pt)

def getAPKName():
	global args
	return args.apk.replace("\\", "/").split("/")[-1][0:-4]


def executeCommand(command):
	global args
	try:
		p = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		output, err = p.communicate()
		return True, output
	except OSError as e:
		return False, None
	except Exception as e:
		print "[-] " + command[0]
		print e
		return False, None

def processAPK():
	global args
	if args.playstore != "":
		playStore()
	elif args.adb:
		adb()
	unpackAndDecompile(args.apk)

def playStore():
	global args
	
	print "[*] This feature is experimental (depends on apps.evozi.com)"
	print "[+] Downloading APK (This could take a while...)"
	req = requests.post("https://api-apk-dl.evozi.com/download", obtainTokens(), verify=True)
	
	if "404" in req.text:
		print "[-] APK not found. Check if it is downloadable from https://apps.evozi.com/apk-downloader/"
	        sys.exit()
	else:
		try:
			url = "https://" + req.text[req.text.find("storage.evozi.com"):req.text.find("\",\"obb_url\"")].replace("\\", "")
			req = requests.get(url, allow_redirects=True, timeout=300)
			open(args.outputdir + args.playstore + ".apk", "wb").write(req.content)
			args.apk = args.outputdir + args.playstore + ".apk"
		except:
			print "[-] Download failed. Check if it is downloadable from https://apps.evozi.com/apk-downloader/"
			sys.exit()

#Obtain a mandatory tokens to download from evozi
def obtainTokens():
	req = requests.get("https://apps.evozi.com/apk-downloader/?id=" + args.playstore, headers={'User-Agent': random.choice(user_agent_list)})
	#NTjkzVfJCDIbwLwRt =  { aafcfaaffeadbeadf   : 1571161819,  adbfeeccdfe: ebeGrxcqBYsDWwSvxGL,      aedfebf:       olYbP,   fetch: $('#forceRefetch').is(':checked')};
	response = req.text.replace(" ", "").replace("\r", "").replace("\n", "")
	v1 = response.find("type:\"POST\",//crossDomain:true,dataType:\"json\",data:")
	#varName is NTjkzVfJCDIbwLwRt
	varName = response[v1:].split(":")[4].split(",")[0]
	if v1 == -1:
		v1 = response.find("type:\"POST\",dataType:\"json\",data:")
		varName = response[v1:].split(":")[3].split(",")[0]
	
	requestJSONData = response[response.find(varName + "={") + len(varName) + 2:]

	auxToken = response[response.find("var" + str(requestJSONData.split(",")[2].split(":")[1])):].split(";")[0].split("=")[1][1:-1]
	
	return {str(requestJSONData.split(":")[0]) : str(requestJSONData.split(":")[1].split(",")[0]),
			str(requestJSONData.split(":")[1].split(",")[1]) : args.playstore,
			str(requestJSONData.split(":")[2].split(",")[1]) : auxToken,
			"fetch" : "false"}

def info():
	global args
	if not args.skipinfo:
		#Clear contents of info file
		f = open(getAPKName() + "-info.txt", "w")
		f.write("APK name: " + args.apk.split("/")[-1] + "\n")
		f.write("Date: " + str(datetime.now()) + "\n")
		f.close()
		print "[+] Calulating hashes"
		calculateHash()
		print "[+] Retrieving version"
		version()

def calculateHash():
	global args
	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()
	sha512 = hashlib.sha512()
	with open(args.apk,"rb") as f:
		# Read and update hash string value in blocks of 4K
		for byte_block in iter(lambda: f.read(4096),b""):
			md5.update(byte_block)
			sha1.update(byte_block)
			sha256.update(byte_block)
			sha512.update(byte_block)

	f = open(getAPKName() + "-info.txt", "a")
	f.write("MD5: " + md5.hexdigest() + "\n")
	f.write("SHA1: " + sha1.hexdigest() + "\n")
	f.write("SHA256: " + sha256.hexdigest() + "\n")
	f.write("SHA512: " + sha512.hexdigest() + "\n")
	f.close()

def version():
	f = open(getAPKName() + "-info.txt", "a")
	for line in open(args.outputdir + getAPKName() + "/apktool.yml").readlines():
		if line.find("versionCode") != -1:
			f.write("Internal version: " + line.replace("'", "").split(" ")[3])
		if line.find("versionName") != -1:
			f.write("Public version: " + line.replace("'", "").split(" ")[3])
		if line.find("minSdkVersion") != -1:
			f.write("Min SDK: " + line.replace("'", "").split(" ")[3])
		if line.find("targetSdkVersion") != -1:
			f.write("Target SDK: " + line.replace("'", "").split(" ")[3])
	f.close()

def getTerminalSize():
	import fcntl, termios, struct
	th, tw, hp, wp = struct.unpack('HHHH',
		fcntl.ioctl(0, termios.TIOCGWINSZ,
		struct.pack('HHHH', 0, 0, 0, 0)))
	return tw, th

if __name__== "__main__":
	checkTools()
	parseArgs()
	processAPK()
	info()
