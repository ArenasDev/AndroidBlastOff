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
import glob
import time
import colorama
import warnings
from selenium import webdriver
from termcolor import colored
from lxml import etree
from getpass import getpass
from subprocess import Popen, PIPE
from datetime import datetime
from prettytable import PrettyTable
from prettytable import PLAIN_COLUMNS

args = ""
user_agent_list = [
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

colorama.init()
time1 = ""

def parseArgs():
	global args
	parser = argparse.ArgumentParser(description='Basic tool for automating the initial tasks of Android pentesting')
	parser.add_argument('--apk', default="", help='Path of the apk (default: current path)', required=False)
	parser.add_argument('--playstore', default="", help='[EXPERIMENTAL] PACKAGE name of the app from Play Store (https://play.google.com/store/apps/details?id={PACKAGE_NAME}&hl=es)', required=False)
	parser.add_argument('--adb', default=False, help='Select the apk using adb', required=False, action='store_true')
	parser.add_argument('--device', default="", help='Device to connect to using adb', required=False)
	parser.add_argument('--skipinfo', default=False, help='Skip info tasks (hash, version, etc)', required=False, action='store_true')
	parser.add_argument('--build', default=None, help='Folder of the unpacked APK to build (won\'t decompile or unpack) (can be set to "same" if --sign or --install are set)', required=False)
	parser.add_argument('--sign', default=None, help='Folder of the unpacked APK to sign (won\'t decompile or unpack) (can be set to "same" if --build or --install are set)', required=False)
	parser.add_argument('--install', default=None, help='Folder of the unpacked APK to install (WILL UNINSTALL APK FROM DEVICE and won\'t decompile or unpack) (can be set to "same" if --sign or --build are set)', required=False)
	parser.add_argument('--buildsigninstall', default=False, help='Build, sign and install the apk (WILL UNINSTALL APK FROM DEVICE requires --apk, --playstore or --adb and a device connected through adb)', required=False, action='store_true')
	parser.add_argument('--keystore', default="", help='Keystore to use for signing', required=False)
	parser.add_argument('--keystorepassword', default="", help='Password for the keystore to use for signing', required=False)
	parser.add_argument('--keystorealias', default="", help='Alias for the new keystore to use for signing', required=False)
	parser.add_argument('--keystorealg', default="", help='Algorithm for the new keystore to use for signing', required=False)
	parser.add_argument('--keystorename', default="", help='Name for the new keystore to use for signing', required=False)

	args = parser.parse_args()

	if (args.apk != "" and (args.playstore != "" or args.adb)) or (args.playstore != "" and (args.apk != "" or args.adb)) or (args.adb and (args.playstore != "" or args.apk != "")):
		print colored("[-] --apk, --playstore and --adb are mutually exclusive. Only one can be used", 'red', attrs=['bold'])
	if args.apk == "" and args.playstore == "" and not args.adb and args.sign == None and args.build == None and args.install == None and args.buildsigninstall == False:
		print colored("[-] No option has been selected", 'red', attrs=['bold'])
		parser.print_help()
		sys.exit()

	if args.apk != "" and not os.path.exists(args.apk):
		print colored("[-] File " + args.apk + " does not exist", 'red', attrs=['bold'])
		sys.exit()

	if args.buildsigninstall and args.apk == "" and args.adb == "" and args.playstore == "":
		print colored("[-] Must specify --apk, --adb or --playstore to use --buildsigninstall", 'red', attrs=['bold'])
		sys.exit()

	if args.keystore != "" and args.keystorealias == "":
		print colored("[-] Must specify a keystore alias if a keystore is specified (use --keystorealias)", 'red', attrs=['bold'])
		sys.exit()

	if args.sign != None:
		#remove last slash
		if args.sign[-1:] == "/":
			args.sign = args.sign[:-1]
		elif args.sign == "same":
			#If one parameter (--sign, --install or --build) is set to a folder and another one is not None, set that to the same folder
			if args.install != None and args.install != "same":
				args.sign = args.install
			elif args.build != None and args.build != "same":
				args.sign = args.build

	if args.build != None:
		#remove last slash
		if args.build[-1:] == "/":
			args.build = args.build[:-1]
		elif args.build == "same":
			#If one parameter (--sign, --install or --build) is set to a folder and another one is not None, set that to the same folder
			if args.install != None and args.install != "same":
				args.build = args.install
			elif args.sign != None and args.sign != "same":
				args.build = args.sign

	if args.install != None:
		#remove last slash
		if args.install[-1:] == "/":
			args.install = args.install[:-1]
		elif args.install == "same":
			#If one parameter (--sign, --install or --build) is set to a folder and another one is not None, set that to the same folder
			if args.build != None and args.build != "same":
				args.install = args.build
			elif args.sign != None and args.sign != "same":
				args.install = args.sign

def unpackAndDecompile():
	global args
	if args.apk != "":
		print colored("[+] Unpacking APK using Apktool", 'green', attrs=['bold'])
		print colored("[+] Decompiling APK using enjarify", 'green', attrs=['bold'])
		with concurrent.futures.ThreadPoolExecutor(max_workers=multiprocessing.cpu_count()) as executor:
			executor.map(executeCommand, [["apktool", "d", args.apk, "-f"], ["enjarify", args.apk, "-f"]])

#Connect using adb, show packages and download selected apk
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
		print colored("[+] Available packages:", 'green', attrs=['bold'])
		prettyPrintPackages(packages)
		#get users choice
		selectedPackage = -1
		while True:
			try:
				print colored("[+] Select package to download APK file (0 - " + str(len(packages) - 1) + "):", 'green', attrs=['bold'])
				selectedPackage = int(input())
				break
			except KeyboardInterrupt as e:
				sys.exit()
			except:
				pass
		#Get full path for the APK file
		print colored("[+] Obtaining full path of selected APK", 'green', attrs=['bold'])
		_, output = executeCommand(["adb", "shell", "pm", "path", packages[selectedPackage]])

		#Extract apk into destination
		print colored("[+] Extracting APK", 'green', attrs=['bold'])
		args.apk = output.split("/")[-1].splitlines()[0]
		_, output = executeCommand(["adb", "pull", output.split(":")[1].splitlines()[0], output.split("/")[-1].splitlines()[0]])
		print colored("[+] APK extracted to " + args.apk, 'green', attrs=['bold'])
	else:
		print colored("[-] ADB: Specified device is not found or there is no device.", 'red', attrs=['bold'])
		sys.exit()

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
	print colored(pt, 'green', attrs=['bold'])

def getAPKName():
	global args
	if args.apk:
		return args.apk.replace("\\", "/").split("/")[-1][0:-4]
	else:
		return ""

def executeCommand(command):
	global args
	try:
		cmd = ""
		if type(command) is str:
			cmd = command
		else:
			cmd = command[0]
		try:
			#Check if tool exists
			p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
			output, err = p.communicate()
		except OSError as e:
			print colored("[-] Tool " + cmd + " is not found in the system.\n", 'red', attrs=['bold'])
			os._exit(1)
		p = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
		output, err = p.communicate()
		return True, output
	except OSError as e:
		return False, None
	except Exception as e:
		print colored("[-] " + command[0], 'red', attrs=['bold'])
		print colored(e, 'red', attrs=['bold'])
		return False, None

def processAPK():
	global args
	if not args.sign:
		if args.playstore != "":
			playStore()
		elif args.adb:
			adb()
		unpackAndDecompile()

def playStore2():
	print colored("[+] Trying alternate method", 'yellow', attrs=['bold'])
	req = requests.post("https://api-apk-dl.evozi.com/download", obtainTokens(), verify=True)
	
	if "404" in req.text:
		print colored("[-] APK not found. Check if it is downloadable from https://apps.evozi.com/apk-downloader/", 'red', attrs=['bold'])
		sys.exit()
	else:
		try:
			url = "https://" + req.text[req.text.find("storage.evozi.com"):req.text.find("\",\"obb_url\"")].replace("\\", "")
			req = requests.get(url, allow_redirects=True, timeout=300)
			open(args.playstore + ".apk", "wb").write(req.content)
			print colored("[+] APK downloaded", 'green', attrs=['bold'])
			args.apk = args.playstore + ".apk"
		except:
			print colored("[-] Download failed. Check if it is downloadable from https://apps.evozi.com/apk-downloader/", 'red', attrs=['bold'])
			sys.exit()

def playStore():
	print colored("[*] This feature is experimental (depends on apps.evozi.com)", 'yellow', attrs=['bold'])
	print colored("[*] Downloading APK", 'green', attrs=['bold'])
	warnings.filterwarnings('ignore')
	time1 = time.time()

	driver = webdriver.PhantomJS(service_log_path=os.path.devnull)
	driver.set_window_size(1120, 550)
	driver.get("https://apps.evozi.com/apk-downloader/?id=")
	domain = 'storage.evozi.com'
	check = False
	try:
		for elem in driver.find_elements_by_tag_name("input"):
			aux = elem.get_attribute('placeholder')
			if "play.google.com" in aux or "com.evozi.network" in aux:
				check = True
				elem.send_keys(args.playstore)
		if not check:
			raise Exception("Input field not found in web page")
		check = False

		for elem in driver.find_elements_by_tag_name("button"):
			aux = elem.text
			if "Generate Down" in aux or "oad Link" in aux:
				check = True
				elem.click()

		if not check:
			raise Exception("Button not found in website")

		print colored("[+] Waiting for the download link (This could take a while...)", 'green', attrs=['bold'])
		check = False
		while not check:
			for elem in driver.find_elements_by_tag_name("a"):
				aux = elem.get_attribute('href')
				if aux != None and domain in aux:
					check = True
					print colored("[+] Download link received. Downloading APK", 'green', attrs=['bold'])
					req = requests.get(aux, allow_redirects=True, timeout=180)
					open(args.playstore + ".apk", "wb").write(req.content)
					print colored("[+] APK downloaded", 'green', attrs=['bold'])
					args.apk = args.playstore + ".apk"
					break
			time.sleep(2)
			if (time.time() - time1) > 180:
				raise Exception("Timeout")
	except Exception as e:
		print colored("[-] Download failed", 'red', attrs=['bold'])
		print colored(e, 'red', attrs=['bold'])
		playStore2(args.playstore)

	driver.quit()

#Obtain a mandatory tokens to download from evozi
def obtainTokens():
	req = requests.get("https://apps.evozi.com/apk-downloader/?id=" + args.playstore, headers={'User-Agent': random.choice(user_agent_list)})
	#NTjkzVfJCDIbwLwRt =  { aafcfaaffeadbeadf   : 1571161819,  adbfeeccdfe: ebeGrxcqBYsDWwSvxGL,	  aedfebf:	   olYbP,   fetch: $('#forceRefetch').is(':checked')};
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
	if not args.skipinfo and not args.sign and not args.build and not args.install:
		#Clear contents of info file
		f = open(getAPKName() + "-info.txt", "w")
		f.write("APK name: " + args.apk.split("/")[-1] + "\n")
		f.write("Date: " + str(datetime.now()) + "\n")
		f.close()
		print colored("[+] Calculating hashes", 'green', attrs=['bold'])
		calculateHash()
		print colored("[+] Retrieving version", 'green', attrs=['bold'])
		version()

def calculateHash():
	global args
	md5 = hashlib.md5()
	sha1 = hashlib.sha1()
	sha256 = hashlib.sha256()
	sha512 = hashlib.sha512()
	with open(args.apk, "rb") as f:
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
	for line in open(getAPKName() + "/apktool.yml").readlines():
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

def signAPK():
	global args
	print colored("[+] Signing APK", 'green', attrs=['bold'])
	if args.keystore != "" and len(glob.glob(args.sign + "/dist/*.apk")) == 1:
		if os.path.exists(args.keystore):
			if args.keystorepassword == "":
				while True:
					try:
						args.keystorepassword = getpass("[+] Input keystore password:")
						break
					except KeyboardInterrupt as e:
						sys.exit()
					except:
						pass
		else:
			print colored("[-] Keystore file not found (" + args.keystore + ")", 'red', attrs=['bold'])
	else:
		createKeystore()

	_, output = executeCommand(["jarsigner", "-sigalg", "MD5withRSA", "-digestalg", "SHA1", "-storepass", args.keystorepassword, "-keystore", args.keystore, glob.glob(args.sign + "/dist/*.apk")[0], (args.keystorealias if args.keystorealias else "abo")])

	if "jarsigner error" in output:
		print colored("[-] APK not signed - Incorrect password", 'red', attrs=['bold'])
	elif "jar signed" in output:
		print colored("[+] APK signed", 'green', attrs=['bold'])

def createKeystore():
	global args

	if args.keystorename == "":
		args.keystorename = "abo.keystore"
	elif args.keystorename and not (".keystore" in args.keystorename):
		args.keystorename = args.keystorename + ".keystore"

	if os.path.exists(args.keystorename):
		os.remove(args.keystorename)

	command = ["keytool", "-genkey"] + \
	["-alias"] + ([args.keystorealias] if args.keystorealias else ["abo"]) + \
	["-keyalg"] + ([args.keystorealg] if args.keystorealg else ["RSA"]) + \
	["-keystore"] + ([args.keystorename] if args.keystorename else ["abo.keystore"]) + \
	["-storepass"] + ([args.keystorepassword] if args.keystorepassword else ["abo123abo"]) + \
	["-keysize", "2048", "-validity", "10000"] + \
	["-dname", "CN=ABO, OU=ABO, O=ABO, L=ABO, S=ABO, C=US"]

	print colored("[+] Using internal keystore with:", 'green', attrs=['bold'])
	print colored("\tAlias: " + (args.keystorealias if args.keystorealias != "" else "abo"), 'green', attrs=['bold'])
	print colored("\tAlg: " + (args.keystorealg if args.keystorealg != "" else "RSA"), 'green', attrs=['bold'])
	print colored("\tName: " + (args.keystorename if args.keystorename != "" else "abo.keystore"), 'green', attrs=['bold'])
	print colored("\tPassword: " + (args.keystorepassword if args.keystorepassword != "" else "abo123abo"), 'green', attrs=['bold'])
	print colored("\tKey size: 2048", 'green', attrs=['bold'])
	print colored("\tValidity: 10000", 'green', attrs=['bold'])
	print colored("\tDistinguished name: CN=ABO, OU=ABO, O=ABO, L=ABO, S=ABO, C=US", 'green', attrs=['bold'])
	
	_, output = executeCommand(command)

	args.keystore = args.keystorename
	args.keystorepassword = "abo123abo"

def buildAPK():
	global args
	if args.build != "" and os.path.exists(args.build):
		print colored("[+] Building APK", 'green', attrs=['bold'])
		executeCommand(["apktool", "b", args.build])

def installAPK():
	global args

	_, output = executeCommand(["adb", "devices"])
	device = ""
	if args.device and output.find(args.device) != -1:
		device = args.device
	else:
		device = output.splitlines()[1].split(":")[0]
	if device:
		apk = glob.glob(args.install + "/dist/" + args.install + ".apk")[0]
		
		package = etree.parse(glob.glob(args.install + "/AndroidManifest.xml")[0]).xpath("/manifest")[0].get("package")
			
		#Check if the apk is already installed
		_, output = executeCommand(["adb", "shell", "pm", "list", "packages"])
		if package in output.splitlines():
			#uninstall first the package just in case the signature does not match
			_, output = executeCommand(["adb", "uninstall", package])
			print colored("[+] Uninstalling original APK", 'green', attrs=['bold'])

		#install the apk
		_, output = executeCommand(["adb", "install", apk])

		if "INSTALL_PARSE_FAILED_NO_CERTIFICATES" in output:
			print colored("[-] APK is not signed. Use --sign", 'red', attrs=['bold'])
			sys.exit()
		
		print colored("[+] Installing APK", 'green', attrs=['bold'])
	else:
		print colored("[-] ADB: Specified device is not found or there is no device.", 'red', attrs=['bold'])
		sys.exit()

def buildSignInstall():
	if args.build:
		buildAPK()
	if args.sign:
		signAPK()
	if args.install:
		installAPK()
	if args.buildsigninstall:
		args.sign = args.build = args.install = getAPKName()
		buildAPK()
		signAPK()
		installAPK()

if __name__== "__main__":
	parseArgs()
	processAPK()
	info()
	buildSignInstall()
	