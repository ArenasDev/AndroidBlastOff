# AndroidBlastOff
A tool to speed up Android pentesting by automating the APK acquisition and initial information gathering.

Moved to only Python 3

Features:
- Extract from an adb connected device (listing all available packages)
- Work with a local copy of an APK
- Extract initial information (Timestamp, MD5, SHA1, SHA256, SHA512, internal version, public version, and min and target SDK)
- Build apk from decompiled
- Sign apk
- Install apk (through adb)
- Or build, sign and install automatically

Parameters:

	-h, --help            show this help message and exit
	--apk APK             Path of the apk (default: current path)
	--adb                 Select the apk using adb
	--device DEVICE       Device to connect to using adb
	--skipinfo            Skip info tasks (hash, version, etc)
	--build BUILD         Folder of the unpacked APK to build (won't decompile or unpack) (can be set to "same" if --sign or --install are set)
	--sign SIGN           Folder of the unpacked APK to sign (won't decompile or unpack) (can be set to "same" if --build or --install are set)
	--install INSTALL     Folder of the unpacked APK to install (WILL UNINSTALL APK FROM DEVICE and won't decompile or unpack) (can be set to "same" if --sign or --build are set)
	--bsi BSI             Build, sign and install the apk (WILL UNINSTALL APK FROM DEVICE requires --apk, --playstore or --adb and a device connected through adb)
	--keystore KEYSTORE   Keystore to use for signing
	--keystorepassword KEYSTOREPASSWORD
	                    Password for the keystore to use for signing
	--keystorealias KEYSTOREALIAS
	                    Alias for the new keystore to use for signing
	--keystorealg KEYSTOREALG
	                    Algorithm for the new keystore to use for signing
	--keystorename KEYSTORENAME
	                    Name for the new keystore to use for signing

Example of use

	Perform operations with a local copy of APK:
	        abo --apk {PATH_TO_LOCAL_APK}
	Get APK using ADB (requires a connection via ADB):
	        abo --adb
	Get APK using ADB using specific device (requires a connection via ADB):
	        abo --adb --device {IP_ADDRESS_OF_ADB_CONNECTED_DEVICE}
	Skip info tasks:
	        abo --skipinfo
	Build an unpacked app:
	        abo --build {FOLDER_OF_UNPACKED_APK}
	Sign an unpacked app:
	        abo --sign {FOLDER_OF_UNPACKED_APK}
	Install an unpacked app (requires a connection via ADB):
	        abo --install {FOLDER_OF_UNPACKED_APK}
	Install an unpacked app using specific device(requires a connection via ADB):
	        abo --install {FOLDER_OF_UNPACKED_APK} --device {IP_ADDRESS_OF_ADB_CONNECTED_DEVICE}
	Build, sign and install an unpacked app (requires a connection via ADB):
	        abo --bsi {FOLDER_OF_UNPACKED_APK}
	Build, sign and install an unpacked app (requires a connection via ADB):
	        abo --bsi {FOLDER_OF_UNPACKED_APK} --device {IP_ADDRESS_OF_ADB_CONNECTED_DEVICE}

	ADITIONAL
	Use specific keystore for signing:
	        --keystore {PATH_TO_KEYSTORE}
	Use specific keystore for signing specifying its password and alias:
	        --keystore {PATH_TO_KEYSTORE} --keystorepassword {PASSWORD} --keystorealias {ALIAS}
	Use specific algorithm for signing (only when custom keystore is not specified):
	        --keystorealg {ALGORITHM}
	Name for the keystore that will be created (only when custom keystore is not specified):
	        --keystorename {NAME}
