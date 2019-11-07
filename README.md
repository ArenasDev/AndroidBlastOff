# AndroidBlastOff
A tool to speed up Android pentesting by automating the APK acquisition and initial information gathering.

Features:
- Extract from an adb connected device (listing all available packages)
- Download the latest version of the APK from Play Store (thanks to evozi.com, pls do not brute force them)
- Work with a local copy of an APK
- Extract initial information (Timestamp, MD5, SHA1, SHA256, SHA512, internal version, public version, and min and target SDK)
- Build apk from decompiled
- Sign apk
- Install apk (through adb)
- Or build, sign and install automatically

TODO:
- Implement more ways of downloading the APK (find other providers)
