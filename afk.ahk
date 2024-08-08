#NoEnv
SendMode Input
SetWorkingDir %A_ScriptDir%
#SingleInstance force
Menu Tray, Icon, shell32.dll, 286
RunWith(32)
global uiHotkey := f1
global objOffset = 0x04
global vfxOffset = 0x2C
global drawOffset = 0x28
global shaderOffset = 0x1C
global pointer = 0x00FD9D88
global rpointer = 0x00FD9D28
global fishpointer = 0x00FAB7F0
global ptrScan = "A1 ?? ?? ?? ?? 8B 40 ?? 85 C0 74 ?? 0F 28 ?? ?? EB 07 0F 28 05 ?? ?? ?? ?? 80"
global rptrScan = "A1 ?? ?? ?? ?? 80 78 ?? ?? 75 4C A1 ?? ?? ?? ?? 85 C0 74 43 DD ?? ?? DD"
global fishptrScan = "53 6A 00 51 8B ?? ?? ?? ?? ?? E8"
global usernameOffsetString := "0x0+0x28+0x54+0x1ac+0x0"
titleScript := "AFK Script decompiled by https://github.com/DecompiledTrove"
trueBreak := 0
Settings := LoadSettings()
FailSafe := 1
AccountName := ""
AccountEmail := ""
AccountPassword := ""
AutoM1 := 0
AutoM2 := 0
AutoSpecial1 := 0
AutoSpecial2 := 0
AutoRButton := 0
AutoTButton := 0
AutoLoot := 0
AutoReconnect := 0
OneTimeActDelayed:= 15000
AutoPvP:= 0
FXDisable := 0
badGraphic := 0
DisableAccount := 0
winX := 0
winY := 0
winW := 480
winH := 480
maxAccounts := 100
UserTableRowBeingEdited := 0
global Privacy := 0
windowFirstStartStates := {}
isWaited := 0
HowToText := "You must add Name, Email, Password to be able to use this script.`nYou have to edit your edit your hotkeys ingame to this:"
HowToGlyph := "1. Open Autohotkey Dash (should be installed if you have Autohotkey installed).`n2. Click Windows Spy.`n3. Hower Over each Button on the Glyph Launcher and note down the Positions.`n4. Change The Glyph Positions on the Tab 'Hotkeys' to the ones you just note down.`n5. Press the Save button."
Credits := "https://github.com/DecompiledTrove"
Loop{
Gosub, LoadUiHotkeysFromINI
if(!FailSafe) {
for index, value in Settings
{
if(value[13])
continue
if(WinExist(value[1])){
cm := new _ClassMemory("ahk_exe Trove.exe", "", hProcessCopy)
WinGet, pidstart, PID, ahk_exe Trove.exe
WinGet, hwndstart, ID, ahk_pid %pidstart%
Base := getProcessBaseAddress(hwndstart)
pointer := IntToHex(ReadMemory(cm.processPatternScan(,, cm.hexStringToPattern(ptrScan)*)+1, pidstart) - Base)
rpointer := IntToHex(ReadMemory(cm.processPatternScan(,, cm.hexStringToPattern(rptrScan)*)+1, pidstart) - Base)
fishpointer := IntToHex(ReadMemory(cm.processPatternScan(,, cm.hexStringToPattern(fishptrScan)*)+6, pidstart) - Base)
usernameAdress := GetAddress(pidstart, Base, pointer, usernameOffsetString)
username :=  ReadMemory_Str(usernameAdress, ,pidstart)
getProcessBaseAddress(Handle) {
Return DllCall( A_PtrSize = 4
? "GetWindowLong"
: "GetWindowLongPtr"
, "Ptr", Handle
, "Int", -6
, "Int64")
}
IntToHex(int)
{
HEX_INT := 8
while (HEX_INT--)
{
n := (int >> (HEX_INT * 4)) & 0xf
h .= n > 9 ? chr(0x37 + n) : n
if (HEX_INT == 0 && HEX_INT//2 == 0)
h .= " "
}
return "0x" h
}
ReadMemory(MADDRESS, pid) {
VarSetCapacity(MVALUE,4,0)
ProcessHandle := DllCall("OpenProcess", "Int", 24, "Char", 0, "UInt", pid, "UInt")
DllCall("ReadProcessMemory", "UInt", ProcessHandle, "Ptr", MADDRESS, "Ptr", &MVALUE, "Uint",4)
Loop 4
result += *(&MVALUE + A_Index-1) << 8*(A_Index-1)
DllCall("CloseHandle", "ptr", ProcessHandle)
Return, result
}
class _ClassMemory
{
static baseAddress, hProcess, PID, currentProgram
, insertNullTerminator := True
, readStringLastError := False
, isTarget64bit := False
, ptrType := "UInt"
, aTypeSize := {"UChar":1, "Char": 1, "UShort": 2, "Short": 2, "UInt": 4, "Int": 4, "UFloat": 4, "Float": 4, "Int64": 8, "Double": 8}
, aRights := {"PROCESS_ALL_ACCESS": 0x001F0FFF, "PROCESS_CREATE_PROCESS": 0x0080, "PROCESS_CREATE_THREAD": 0x0002, "PROCESS_DUP_HANDLE": 0x0040, "PROCESS_QUERY_INFORMATION": 0x0400, "PROCESS_QUERY_LIMITED_INFORMATION": 0x1000, "PROCESS_SET_INFORMATION": 0x0200, "PROCESS_SET_QUOTA": 0x0100, "PROCESS_SUSPEND_RESUME": 0x0800, "PROCESS_TERMINATE": 0x0001, "PROCESS_VM_OPERATION": 0x0008, "PROCESS_VM_READ": 0x0010, "PROCESS_VM_WRITE": 0x0020, "SYNCHRONIZE": 0x00100000}
__new(program, dwDesiredAccess := "", byRef handle := "", windowMatchMode := 3)
{
if this.PID := handle := this.findPID(program, windowMatchMode)
{
if dwDesiredAccess is not integer
dwDesiredAccess := this.aRights.PROCESS_QUERY_INFORMATION | this.aRights.PROCESS_VM_OPERATION | this.aRights.PROCESS_VM_READ | this.aRights.PROCESS_VM_WRITE
dwDesiredAccess |= this.aRights.SYNCHRONIZE
if this.hProcess := handle := this.OpenProcess(this.PID, dwDesiredAccess)
{
this.pNumberOfBytesRead := DllCall("GlobalAlloc", "UInt", 0x0040, "Ptr", A_PtrSize, "Ptr")
this.pNumberOfBytesWritten := DllCall("GlobalAlloc", "UInt", 0x0040, "Ptr", A_PtrSize, "Ptr")
this.readStringLastError := False
this.currentProgram := program
if this.isTarget64bit := this.isTargetProcess64Bit(this.PID, this.hProcess, dwDesiredAccess)
this.ptrType := "Int64"
else this.ptrType := "UInt"
if (A_PtrSize != 4 || !this.isTarget64bit)
this.BaseAddress := this.getModuleBaseAddress()
if this.BaseAddress < 0 || !this.BaseAddress
this.BaseAddress := this.getProcessBaseAddress(program, windowMatchMode)
return this
}
}
return
}
__delete()
{
this.closeHandle(this.hProcess)
if this.pNumberOfBytesRead
DllCall("GlobalFree", "Ptr", this.pNumberOfBytesRead)
if this.pNumberOfBytesWritten
DllCall("GlobalFree", "Ptr", this.pNumberOfBytesWritten)
return
}
version()
{
return 2.92
}
findPID(program, windowMatchMode := "3")
{
if RegExMatch(program, "i)\s*AHK_PID\s+(0x[[:xdigit:]]+|\d+)", pid)
return pid1
if windowMatchMode
{
mode := A_TitleMatchMode
StringReplace, windowMatchMode, windowMatchMode, 0x
SetTitleMatchMode, %windowMatchMode%
}
WinGet, pid, pid, %program%
if windowMatchMode
SetTitleMatchMode, %mode%
if (!pid && RegExMatch(program, "i)\bAHK_EXE\b\s*(.*)", fileName))
{
filename := RegExReplace(filename1, "i)\bahk_(class|id|pid|group)\b.*", "")
filename := trim(filename)
SplitPath, fileName , fileName
if (fileName)
{
process, Exist, %fileName%
pid := ErrorLevel
}
}
return pid ? pid : 0
}
isHandleValid()
{
return 0x102 = DllCall("WaitForSingleObject", "Ptr", this.hProcess, "UInt", 0)
}
openProcess(PID, dwDesiredAccess)
{
r := DllCall("OpenProcess", "UInt", dwDesiredAccess, "Int", False, "UInt", PID, "Ptr")
if (!r && A_LastError = 5)
{
this.setSeDebugPrivilege(true)
if (r2 := DllCall("OpenProcess", "UInt", dwDesiredAccess, "Int", False, "UInt", PID, "Ptr"))
return r2
DllCall("SetLastError", "UInt", 5)
}
return r ? r : ""
}
closeHandle(hProcess)
{
return DllCall("CloseHandle", "Ptr", hProcess)
}
numberOfBytesRead()
{
return !this.pNumberOfBytesRead ? -1 : NumGet(this.pNumberOfBytesRead+0, "Ptr")
}
numberOfBytesWritten()
{
return !this.pNumberOfBytesWritten ? -1 : NumGet(this.pNumberOfBytesWritten+0, "Ptr")
}
read(address, type := "UInt", aOffsets*)
{
if !this.aTypeSize.hasKey(type)
return "", ErrorLevel := -2
if DllCall("ReadProcessMemory", "Ptr", this.hProcess, "Ptr", aOffsets.maxIndex() ? this.getAddressFromOffsets(address, aOffsets*) : address, type "*", result, "Ptr", this.aTypeSize[type], "Ptr", this.pNumberOfBytesRead)
return result
return
}
readRaw(address, byRef buffer, bytes := 4, aOffsets*)
{
VarSetCapacity(buffer, bytes)
return DllCall("ReadProcessMemory", "Ptr", this.hProcess, "Ptr", aOffsets.maxIndex() ? this.getAddressFromOffsets(address, aOffsets*) : address, "Ptr", &buffer, "Ptr", bytes, "Ptr", this.pNumberOfBytesRead)
}
pointer(address, finalType := "UInt", offsets*)
{
For index, offset in offsets
address := this.Read(address, this.ptrType) + offset
Return this.Read(address, finalType)
}
getAddressFromOffsets(address, aOffsets*)
{
return aOffsets.Remove() + this.pointer(address, this.ptrType, aOffsets*)
}
getProcessBaseAddress(windowTitle, windowMatchMode := "3")
{
if (windowMatchMode && A_TitleMatchMode != windowMatchMode)
{
mode := A_TitleMatchMode
StringReplace, windowMatchMode, windowMatchMode, 0x
SetTitleMatchMode, %windowMatchMode%
}
WinGet, hWnd, ID, %WindowTitle%
if mode
SetTitleMatchMode, %mode%
if !hWnd
return
return DllCall(A_PtrSize = 4
? "GetWindowLong"
: "GetWindowLongPtr"
, "Ptr", hWnd, "Int", -6, A_Is64bitOS ? "Int64" : "UInt")
}
getModuleBaseAddress(moduleName := "", byRef aModuleInfo := "")
{
aModuleInfo := ""
if (moduleName = "")
moduleName := this.GetModuleFileNameEx(0, True)
if r := this.getModules(aModules, True) < 0
return r
return aModules.HasKey(moduleName) ? (aModules[moduleName].lpBaseOfDll, aModuleInfo := aModules[moduleName]) : -1
}
setSeDebugPrivilege(enable := True)
{
h := DllCall("OpenProcess", "UInt", 0x0400, "Int", false, "UInt", DllCall("GetCurrentProcessId"), "Ptr")
DllCall("Advapi32.dll\OpenProcessToken", "Ptr", h, "UInt", 32, "PtrP", t)
VarSetCapacity(ti, 16, 0)
NumPut(1, ti, 0, "UInt")
DllCall("Advapi32.dll\LookupPrivilegeValue", "Ptr", 0, "Str", "SeDebugPrivilege", "Int64P", luid)
NumPut(luid, ti, 4, "Int64")
if enable
NumPut(2, ti, 12, "UInt")
r := DllCall("Advapi32.dll\AdjustTokenPrivileges", "Ptr", t, "Int", false, "Ptr", &ti, "UInt", 0, "Ptr", 0, "Ptr", 0)
DllCall("CloseHandle", "Ptr", t)
DllCall("CloseHandle", "Ptr", h)
return r
}
isTargetProcess64Bit(PID, hProcess := "", currentHandleAccess := "")
{
if !A_Is64bitOS
return False
else if !hProcess || !(currentHandleAccess & (this.aRights.PROCESS_QUERY_INFORMATION | this.aRights.PROCESS_QUERY_LIMITED_INFORMATION))
closeHandle := hProcess := this.openProcess(PID, this.aRights.PROCESS_QUERY_INFORMATION)
if (hProcess && DllCall("IsWow64Process", "Ptr", hProcess, "Int*", Wow64Process))
result := !Wow64Process
return result, closeHandle ? this.CloseHandle(hProcess) : ""
}
getModules(byRef aModules, useFileNameAsKey := False)
{
if (A_PtrSize = 4 && this.IsTarget64bit)
return -4
aModules := []
if !moduleCount := this.EnumProcessModulesEx(lphModule)
return -3
loop % moduleCount
{
this.GetModuleInformation(hModule := numget(lphModule, (A_index - 1) * A_PtrSize), aModuleInfo)
aModuleInfo.Name := this.GetModuleFileNameEx(hModule)
filePath := aModuleInfo.name
SplitPath, filePath, fileName
aModuleInfo.fileName := fileName
if useFileNameAsKey
aModules[fileName] := aModuleInfo
else aModules.insert(aModuleInfo)
}
return moduleCount
}
GetModuleFileNameEx(hModule := 0, fileNameNoPath := False)
{
VarSetCapacity(lpFilename, 2048 * (A_IsUnicode ? 2 : 1))
DllCall("psapi\GetModuleFileNameEx", "Ptr", this.hProcess, "Ptr", hModule, "Str", lpFilename, "Uint", 2048 / (A_IsUnicode ? 2 : 1))
if fileNameNoPath
SplitPath, lpFilename, lpFilename
return lpFilename
}
EnumProcessModulesEx(byRef lphModule, dwFilterFlag := 0x03)
{
lastError := A_LastError
size := VarSetCapacity(lphModule, 4)
loop
{
DllCall("psapi\EnumProcessModulesEx", "Ptr", this.hProcess, "Ptr", &lphModule, "Uint", size, "Uint*", reqSize, "Uint", dwFilterFlag)
if ErrorLevel
return 0
else if (size >= reqSize)
break
else size := VarSetCapacity(lphModule, reqSize)
}
DllCall("SetLastError", "UInt", lastError)
return reqSize // A_PtrSize
}
GetModuleInformation(hModule, byRef aModuleInfo)
{
VarSetCapacity(MODULEINFO, A_PtrSize * 3), aModuleInfo := []
return DllCall("psapi\GetModuleInformation"
, "Ptr", this.hProcess
, "Ptr", hModule
, "Ptr", &MODULEINFO
, "UInt", A_PtrSize * 3)
, aModuleInfo := { lpBaseOfDll: numget(MODULEINFO, 0, "Ptr"), SizeOfImage: numget(MODULEINFO, A_PtrSize, "UInt"), EntryPoint: numget(MODULEINFO, A_PtrSize * 2, "Ptr") }
}
hexStringToPattern(hexString)
{
AOBPattern := []
hexString := RegExReplace(hexString, "(\s|0x)")
StringReplace, hexString, hexString, ?, ?, UseErrorLevel
wildCardCount := ErrorLevel
if !length := StrLen(hexString)
return -1
else if RegExMatch(hexString, "[^0-9a-fA-F?]")
return -2
else if Mod(wildCardCount, 2)
return -3
else if Mod(length, 2)
return -4
loop, % length/2
{
value := "0x" SubStr(hexString, 1 + 2 * (A_index-1), 2)
AOBPattern.Insert(value + 0 = "" ? "?" : value)
}
return AOBPattern
}
stringToPattern(string, encoding := "UTF-8", insertNullTerminator := False)
{
if !length := StrLen(string)
return -1
AOBPattern := []
encodingSize := (encoding = "utf-16" || encoding = "cp1200") ? 2 : 1
requiredSize := StrPut(string, encoding) * encodingSize - (insertNullTerminator ? 0 : encodingSize)
VarSetCapacity(buffer, requiredSize)
StrPut(string, &buffer, length + (insertNullTerminator ? 1 : 0), encoding)
loop, % requiredSize
AOBPattern.Insert(NumGet(buffer, A_Index-1, "UChar"))
return AOBPattern
}
processPatternScan(startAddress := 0, endAddress := "", aAOBPattern*)
{
address := startAddress
if endAddress is not integer
endAddress := this.isTarget64bit ? (A_PtrSize = 8 ? 0x7FFFFFFFFFF : 0xFFFFFFFF) : 0x7FFFFFFF
MEM_COMMIT := 0x1000, MEM_MAPPED := 0x40000, MEM_PRIVATE := 0x20000
PAGE_NOACCESS := 0x01, PAGE_GUARD := 0x100
if !patternSize := this.getNeedleFromAOBPattern(patternMask, AOBBuffer, aAOBPattern*)
return -10
while address <= endAddress
{
if !this.VirtualQueryEx(address, aInfo)
return -1
if A_Index = 1
aInfo.RegionSize -= address - aInfo.BaseAddress
if (aInfo.State = MEM_COMMIT)
&& !(aInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD))
&& aInfo.RegionSize >= patternSize
&& (result := this.PatternScan(address, aInfo.RegionSize, patternMask, AOBBuffer))
{
if result < 0
return -2
else if (result + patternSize - 1 <= endAddress)
return result
else return 0
}
address += aInfo.RegionSize
}
return 0
}
getNeedleFromAOBPattern(byRef patternMask, byRef needleBuffer, aAOBPattern*)
{
patternMask := "", VarSetCapacity(needleBuffer, aAOBPattern.MaxIndex())
for i, v in aAOBPattern
patternMask .= (v + 0 = "" ? "?" : "x"), NumPut(round(v), needleBuffer, A_Index - 1, "UChar")
return round(aAOBPattern.MaxIndex())
}
VirtualQueryEx(address, byRef aInfo)
{
if (aInfo.__Class != "_ClassMemory._MEMORY_BASIC_INFORMATION")
aInfo := new this._MEMORY_BASIC_INFORMATION()
return aInfo.SizeOfStructure = DLLCall("VirtualQueryEx", "Ptr", this.hProcess, "Ptr", address, "Ptr", aInfo.pStructure, "Ptr", aInfo.SizeOfStructure, "Ptr")
}
patternScan(startAddress, sizeOfRegionBytes, byRef patternMask, byRef needleBuffer)
{
if !this.readRaw(startAddress, buffer, sizeOfRegionBytes)
return -1
if (offset := this.bufferScanForMaskedPattern(&buffer, sizeOfRegionBytes, patternMask, &needleBuffer)) >= 0
return startAddress + offset
else return 0
}
bufferScanForMaskedPattern(hayStackAddress, sizeOfHayStackBytes, byRef patternMask, needleAddress, startOffset := 0)
{
static p
if !p
{
if A_PtrSize = 4
p := this.MCode("1,x86:8B44240853558B6C24182BC5568B74242489442414573BF0773E8B7C241CBB010000008B4424242BF82BD8EB038D49008B54241403D68A0C073A0A740580383F750B8D0C033BCD74174240EBE98B442424463B74241876D85F5E5D83C8FF5BC35F8BC65E5D5BC3")
else
p := this.MCode("1,x64:48895C2408488974241048897C2418448B5424308BF2498BD8412BF1488BF9443BD6774A4C8B5C24280F1F800000000033C90F1F400066660F1F840000000000448BC18D4101418D4AFF03C80FB60C3941380C18740743803C183F7509413BC1741F8BC8EBDA41FFC2443BD676C283C8FF488B5C2408488B742410488B7C2418C3488B5C2408488B742410488B7C2418418BC2C3")
}
if (needleSize := StrLen(patternMask)) + startOffset > sizeOfHayStackBytes
return -1
if (sizeOfHayStackBytes > 0)
return DllCall(p, "Ptr", hayStackAddress, "UInt", sizeOfHayStackBytes, "Ptr", needleAddress, "UInt", needleSize, "AStr", patternMask, "UInt", startOffset, "cdecl int")
return -2
}
MCode(mcode)
{
static e := {1:4, 2:1}, c := (A_PtrSize=8) ? "x64" : "x86"
if !regexmatch(mcode, "^([0-9]+),(" c ":|.*?," c ":)([^,]+)", m)
return
if !DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", 0, "uint", e[m1], "ptr", 0, "uint*", s, "ptr", 0, "ptr", 0)
return
p := DllCall("GlobalAlloc", "uint", 0, "ptr", s, "ptr")
DllCall("VirtualProtect", "ptr", p, "ptr", s, "uint", 0x40, "uint*", op)
if DllCall("crypt32\CryptStringToBinary", "str", m3, "uint", 0, "uint", e[m1], "ptr", p, "uint*", s, "ptr", 0, "ptr", 0)
return p
DllCall("GlobalFree", "ptr", p)
return
}
class _MEMORY_BASIC_INFORMATION
{
__new()
{
if !this.pStructure := DllCall("GlobalAlloc", "UInt", 0, "Ptr", this.SizeOfStructure := A_PtrSize = 8 ? 48 : 28, "Ptr")
return ""
return this
}
__Delete()
{
DllCall("GlobalFree", "Ptr", this.pStructure)
}
__get(key)
{
static aLookUp := A_PtrSize = 8
? {"BaseAddress": {"Offset": 0, "Type": "Int64"}, "AllocationBase": {"Offset": 8, "Type": "Int64"}, "AllocationProtect": {"Offset": 16, "Type": "UInt"}, "RegionSize": {"Offset": 24, "Type": "Int64"}, "State": {"Offset": 32, "Type": "UInt"}, "Protect": {"Offset": 36, "Type": "UInt"}, "Type": {"Offset": 40, "Type": "UInt"} }
: {"BaseAddress": {"Offset": 0, "Type": "UInt"}, "AllocationBase": {"Offset": 4, "Type": "UInt"}, "AllocationProtect": {"Offset": 8, "Type": "UInt"}, "RegionSize": {"Offset": 12, "Type": "UInt"}, "State": {"Offset": 16, "Type": "UInt"}, "Protect": {"Offset": 20, "Type": "UInt"}, "Type": {"Offset": 24, "Type": "UInt"} }
if aLookUp.HasKey(key)
return numget(this.pStructure+0, aLookUp[key].Offset, aLookUp[key].Type)
}
__set(key, value)
{
static aLookUp := A_PtrSize = 8
? {"BaseAddress": {"Offset": 0, "Type": "Int64"}, "AllocationBase": {"Offset": 8, "Type": "Int64"}, "AllocationProtect": {"Offset": 16, "Type": "UInt"}, "RegionSize": {"Offset": 24, "Type": "Int64"}, "State": {"Offset": 32, "Type": "UInt"}, "Protect": {"Offset": 36, "Type": "UInt"}, "Type": {"Offset": 40, "Type": "UInt"} }
: {"BaseAddress": {"Offset": 0, "Type": "UInt"}, "AllocationBase": {"Offset": 4, "Type": "UInt"}, "AllocationProtect": {"Offset": 8, "Type": "UInt"}, "RegionSize": {"Offset": 12, "Type": "UInt"}, "State": {"Offset": 16, "Type": "UInt"}, "Protect": {"Offset": 20, "Type": "UInt"}, "Type": {"Offset": 24, "Type": "UInt"} }
if aLookUp.HasKey(key)
{
NumPut(value, this.pStructure+0, aLookUp[key].Offset, aLookUp[key].Type)
return value
}
}
Ptr()
{
return this.pStructure
}
sizeOf()
{
return this.SizeOfStructure
}
}
}
}
if(value[4])
{
if(WinExist(value[1]))
{
ControlSend, , {3 up}, % value[1]
Sleep, 200
ControlSend, , {3 down}, % value[1]
}
}
if(value[5])
{
if(WinExist(value[1]))
{
ControlSend, , {4 down}, % value[1]
Sleep, 200
ControlSend, , {4 up}, % value[1]
}
}
if(value[6])
{
if(WinExist(value[1]))
{
ControlSend, , {1 down}, % value[1]
Sleep, 200
ControlSend, , {1 up}, % value[1]
}
}
if(value[7])
{
if(WinExist(value[1]))
{
ControlSend, , {2 down}, % value[1]
Sleep, 300
ControlSend, , {2 up}, % value[1]
}
}
if(value[8])
{
if(WinExist(value[1]))
{
ControlSend, , {r down}, % value[1]
Sleep, 6000
ControlSend, , {r up}, % value[1]
}
}
if(value[9])
{
if(WinExist(value[1]))
{
ControlSend, , {t down}, % value[1]
Sleep, 6000
ControlSend, , {t up}, % value[1]
}
}
if(value[10])
{
if(WinExist(value[1]))
{
ControlSend, , {e down}, % value[1]
Sleep, 500
ControlSend, , {e up}, % value[1]
}
}
if (!windowFirstStartStates[value[1]])
{
if(WinExist(value[1])) {
if(value[18]) {
if(WinExist(value[1]))
{
if (!isWaited) {
Sleep, % value[19]
isWaited := 1
}
ControlSend, , {LCtrl down}, % value[1]
Sleep, 100
ControlSend, , {b down}, % value[1]
Sleep, 100
ControlSend, , {b up}, % value[1]
Sleep, 100
ControlSend, , {LCtrl up}, % value[1]
Sleep, 200
}
}
if(value[12]) {
if(WinExist(value[1]))
{
if (!isWaited) {
Sleep, % value[19]
isWaited := 1
}
ControlSend, , {Enter}, % value[1]
ControlSend, , /drawdistance 0, % value[1]
ControlSend, , {Enter}, % value[1]
Sleep 600
ControlSend, , {Enter}, % value[1]
ControlSend, , /fxenable 0, % value[1]
ControlSend, , {Enter}, % value[1]
Sleep 600
ControlSend, , {Enter}, % value[1]
ControlSend, , /objdistance 0, % value[1]
ControlSend, , {Enter}, % value[1]
Sleep, 200
}
}
if (value[20]) {
if(WinExist(value[1]))
{
if (!isWaited) {
Sleep, % value[19]
isWaited := 1
}
if(!value[20]){
break
}
tmp := value[1]
WinGetActiveTitle, %tmp%
WinGet, hwnd, ID, %tmp%
WinGet, pid, PID, %tmp%
Base := getProcessBaseAddress(hwnd)
vfxAddr := GetAddress(pid, Base, rpointer, vfxOffset)
shaderAddr := GetAddress(pid, Base, rpointer, shaderOffset)
drawAddr := GetAddress(pid, Base, rpointer, drawOffset)
objAddr := GetAddress(pid, Base, rpointer, objOffset)
WriteProcessMemory(pid, vfxAddr, FloatToHex(0), 4)
WriteProcessMemory(pid, shaderAddr, FloatToHex(0), 4)
WriteProcessMemory(pid, drawAddr, FloatToHex(0), 4)
WriteProcessMemory(pid, objAddr, FloatToHex(0), 4)
}
}
windowFirstStartStates[value[1]] := 1
}
}
if(!WinExist(value[1]))
{
windowFirstStartStates[value[1]] := 0
isWaited := 0
if(value[11])
{
if(value[13]){
Break
}
WinGetActiveTitle, PreviouslyActiveWindowTitle
WinActivate, Glyph
AwaitActiveWindow("Glyph")
WinGetPos, Xpos, Ypos,Wpos,Hpos, Glyph
LoginButtonX    :=  0
LoginButtonY    :=  0
DiffAccButtonX  :=  0
DiffAccButtonY  :=  0
LoginAccButtonX :=  0
LoginAccButtonY :=  0
PlayButtonX     :=  0
PlayButtonY     :=  0
defaultLoginButtonX    :=  (Wpos * (84/100)  )
defaultLoginButtonY    :=  (Hpos * (4/100)   )
defaultDiffAccButtonX  :=  (Wpos * (83/100)  )
defaultDiffAccButtonY  :=  (Hpos * (21/100)  )
defaultLoginAccButtonX :=  (Wpos * (28.6/100))
defaultLoginAccButtonY :=  (Hpos * (58/100)  )
defaultPlayButtonX     :=  (Wpos * (80/100)  )
defaultPlayButtonY     :=  (Hpos * (14/100)  )
IniRead, LoginButtonX, Settings.ini, GlyphSettings, LoginButtonX
IniRead, LoginButtonY, Settings.ini, GlyphSettings, LoginButtonY
IniRead, DiffAccButtonX, Settings.ini, GlyphSettings, DiffAccButtonX
IniRead, DiffAccButtonY, Settings.ini, GlyphSettings, DiffAccButtonY
IniRead, LoginAccButtonX, Settings.ini, GlyphSettings, LoginAccButtonX
IniRead, LoginAccButtonY, Settings.ini, GlyphSettings, LoginAccButtonY
IniRead, PlayButtonX, Settings.ini, GlyphSettings, PlayButtonX
IniRead, PlayButtonY, Settings.ini, GlyphSettings, PlayButtonY
if(LoginButtonX == "ERROR" || LoginButtonY == "ERROR" || DiffAccButtonX == "ERROR" || DiffAccButtonY == "ERROR" || LoginAccButtonX == "ERROR" || LoginAccButtonY == "ERROR" || PlayButtonX == "ERROR" || PlayButtonY == "ERROR"){
IniWrite, %defaultLoginButtonX%, Settings.ini, GlyphSettings, LoginButtonX
IniWrite, %defaultLoginButtonY%, Settings.ini, GlyphSettings, LoginButtonY
IniWrite, %defaultDiffAccButtonX%, Settings.ini, GlyphSettings, DiffAccButtonX
IniWrite, %defaultDiffAccButtonY%, Settings.ini, GlyphSettings, DiffAccButtonY
IniWrite, %defaultLoginAccButtonX%, Settings.ini, GlyphSettings, LoginAccButtonX
IniWrite, %defaultLoginAccButtonY%, Settings.ini, GlyphSettings, LoginAccButtonY
IniWrite, %defaultPlayButtonX%, Settings.ini, GlyphSettings, PlayButtonX
IniWrite, %defaultPlayButtonY%, Settings.ini, GlyphSettings, PlayButtonY
}
Click, %LoginButtonX%,%LoginButtonY%
Sleep, 200
Click, %DiffAccButtonX%,%DiffAccButtonY%
AwaitActiveWindow("Glyph Login")
SendRaw, % value[2]
Sleep, 600
ControlSend,,{tab},Glyph
Sleep, 600
SendRaw, % value[3]
Sleep, 600
Click, %LoginAccButtonX%,%LoginAccButtonY%
AwaitActiveWindow("Glyph")
Click, %PlayButtonX%, %PlayButtonY%
AwaitActiveWindow("Trove")
WinGetActiveTitle, Title
WinSetTitle, %Title%,, % value[1]
if(value[16] != 0)
{
WinMove, % value[1] ,, % value[14], % value[15], % value[16], % value[17]
}
else
{
WinMove, % value[1] ,, 0, 0, 800, 600
}
WinActivate, %PreviouslyActiveWindowTitle%
}
}
if()
Sleep, (((value[4] * 100) + (value[5] * 100) + (value[6] * 100) + (value[7] * 300) + (value[8] * 300) + (value[9] * 300) + (value[10] * 300)) / settings.Length())
}
}
}
LoadGlyphSettings:
LoginButtonX    :=  0
LoginButtonY    :=  0
DiffAccButtonX  :=  0
DiffAccButtonY  :=  0
LoginAccButtonX :=  0
LoginAccButtonY :=  0
PlayButtonX     :=  0
PlayButtonY     :=  0
IniRead, LoginButtonX, Settings.ini, GlyphSettings, LoginButtonX
IniRead, LoginButtonY, Settings.ini, GlyphSettings, LoginButtonY
IniRead, DiffAccButtonX, Settings.ini, GlyphSettings, DiffAccButtonX
IniRead, DiffAccButtonY, Settings.ini, GlyphSettings, DiffAccButtonY
IniRead, LoginAccButtonX, Settings.ini, GlyphSettings, LoginAccButtonX
IniRead, LoginAccButtonY, Settings.ini, GlyphSettings, LoginAccButtonY
IniRead, PlayButtonX, Settings.ini, GlyphSettings, PlayButtonX
IniRead, PlayButtonY, Settings.ini, GlyphSettings, PlayButtonY
if(LoginButtonX == "ERROR" || LoginButtonY == "ERROR" || DiffAccButtonX == "ERROR" || DiffAccButtonY == "ERROR" || LoginAccButtonX == "ERROR" || LoginAccButtonY == "ERROR" || PlayButtonX == "ERROR" || PlayButtonY == "ERROR"){
IniWrite, 974.4, Settings.ini, GlyphSettings, LoginButtonX
IniWrite, 29.4, Settings.ini, GlyphSettings, LoginButtonY
IniWrite, 962.8, Settings.ini, GlyphSettings, DiffAccButtonX
IniWrite, 153.3, Settings.ini, GlyphSettings, DiffAccButtonY
IniWrite, 331.76, Settings.ini, GlyphSettings, LoginAccButtonX
IniWrite, 423.4, Settings.ini, GlyphSettings, LoginAccButtonY
IniWrite, 928.0, Settings.ini, GlyphSettings, PlayButtonX
IniWrite, 102.2, Settings.ini, GlyphSettings, PlayButtonY
}
Return
OpenUI:
Privacy := LoadUiSetting("Privacy","Privacy")
uiHotkey := LoadUiSetting("UiHotkey","UiHotkey")
UrlDownloadToFile, https://i.ibb.co/XzwS2ph/Screenshot-2024-05-29-232444.png, hotkey.png
Gui Tab, 1
Gui, Main:New, , %titleScript%
Gui Add, Tab3, x0 y0 +BackgroundTrans, Main|Info|Hotkeys
Gui, Main:Add, Button, x10 y30 w100 h30 gAddToAccountList, Add account
if(FailSafe){
Gui, Main:Add, Button, x120 y30 w100 h30 gStopTask, Start
}
else{
Gui, Main:Add, Button, x120 y30 w100 h30 gStopTask, Stop
}
Gui, Main:Add, Button, x230 y30 w100 h30 gKillAllEnabledTrove, Kill All Enabled
Gui, Main:Add, Button, x340 y30 w100 h30 gReloadScript, Reload Script
Gui, Main:Add, Button, x450 y30 w100 h30 gSendTextToAllEnabledTrove, Send Text to All Enabled Trove
Gui, Main:Add, Button, x560 y30 w100 h30 gSendActionToAllEnabledTrove, Send Action to All Enabled Trove
Gui, Main:Add, Checkbox, x780 y40 checked%Privacy% gPrivacyCheck vPrivacy, Privacy Mode?
Gui, Main:Add, Button, x1090 y30 w100 h30 gKillScript, Kill Script
Gui, Main:Add, Button, x670 y30 w100 h30 gRenamedAlreadyOpenedTrove, Rename Already Opened Trove
Gui, Main:Add, ListView, x10 y100 w1200 h300 gListViewInteract NoSort R8 hwndhlv, Name|Email|Password|AutoM1|AutoM2|AutoSpecial1|AutoSpecial2|UsesFlaskR|UsesFlaskT|AutoLoot|AutoLogin|FXDisable|Disabled|winX|winY|winW|winH|AutoPvP|OneTimeActDelayed|badGraphic
for index, value in Settings
{
LV_Add("", value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11], value[12], value[13], value[14], value[15], value[16], value[17], value[18], value[19], value[20], value[21])
}
Loop, % LV_GetCount("Column"){
LV_ModifyCol(A_Index, "AutoHdr")
}
Gosub, Build2Tab
Gosub, Build3Tab
Gosub, Build4Tab
Gui, Main:Show,
Gosub, PrivacyCheck
Return
SendActionToAllEnabledTrove:
InputBox, UserInput, Action (One Time KeyEvent), Please enter an Action:, , 300, 100
for index, value in Settings {
if(!value[13]){
if(UserInput != ""){
ControlSend, , %UserInput%, % value[1]
sleep, 100
}
}
}
RenamedAlreadyOpenedTrove:
cm := new _ClassMemory("ahk_exe Trove.exe", "", hProcessCopy)
WinGet, winList, List, ahk_exe Trove.exe
Loop % winList {
WinGet, pidstart, PID, % "ahk_id " winList%a_index%
WinGet, hwndstart, ID, ahk_pid %pidstart%
WinGet, PN, ProcessName, % "ahk_id " hwndstart
Base := getProcessBaseAddress(hwndstart)
userpointer := IntToHex(ReadMemory(cm.processPatternScan(,, cm.hexStringToPattern(ptrScan)*)+1, pidstart) - Base)
usernameAdress := GetAddress(pidstart, Base, userpointer, usernameOffsetString)
username :=  ReadMemory_Str(usernameAdress, ,pidstart)
WinSetTitle, ahk_pid %pidstart%,, % username
}
Return
Return
SendTextToAllEnabledTrove:
InputBox, UserInput, Command or Text (Cases do not work), Please enter a Text:, , 300, 100
sleep, 200
for index, value in Settings {
if(!value[13]){
if(UserInput != ""){
ControlSend, , {Enter}, % value[1]
ControlSendRaw, , %UserInput%, % value[1]
sleep, 100
ControlSend, , {Enter}, % value[1]
}
}
}
Return
Build3Tab:
#NoEnv
SetWorkingDir %A_ScriptDir%
SendMode Input
#SingleInstance force
#WinActivateForce
SetBatchLines -1
OnExit("ExitFunktion")
global ScriptName := "BlackMagic"
global ScriptVersion := "1.6.3"
TempPointerFile = %A_Temp%\Trove_Pointer.ini
TempVersionsFile = %A_Temp%\Versions.ini
PointerHostFile := "https://webtrash.lima-city.de/Trove_Pointer_Host.ini"
VersionsFile := "https://webtrash.lima-city.de/Versions.ini"
PointerFile := "pointer.ini"
iniFile := "blackconfig.ini"
global LastUpdateSupport := "01.01.2000"
global SkipSize := 0
global SkipBase := "0x00000000"
global xSkipOffsetString := "0x0+0x0+0x0+0x0+0x0"
global ySkipOffsetString := "0x0+0x0+0x0+0x0+0x0"
global zSkipOffsetString := "0x0+0x0+0x0+0x0+0x0"
global AccelerationSize := 0
global AccelerationBase := "0x00000000"
global xAccelerationOffsetString := "0x0+0x0+0x0+0x0+0x0"
global yAccelerationOffsetString := "0x0+0x0+0x0+0x0+0x0"
global zAccelerationOffsetString := "0x0+0x0+0x0+0x0+0x0"
global ViewSize := 0
global ViewBase := "0x00000000"
global xViewOffsetString := "0x0+0x0+0x0+0x0+0x0"
global yViewOffsetString := "0x0+0x0+0x0+0x0+0x0"
global zViewOffsetString := "0x0+0x0+0x0+0x0+0x0"
global SpeedSize := 0
global SpeedBase := "0x00000000"
global SpeedOffsetString := "0x0+0x0+0x0+0x0+0x0"
global CDSize := 0
global CDBase := "0x00000000"
global minCDOffsetString := "0x0+0x0"
global maxCDOffsetString := "0x0+0x0"
global cViewSize := 0
global cViewBase := "0x00000000"
global cViewHightSOffsetString := "0x0+0x0"
global cViewWidthOffsetString := "0x0+0x0"
global EncKeySize := 0
global EncKeyBase := "0x00000000"
global EncKeyOffsetString := "0x0+0x0+0x0+0x0+0x0"
global InputBoxSize := 0
global InputBoxBase := "0x00000000"
PointerAutoUpdate := false
EnableUpdateCheck := false
ShowTooltip := false
FlyAccel := 20
SkipDistance := 3.5
SuperJumpAccel := 20
FallManipulationAccel := -3
minCamDistance := 1.5
maxCamDistance := 4.2
FloatAccel := 0.4
DecSpeedValue := 260
EnableForceAccel := true
EnableStopIfDontMove := false
SpeedKey = ^k
FreezeKey = ^p
yFreezeKey = ^l
FlyKey = ^w
SkipKey = MButton
FloatKey = ^f
SuperJumpKey = ^m
FallManipulationKey = ^g
AntiAFKKey = ^h
TroveJumpKey = space
TroveAntiAFKKey = m
TroveMoveForwardKey = w
TroveMoveLeftKey = a
TroveMoveBackwardKey = s
TroveMoveRightKey = d
defaultSpeedKey := SpeedKey
defaultFreezeKey := FreezeKey
defaultyFreezeKey := yFreezeKey
defaultFlyKey := FlyKey
defaultSkipKey := SkipKey
defaultFloatKey := FloatKey
defaultSuperJumpKey := SuperJumpKey
defaultFallManipulationKey := FallManipulationKey
defaultAntiAFKKey := AntiAFKKey
defaultTroveJumpKey := TroveJumpKey
defaultTroveAntiAFKKey := TroveAntiAFKKey
defaultTroveMoveForwardKey := TroveMoveForwardKey
defaultTroveMoveLeftKey := TroveMoveLeftKey
defaultTroveMoveBackwardKey := TroveMoveBackwardKey
defaultTroveMoveRightKey := TroveMoveRightKey
AntiAFKDelay := 2500
PI := 3.1414
SplashTextOn,130,25,% ScriptName " v" ScriptVersion,% "Starting..."
Gosub, loadINI
if (PointerAutoUpdate == TRUE)
{
try
{
UrlDownloadToFile, %PointerHostFile% , %TempPointerFile%
}
if FileExist(TempPointerFile)
{
ReadPointerfromini(TempPointerFile)
if (WritePointertoini(PointerFile) != TRUE)
{
ReadPointerfromini(PointerFile)
}
FileDelete,%TempPointerFile%
}
}
if (EnableUpdateCheck == TRUE)
{
SplashTextOn,200,25,% ScriptName " v" ScriptVersion,% "Check for Update..."
try
{
UrlDownloadToFile, %VersionsFile%, %TempVersionsFile%
}
if FileExist(TempVersionsFile)
{
IniRead,NewScriptVersion,%TempVersionsFile%,Version,BM
if (NewScriptVersion != "ERROR" && NewScriptVersion != ScriptVersion)
{
SplashTextOff
MsgBox, 4, %ScriptName%,% "An Update is available! " ScriptVersion " -> " NewScriptVersion "`nDownload now?"
IfMsgBox, Yes
{
IniRead,NewScriptVersionURL,%TempVersionsFile%,URL,BM
run, %NewScriptVersionURL%
}
}
}
FileDelete,%TempVersionsFile%
}
SplashTextOn,200,25,% ScriptName " v" ScriptVersion,% "Building GUI..."
Gosub, GUI
Gosub, refreshInputBox
Gosub, ToolTip
Gosub, InitHotkeys
Gosub, refreshAddress
SplashTextOff
return
loadINI:
if !FileExist(PointerFile)
{
WritePointertoini(PointerFile)
}
if FileExist(PointerFile)
{
ReadPointerfromini(PointerFile)
}
Return
WritePointertoini(ini)
{
if (LastUpdateSupport != "ERROR")
{
IniWrite,%LastUpdateSupport%,%ini%,date,LastUpdateSupport
IniWrite,%SkipSize%,%ini%,skip,Size
IniWrite,%SkipBase%,%ini%,skip,Base
IniWrite,%xSkipOffsetString%,%ini%,skip,xOffsets
IniWrite,%ySkipOffsetString%,%ini%,skip,yOffsets
IniWrite,%zSkipOffsetString%,%ini%,skip,zOffsets
IniWrite,%AccelerationSize%,%ini%,acceleration,Size
IniWrite,%AccelerationBase%,%ini%,acceleration,Base
IniWrite,%xAccelerationOffsetString%,%ini%,acceleration,xOffsets
IniWrite,%yAccelerationOffsetString%,%ini%,acceleration,yOffsets
IniWrite,%zAccelerationOffsetString%,%ini%,acceleration,zOffsets
IniWrite,%ViewSize%,%ini%,view,Size
IniWrite,%ViewBase%,%ini%,view,Base
IniWrite,%xViewOffsetString%,%ini%,view,xOffsets
IniWrite,%yViewOffsetString%,%ini%,view,yOffsets
IniWrite,%zViewOffsetString%,%ini%,view,zOffsets
IniWrite,%SpeedSize%,%ini%,speed,Size
IniWrite,%SpeedBase%,%ini%,speed,Base
IniWrite,%SpeedOffsetString%,%ini%,speed,Offsets
IniWrite,%CDBase%,%ini%,camera_Distance,Size
IniWrite,%CDBase%,%ini%,camera_Distance,Base
IniWrite,%minCDOffsetString%,%ini%,camera_Distance,minOffset
IniWrite,%maxCDOffsetString%,%ini%,camera_Distance,maxOffset
IniWrite,%cViewSize%,%ini%,cView,Size
IniWrite,%cViewBase%,%ini%,cView,Base
IniWrite,%cViewHightSOffsetString%,%ini%,cView,Hight
IniWrite,%cViewWidthOffsetString%,%ini%,cView,Width
IniWrite,%EncKeySize%,%ini%,StatEncKey,Size
IniWrite,%EncKeyBase%,%ini%,StatEncKey,Base
IniWrite,%EncKeyOffsetString%,%ini%,StatEncKey,Offsets
IniWrite,%InputBoxSize%,%ini%,InputBox,Size
IniWrite,%InputBoxBase%,%ini%,InputBox,Base
state := TRUE
}
else
{
state := FALSE
}
return state
}
ReadPointerfromini(ini)
{
IniRead,LastUpdateSupport,%ini%,date,LastUpdateSupport
IniRead,SkipSize,%ini%,skip,Size
IniRead,SkipBase,%ini%,skip,Base
IniRead,xSkipOffsetString,%ini%,skip,xOffsets
IniRead,ySkipOffsetString,%ini%,skip,yOffsets
IniRead,zSkipOffsetString,%ini%,skip,zOffsets
IniRead,AccelerationSize,%ini%,acceleration,Size
IniRead,AccelerationBase,%ini%,acceleration,Base
IniRead,xAccelerationOffsetString,%ini%,acceleration,xOffsets
IniRead,yAccelerationOffsetString,%ini%,acceleration,yOffsets
IniRead,zAccelerationOffsetString,%ini%,acceleration,zOffsets
IniRead,ViewSize,%ini%,view,Size
IniRead,ViewBase,%ini%,view,Base
IniRead,xViewOffsetString,%ini%,view,xOffsets
IniRead,yViewOffsetString,%ini%,view,yOffsets
IniRead,zViewOffsetString,%ini%,view,zOffsets
IniRead,SpeedSize,%ini%,speed,Size
IniRead,SpeedBase,%ini%,speed,Base
IniRead,SpeedOffsetString,%ini%,speed,Offsets
IniRead,CDBase,%ini%,camera_Distance,Size
IniRead,CDBase,%ini%,camera_Distance,Base
IniRead,minCDOffsetString,%ini%,camera_Distance,minOffset
IniRead,maxCDOffsetString,%ini%,camera_Distance,maxOffset
IniRead,cViewSize,%ini%,cView,Size
IniRead,cViewBase,%ini%,cView,Base
IniRead,cViewHightSOffsetString,%ini%,cView,Hight
IniRead,cViewWidthOffsetString,%ini%,cView,Width
IniRead,EncKeySize,%ini%,StatEncKey,Size
IniRead,EncKeyBase,%ini%,StatEncKey,Base
IniRead,EncKeyOffsetString,%ini%,StatEncKey,Offsets
IniRead,InputBoxSize,%ini%,InputBox,Size
IniRead,InputBoxBase,%ini%,InputBox,Base
}
Updateini:
if (ConfigVersion < 2 || ConfigVersion == "" || ConfigVersion == "ERROR")
{
ConfigVersion := 2
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%EnableUpdateCheck%,%iniFile%,General,EnableUpdateCheck
IniWrite,%FloatKey%,%iniFile%,Hotkeys,FloatKey
}
if (ConfigVersion < 3)
{
ConfigVersion := 3
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%SuperJumpKey%,%iniFile%,Hotkeys,SuperJumpKey
IniWrite,%SuperJumpAccel%,%iniFile%,Values,SuperJumpAccel
}
if (ConfigVersion < 4)
{
ConfigVersion := 4
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%TroveJumpKey%,%iniFile%,TroveHotkeys,TroveJumpKey
IniWrite,%TroveAntiAFKKey%,%iniFile%,TroveHotkeys,TroveAntiAFKKey
IniWrite,%FallManipulationKey%,%iniFile%,Hotkeys,FallManipulationKey
IniWrite,%AntiAFKKey%,%iniFile%,Hotkeys,AntiAFKKey
IniWrite,%FallManipulationAccel%,%iniFile%,Values,FallManipulationAccel
}
if (ConfigVersion < 5)
{
ConfigVersion := 5
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%minCamDistance%,%iniFile%,Values,minCamDistance
IniWrite,%maxCamDistance%,%iniFile%,Values,maxCamDistance
}
if (ConfigVersion < 6)
{
ConfigVersion := 6
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%FloatAccel%,%iniFile%,Values,FloatAccel
}
if (ConfigVersion < 7)
{
ConfigVersion := 7
IniWrite,%ConfigVersion%,%iniFile%,Version,ConfigVersion
IniWrite,%TroveMoveForwardKey%,%iniFile%,TroveHotkeys,TroveMoveForwardKey
IniWrite,%TroveMoveLeftKey%,%iniFile%,TroveHotkeys,TroveMoveLeftKey
IniWrite,%TroveMoveBackwardKey%,%iniFile%,TroveHotkeys,TroveMoveBackwardKey
IniWrite,%TroveMoveRightKey%,%iniFile%,TroveHotkeys,TroveMoveRightKey
IniWrite,%EnableForceAccel%,%iniFile%,Modifier,EnableForceAccel
IniWrite,%EnableStopIfDontMove%,%iniFile%,Modifier,EnableStopIfDontMove
IniWrite,%DecSpeedValue%,%iniFile%,Values,Speed
}
return
GUI:
return
refreshInputBox:
GuiControl, move, FlyAccel, w30
GuiControl, move, SkipDistance, w30
GuiControl, move, SuperJumpAccel, w30
GuiControl, move, FallManipulationAccel, w30
GuiControl, move, minCamDistance, w30
GuiControl, move, maxCamDistance, w30
GuiControl, move, DecSpeedValue, w30
return
PressedSpeedKey:
if (EnableSpeed != 1)
{
gosub, StartSpeed
}
Else
{
gosub, StopSpeed
}
return
PressedFlyKey:
gosub, AccelerationFly
return
PressedSkipKey:
gosub, ViewSkip
return
PressedFreezeKey:
if (EnableFreeze != 1)
{
gosub, StartFreeze
}
Else
{
gosub, StopFreeze
}
return
PressedyFreezeKey:
if (EnableyFreeze != 1)
{
gosub, StartyFreeze
}
Else
{
gosub, StopyFreeze
}
return
PressedFloatKey:
if (EnableFloat != 1)
{
Gosub, StartFloat
}
Else
{
Gosub, StopFloat
}
return
PressedSuperJumpKey:
if (EnableSuperJump != 1)
{
Gosub, StartSuperJump
}
Else
{
Gosub, StopSuperJump
}
return
PressedFallManipulationKey:
if (EnableFallManipulation != 1)
{
Gosub, StartFallManipulation
}
Else
{
Gosub, StopFallManipulation
}
return
PressedAntiAFKKey:
if (EnableAntiAFK != 1)
{
Gosub, StartAntiAFK
}
Else
{
Gosub, StopAntiAFK
}
return
SaveHotkeys:
Gosub, DisableHotkeys
GuiControlGet,SkipKey,,SkipKey
GuiControlGet,SpeedKey,,SpeedKey
GuiControlGet,FreezeKey,,FreezeKey
GuiControlGet,yFreezeKey,,yFreezeKey
GuiControlGet,FlyKey,,FlyKey
GuiControlGet,FloatKey,,FloatKey
GuiControlGet,SuperJumpKey,,SuperJumpKey
GuiControlGet,FallManipulationKey,,FallManipulationKey
GuiControlGet,AntiAFKKey,,AntiAFKKey
Gosub, SaveHotkeysToINI
Gosub, LoadHotkeysFromINI
Gosub, InitHotkeys
return
ResetHotkeys:
MsgBox, 4, %ScriptName%,% "Reset BlackMagic Hotkeys?"
IfMsgBox, Yes
{
SpeedKey := defaultSpeedKey
FreezeKey := defaultFreezeKey
yFreezeKey := defaultyFreezeKey
FlyKey := defaultFlyKey
SkipKey := defaultSkipKey
FloatKey := defaultFloatKey
SuperJumpKey := defaultSuperJumpKey
FallManipulationKey := defaultFallManipulationKey
AntiAFKKey := defaultAntiAFKKey
Gosub, SaveHotkeysToINI
Gosub, Restart
}
return
SaveTroveHotkeys:
GuiControlGet,TroveJumpKey,,TroveJumpKey
GuiControlGet,TroveAntiAFKKey,,TroveAntiAFKKey
GuiControlGet,TroveMoveForwardKey,,TroveMoveForwardKey
GuiControlGet,TroveMoveLeftKey,,TroveMoveLeftKey
GuiControlGet,TroveMoveBackwardKey,,TroveMoveBackwardKey
GuiControlGet,TroveMoveRightKey,,TroveMoveRightKey
Gosub, SaveTroveHotkeysToINI
Gosub, LoadTroveHotkeysFromINI
return
ResetTroveHotkeys:
MsgBox, 4, %ScriptName%,% "Reset Trove Hotkeys?"
IfMsgBox, Yes
{
TroveJumpKey := defaultTroveJumpKey
TroveAntiAFKKey := defaultTroveAntiAFKKey
TroveMoveForwardKey := defaultTroveMoveForwardKey
TroveMoveLeftKey := defaultTroveMoveLeftKey
TroveMoveBackwardKey := defaultTroveMoveBackwardKey
TroveMoveRightKey := defaultTroveMoveRightKey
Gosub, SaveTroveHotkeysToINI
Gosub, Restart
}
return
SaveTroveHotkeysToINI:
IniWrite,%TroveJumpKey%,%iniFile%,TroveHotkeys,TroveJumpKey
IniWrite,%TroveAntiAFKKey%,%iniFile%,TroveHotkeys,TroveAntiAFKKey
IniWrite,%TroveMoveForwardKey%,%iniFile%,TroveHotkeys,TroveMoveForwardKey
IniWrite,%TroveMoveLeftKey%,%iniFile%,TroveHotkeys,TroveMoveLeftKey
IniWrite,%TroveMoveBackwardKey%,%iniFile%,TroveHotkeys,TroveMoveBackwardKey
IniWrite,%TroveMoveRightKey%,%iniFile%,TroveHotkeys,TroveMoveRightKey
return
LoadTroveHotkeysFromINI:
IniRead,TroveJumpKey,%iniFile%,TroveHotkeys,TroveJumpKey
IniRead,TroveAntiAFKKey,%iniFile%,TroveHotkeys,TroveAntiAFKKey
IniRead,TroveMoveForwardKey,%iniFile%,TroveHotkeys,TroveMoveForwardKey
IniRead,TroveMoveLeftKey,%iniFile%,TroveHotkeys,TroveMoveLeftKey
IniRead,TroveMoveBackwardKey,%iniFile%,TroveHotkeys,TroveMoveBackwardKey
IniRead,TroveMoveRightKey,%iniFile%,TroveHotkeys,TroveMoveRightKey
return
SaveHotkeysToINI:
IniWrite,%SkipKey%,%iniFile%,Hotkeys,SkipKey
IniWrite,%SpeedKey%,%iniFile%,Hotkeys,SpeedKey
IniWrite,%FreezeKey%,%iniFile%,Hotkeys,FreezeKey
IniWrite,%yFreezeKey%,%iniFile%,Hotkeys,yFreezeKey
IniWrite,%FlyKey%,%iniFile%,Hotkeys,FlyKey
IniWrite,%FloatKey%,%iniFile%,Hotkeys,FloatKey
IniWrite,%SuperJumpKey%,%iniFile%,Hotkeys,SuperJumpKey
IniWrite,%FallManipulationKey%,%iniFile%,Hotkeys,FallManipulationKey
IniWrite,%AntiAFKKey%,%iniFile%,Hotkeys,AntiAFKKey
return
LoadHotkeysFromINI:
IniRead,SkipKey,%iniFile%,Hotkeys,SkipKey
IniRead,SpeedKey,%iniFile%,Hotkeys,SpeedKey
IniRead,FreezeKey,%iniFile%,Hotkeys,FreezeKey
IniRead,yFreezeKey,%iniFile%,Hotkeys,yFreezeKey
IniRead,FlyKey,%iniFile%,Hotkeys,FlyKey
IniRead,FloatKey,%iniFile%,Hotkeys,FloatKey
IniRead,SuperJumpKey,%iniFile%,Hotkeys,SuperJumpKey
IniRead,FallManipulationKey,%iniFile%,Hotkeys,FallManipulationKey
IniRead,AntiAFKKey,%iniFile%,Hotkeys,AntiAFKKey
return
InitHotkeys:
If !A_IsCompiled
{
Hotkey, ^R, Restart
Hotkey, ^T, ExitScript
}
gosub, CheckTroveWindow
return
DisableHotkeys:
return
CheckTroveWindow:
WinGet, PID, PID, ahk_exe Trove.exe
WinGet, hwnd, ID, ahk_pid %PID%
Base := getProcessBaseAddresss(hwnd)
Gosub, GetAddresss
oldySkipAddress := ySkipAddress
return
GetAddresss:
xSkipAddress := GetAddresss(PID, Base, SkipBase, xSkipOffsetString)
ySkipAddress := GetAddresss(PID, Base, SkipBase, ySkipOffsetString)
zSkipAddress := GetAddresss(PID, Base, SkipBase, zSkipOffsetString)
xAccelerationAddress := GetAddresss(PID, Base, AccelerationBase, xAccelerationOffsetString)
yAccelerationAddress := GetAddresss(PID, Base, AccelerationBase, yAccelerationOffsetString)
zAccelerationAddress := GetAddresss(PID, Base, AccelerationBase, zAccelerationOffsetString)
xViewAddress := GetAddresss(PID, Base, ViewBase, xViewOffsetString)
yViewAddress := GetAddresss(PID, Base, ViewBase, yViewOffsetString)
zViewAddress := GetAddresss(PID, Base, ViewBase, zViewOffsetString)
SpeedAddress := GetAddresss(PID, Base, SpeedBase, SpeedOffsetString)
currentCDAddress := GetAddresss(PID, Base, CDBase, currentCDOffsetString)
minCDAddress := GetAddresss(PID, Base, CDBase, minCDOffsetString)
maxCDAddress := GetAddresss(PID, Base, CDBase, maxCDOffsetString)
cViewHightAddress := GetAddresss(PID, Base, cViewBase, cViewHightSOffsetString)
cViewWidthAddress := GetAddresss(PID, Base, cViewBase, cViewWidthOffsetString)
EncKeyAddress := GetAddresss(PID, Base, EncKeyBase, EncKeyOffsetString)
InputBoxAddress := GetAddresss(PID, Base, InputBoxBase)
return
Save:
GuiControlGet,PointerAutoUpdate,,PointerAutoUpdate
GuiControlGet,EnableUpdateCheck,,EnableUpdateCheck
GuiControlGet,ShowTooltip,,ShowTooltip
GuiControlGet,DecSpeedValue,,DecSpeedValue
GuiControlGet,FlyAccel,,FlyAccel
GuiControlGet,SkipDistance,,SkipDistance
GuiControlGet,SuperJumpAccel,,SuperJumpAccel
GuiControlGet,FallManipulationAccel,,FallManipulationAccel
GuiControlGet,minCamDistance,,minCamDistance
GuiControlGet,maxCamDistance,,maxCamDistance
GuiControlGet,EnableForceAccel,,EnableForceAccel
GuiControlGet,EnableStopIfDontMove,,EnableStopIfDontMove
IniWrite,%PointerAutoUpdate%,%iniFile%,General,PointerAutoUpdate
IniWrite,%EnableUpdateCheck%,%iniFile%,General,EnableUpdateCheck
IniWrite,%ShowTooltip%,%iniFile%,General,ShowTooltip
IniWrite,%DecSpeedValue%,%iniFile%,Values,Speed
IniWrite,%FlyAccel%,%iniFile%,Values,FlyAccel
IniWrite,%SkipDistance%,%iniFile%,Values,SkipDistance
IniWrite,%SuperJumpAccel%,%iniFile%,Values,SuperJumpAccel
IniWrite,%FallManipulationAccel%,%iniFile%,Values,FallManipulationAccel
IniWrite,%minCamDistance%,%iniFile%,Values,minCamDistance
IniWrite,%maxCamDistance%,%iniFile%,Values,maxCamDistance
IniWrite,%EnableForceAccel%,%iniFile%,Modifier,EnableForceAccel
IniWrite,%EnableStopIfDontMove%,%iniFile%,Modifier,EnableStopIfDontMove
Gosub, CustomCamDistanceLimit
Gosub, CalcEncSpeedValue
return
getBitWiseWASD:
wasd := 0x0
if (GetKeyState(TroveMoveForwardKey, P))
{
wasd ^= 0x8
}
if (GetKeyState(TroveMoveLeftKey, P))
{
wasd ^= 0x4
}
if (GetKeyState(TroveMoveBackwardKey, P))
{
wasd ^= 0x2
}
if (GetKeyState(TroveMoveRightKey, P))
{
wasd ^= 0x1
}
return
Restart:
Run %A_ScriptFullPath%
ExitApp
ExitScript:
ExitApp
ToolTip:
return
refreshAddress:
Gosub, GetAddresss
if (oldySkipAddress != ySkipAddress || oldPID != PID)
{
Gosub, runAtAddressChange
}
oldPID := PID
oldySkipAddress := ySkipAddress
SetTimer, refreshAddress, -1000
return
ViewSkip:
Gosub, CheckTroveWindow
xSkipCurrentPos := HexToFloat(ReadMemoryy(xSkipAddress, PID, SkipSize))
ySkipCurrentPos := HexToFloat(ReadMemoryy(ySkipAddress, PID, SkipSize))
zSkipCurrentPos := HexToFloat(ReadMemoryy(zSkipAddress, PID, SkipSize))
xSkipCurrentView := HexToFloat(ReadMemoryy(xViewAddress, PID, ViewSize))
ySkipCurrentView := HexToFloat(ReadMemoryy(yViewAddress, PID, ViewSize))
zSkipCurrentView := HexToFloat(ReadMemoryy(zViewAddress, PID, ViewSize))
xSkipNewPos := xSkipCurrentPos + (xSkipCurrentView * SkipDistance)
ySkipNewPos := ySkipCurrentPos + (ySkipCurrentView * SkipDistance)
zSkipNewPos := zSkipCurrentPos + (zSkipCurrentView * SkipDistance)
WriteProcessMemoryy(pid, xSkipAddress, FloatToHexx(xSkipNewPos), SkipSize)
WriteProcessMemoryy(pid, ySkipAddress, FloatToHexx(ySkipNewPos), SkipSize)
WriteProcessMemoryy(pid, zSkipAddress, FloatToHexx(zSkipNewPos), SkipSize)
sleep, 100
return
AccelerationFly:
Gosub, CheckTroveWindow
xFlyCurrentView := HexToFloat(ReadMemoryy(xViewAddress, PID, ViewSize))
yFlyCurrentView := HexToFloat(ReadMemoryy(yViewAddress, PID, ViewSize))
zFlyCurrentView := HexToFloat(ReadMemoryy(zViewAddress, PID, ViewSize))
xFlyNewAccel := xFlyCurrentView * FlyAccel
yFlyNewAccel := yFlyCurrentView * FlyAccel
zFlyNewAccel := zFlyCurrentView * FlyAccel
WriteProcessMemoryy(pid, xAccelerationAddress, FloatToHexx(xFlyNewAccel), AccelerationSize)
WriteProcessMemoryy(pid, yAccelerationAddress, FloatToHexx(yFlyNewAccel), AccelerationSize)
WriteProcessMemoryy(pid, zAccelerationAddress, FloatToHexx(zFlyNewAccel), AccelerationSize)
sleep, 20
return
StartFreeze:
Gosub, CheckTroveWindow
xFreezePos := HexToFloat(ReadMemoryy(xSkipAddress, PID, SkipSize))
zFreezePos := HexToFloat(ReadMemoryy(zSkipAddress, PID, SkipSize))
EnableFreeze := 1
Gosub, Freeze
return
StopFreeze:
EnableFreeze := 0
return
Freeze:
if (EnableFreeze == 1)
{
WriteProcessMemoryy(PID, xSkipAddress, FloatToHexx(xFreezePos), SkipSize)
WriteProcessMemoryy(PID, zSkipAddress, FloatToHexx(zFreezePos), SkipSize)
SetTimer, Freeze, -20
}
return
StartyFreeze:
Gosub, CheckTroveWindow
yFreezePos := HexToFloat(ReadMemoryy(ySkipAddress, PID, SkipSize))
EnableyFreeze := 1
Gosub, yFreeze
return
StopyFreeze:
EnableyFreeze := 0
return
yFreeze:
if (EnableyFreeze == 1)
{
WriteProcessMemoryy(PID, ySkipAddress, FloatToHexx(yFreezePos), SkipSize)
SetTimer, yFreeze, -20
}
return
StartSpeed:
Gosub, CheckTroveWindow
Gosub, CalcEncSpeedValue
EnableSpeed := 1
Gosub, Speed
return
StopSpeed:
EnableSpeed := 0
return
Speed:
if (EnableSpeed == 1)
{
if (WinActive("ahk_pid" pid))
{
WriteProcessMemoryy(PID, SpeedAddress, EncSpeedValue, SpeedSize)
if (EnableForceAccel || EnableStopIfDontMove)
{
Gosub, getBitWiseWASD
}
if (wasd != 0x0 && EnableForceAccel && ReadMemoryy(InputBoxAddress, PID,InputBoxSize) == 0)
{
Gosub, CalcNewSpeedAccel
WriteProcessMemoryy(pid, xAccelerationAddress, FloatToHexx(xNewSpeedAccel), AccelerationSize)
WriteProcessMemoryy(pid, zAccelerationAddress, FloatToHexx(zNewSpeedAccel), AccelerationSize)
}
if (wasd == 0x0 && EnableStopIfDontMove)
{
WriteProcessMemoryy(pid, xAccelerationAddress, FloatToHexx(0), AccelerationSize)
WriteProcessMemoryy(pid, zAccelerationAddress, FloatToHexx(0), AccelerationSize)
}
}
SetTimer, Speed, -20
}
return
CalcEncSpeedValue:
Gosub, CheckTroveWindow
EncSpeedValue := FloatToHexx(DecSpeedValue) ^ ReadMemoryy(EncKeyAddress, PID, EncKeySize)
return
CalcNewSpeedAccel:
SpeedBaseAccel := (DecSpeedValue/10)
SpeedCurrentCameraWidth := HexToFloat(ReadMemoryy(cViewWidthAddress, PID, cViewSize))
SpeedCurrentCameraAngle := (360/(2*PI)) * SpeedCurrentCameraWidth
switch wasd
{
case 0x8,0xD,0xF: 	SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle, 360)
case 0xC,0xE:		SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 45, 360)
case 0x4:			SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 90, 360)
case 0x6:			SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 135, 360)
case 0x2,0x7:		SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 180, 360)
case 0x3:			SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 225, 360)
case 0x1:			SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 270, 360)
case 0x9,0xB:		SpeedNewCameraAngle := mod(SpeedCurrentCameraAngle + 315, 360)
}
xNewSpeedAccel := SpeedBaseAccel * sin(SpeedNewCameraAngle * (PI / 180))
zNewSpeedAccel := SpeedBaseAccel * cos(SpeedNewCameraAngle * (PI / 180))
return
StartFloat:
Gosub, CheckTroveWindow
EnableFloat := 1
Gosub, Float
return
StopFloat:
EnableFloat := 0
return
Float:
if (EnableFloat == 1)
{
WriteProcessMemoryy(pid, yAccelerationAddress, FloatToHexx(FloatAccel), AccelerationSize)
SetTimer, Float, -10
}
return
StartSuperJump:
Gosub, CheckTroveWindow
EnableSuperJump := 1
Gosub, SuperJump
return
StopSuperJump:
EnableSuperJump := 0
return
SuperJump:
if (EnableSuperJump == 1)
{
if (GetKeyState(TroveJumpKey, P) && ReadMemoryy(InputBoxAddress, PID,InputBoxSize) == 0 && WinActive("ahk_pid" pid))
{
ySuperJumpCurrentAccel := HexToFloat(ReadMemoryy(yAccelerationAddress, PID, AccelerationSize))
WriteProcessMemoryy(PID, yAccelerationAddress, FloatToHexx(SuperJumpAccel), AccelerationSize)
ySuperJumpCurrentAccel := 0
}
SetTimer, SuperJump, -5
}
return
StartFallManipulation:
Gosub, CheckTroveWindow
EnableFallManipulation := 1
Gosub, FallManipulation
return
StopFallManipulation:
EnableFallManipulation := 0
return
FallManipulation:
if (EnableFallManipulation == 1)
{
if (HexToFloat(ReadMemoryy(yAccelerationAddress, PID, AccelerationSize)) < 0 )
{
WriteProcessMemoryy(PID, yAccelerationAddress, FloatToHexx(FallManipulationAccel), AccelerationSize)
}
SetTimer, FallManipulation, -5
}
return
StartAntiAFK:
Gosub, CheckTroveWindow
EnableAntiAFK := 1
Gosub, AntiAFK
return
StopAntiAFK:
EnableAntiAFK := 0
return
AntiAFK:
if (EnableAntiAFK == 1)
{
ControlSend, ahk_parent, {%TroveAntiAFKKey%}, ahk_pid %PID%
SetTimer, AntiAFK, -%AntiAFKDelay%
}
return
CustomCamDistanceLimit:
WriteProcessMemoryy(PID, minCDAddress, FloatToHexx(minCamDistance), CDSize)
WriteProcessMemoryy(PID, maxCDAddress, FloatToHexx(maxCamDistance), CDSize)
return
runAtAddressChange:
Gosub, StopFloat
Gosub, StopyFreeze
Gosub, StopFreeze
Gosub, StopAntiAFK
Gosub, CustomCamDistanceLimit
return
ExitFunktion()
{
gosub,ExitScript
}
getProcessBaseAddresss(Handle)
{
Return DllCall( A_PtrSize = 4
? "GetWindowLong"
: "GetWindowLongPtr"
, "Ptr", Handle
, "Int", -6
, "Int64")
}
GetAddresss(PID, Base, Address, Offset = "")
{
pointerBase := base + Address
if (Offset == "")
{
return pointerBase
}
y := ReadMemoryy(pointerBase,PID)
OffsetSplit := StrSplit(Offset, "+")
OffsetCount := OffsetSplit.MaxIndex()
Loop, %OffsetCount%
{
if (a_index = OffsetCount)
{
Address := (y + OffsetSplit[a_index])
}
Else if(a_index = 1)
{
y := ReadMemoryy(y + OffsetSplit[a_index],PID)
}
Else
{
y := ReadMemoryy(y + OffsetSplit[a_index],PID)
}
}
Return Address
}
ReadMemoryy(MADDRESS, pid, size = 4)
{
VarSetCapacity(MVALUE,size,0)
ProcessHandle := DllCall("OpenProcess", "Int", 24, "Char", 0, "UInt", pid, "UInt")
DllCall("ReadProcessMemory", "UInt", ProcessHandle, "Ptr", MADDRESS, "Ptr", &MVALUE, "Uint",size)
Loop %size%
result += *(&MVALUE + A_Index-1) << 8*(A_Index-1)
Return, result
}
WriteProcessMemoryy(pid,address,valueToWrite, size = 4)
{
VarSetCapacity(processhandle,32,0)
VarSetCapacity(value, 32, 0)
NumPut(valueToWrite,value,0,Uint)
processhandle:=DllCall("OpenProcess","Uint",0x38,"int",0,"int",pid)
Bvar:=DllCall("WriteProcessMemory","Uint",processhandle,"Uint",address+0,"Uint",&value,"Uint",size,"Uint",0)
}
HexToFloat(d)
{
Return (1-2*(d>>31)) * (2**((d>>23 & 255)-127)) * (1+(d & 8388607)/8388608)
}
FloatToHexx(f)
{
form := A_FormatInteger
SetFormat Integer, HEX
v := DllCall("MulDiv", Float,f, Int,1, Int,1, UInt)
SetFormat Integer, %form%
Return v
}
return
Build4Tab:
Gui Tab, 3
Gosub, LoadGlyphSettings
Gui, Add, GroupBox, x10 y30 w200 h160 , Hotkeys
Gui, Add, Text, x20 y52, Window Hotkey
Gui, Add, Hotkey,x100 y50 w80 h20 vUiHotkey, %uiHotkey%
Gui, Add, Button, x20 y155 gSaveUiHotkeys, Save Hotkeys
Gui, Add, GroupBox, x220 y30 w350 h160 , Glyph Position Settings
Gui, Add, Text, x230 y53, LoginButtonX
Gui, Add, Edit, x310 y50 vLoginButtonX gSave, %LoginButtonX%
Gui, Add, Text, x230 y78, LoginButtonY
Gui, Add, Edit, x310 y75 vLoginButtonY gSave, %LoginButtonY%
Gui, Add, Text, x230 y103, DiffAccButtonX
Gui, Add, Edit, x310 y100 vDiffAccButtonX gSave, %DiffAccButtonX%
Gui, Add, Text, x230 y128, DiffAccButtonY
Gui, Add, Edit, x310 y125 vDiffAccButtonY gSave, %DiffAccButtonY%
Gui, Add, Text, x380 y53, LoginAccButtonX
Gui, Add, Edit, x470 y50 vLoginAccButtonX gSave, %LoginAccButtonX%
Gui, Add, Text, x380 y78, LoginAccButtonY
Gui, Add, Edit, x470 y75 vLoginAccButtonY gSave, %LoginAccButtonY%
Gui, Add, Text, x380 y103, PlayButtonX
Gui, Add, Edit, x470 y100 vPlayButtonX gSave, %PlayButtonX%
Gui, Add, Text, x380 y128, PlayButtonY
Gui, Add, Edit, x470 y125 vPlayButtonY gSave, %PlayButtonY%
Gui, Add, Button, x230 y155 gSaveGlyphHotkeys, Save Glyph Position Settings
return
SaveUiHotkeys:
Gosub, DisableUiHotkeys
GuiControlGet,uiHotkey,,uiHotkey
Gosub, SaveUiHotkeysToINI
Gosub, LoadUiHotkeysFromINI
return
SaveGlyphHotkeys:
GuiControlGet,LoginButtonX,,LoginButtonX
GuiControlGet,LoginButtonY,,LoginButtonY
GuiControlGet,DiffAccButtonX,,DiffAccButtonX
GuiControlGet,DiffAccButtonY,,DiffAccButtonY
GuiControlGet,LoginAccButtonX,,LoginAccButtonX
GuiControlGet,LoginAccButtonY,,LoginAccButtonY
GuiControlGet,PlayButtonX,,PlayButtonX
GuiControlGet,PlayButtonY,,PlayButtonY
Gosub, SaveGlyphSettingsToINI
Gosub, LoadGlyphSettingsFromINI
return
SaveGlyphSettingsToINI:
IniWrite, %LoginButtonX%, Settings.ini, GlyphSettings, LoginButtonX
IniWrite, %LoginButtonY%, Settings.ini, GlyphSettings, LoginButtonY
IniWrite, %DiffAccButtonX%, Settings.ini, GlyphSettings, DiffAccButtonX
IniWrite, %DiffAccButtonY%, Settings.ini, GlyphSettings, DiffAccButtonY
IniWrite, %LoginAccButtonX%, Settings.ini, GlyphSettings, LoginAccButtonX
IniWrite, %LoginAccButtonY%, Settings.ini, GlyphSettings, LoginAccButtonY
IniWrite, %PlayButtonX%, Settings.ini, GlyphSettings, PlayButtonX
IniWrite, %PlayButtonY%, Settings.ini, GlyphSettings, PlayButtonY
return
LoadGlyphSettingsFromINI:
Gosub, LoadGlyphSettings
return
DisableUiHotkeys:
if (uiHotkey != "")
{
Hotkey, %uiHotkey%, OpenUi, off
}
Return
SaveUiHotkeysToINI:
IniWrite,%uiHotkey%,Settings.ini,UiSettings,UiHotkey
IniWrite, %LoginButtonX%, Settings.ini, GlyphSettings, LoginButtonX
IniWrite, %LoginButtonY%, Settings.ini, GlyphSettings, LoginButtonY
IniWrite, %DiffAccButtonX%, Settings.ini, GlyphSettings, DiffAccButtonX
IniWrite, %DiffAccButtonY%, Settings.ini, GlyphSettings, DiffAccButtonY
IniWrite, %LoginAccButtonX%, Settings.ini, GlyphSettings, LoginAccButtonX
IniWrite, %LoginAccButtonY%, Settings.ini, GlyphSettings, LoginAccButtonY
IniWrite, %PlayButtonX%, Settings.ini, GlyphSettings, PlayButtonX
IniWrite, %PlayButtonY%, Settings.ini, GlyphSettings, PlayButtonY
return
LoadUiHotkeysFromINI:
IniRead,uiHotkey,Settings.ini,UiSettings,uiHotkey
if(uiHotkey == "" || uiHotkey == "ERROR"){
IniWrite,f1,Settings.ini,UiSettings,UiHotkey
sleep, 200
IniRead,uiHotkey,Settings.ini,UiSettings,uiHotkey
}
if (uiHotkey != "" && uiHotkey != "ERROR")
{
Hotkey, %uiHotkey%, OpenUi, on
}
return
Build2Tab:
Gui Tab, 2
Gui, Add, GroupBox, x10 y30 w600 h160 , How To Use
Gui Main:Add, Text, x30 y50, % HowToText
Gui Main:Add, Pic, x30 y80 w550 h86, hotkey.png
Gui, Add, GroupBox, x620 y30 w600 h160 , Weird Resolution? Change Glyph Positions
Gui Main:Add, Text, x650 y50, % HowToGlyph
Gui, Add, GroupBox, x10 y190 w600 h140 , Credits
Gui, Main:Add, Text, x30 y215, % Credits
FileDelete, hotkey.png
Return
PrivacyCheck:
GuiControlGet, CheckBoxState,, Privacy
SaveUiSetting(CheckBoxState, "Privacy")
if(CheckBoxState = 1){
LV_ModifyCol(2,"5")
LV_ModifyCol(3,"5")
} else {
LV_ModifyCol(2,"AutoHdr")
LV_ModifyCol(3,"AutoHdr")
}
Return
KillScript:
ExitApp
Return
ReloadScript:
if A_IsCompiled
Run "%A_ScriptFullPath%" /force
else
Run "%A_AhkPath%" /force "%A_ScriptFullPath%"
ExitApp
Return
KillAllEnabledTrove:
Settings := LoadSettings()
Sleep, 300
if(!FailSafe){
Gosub, StopTask
}
for index, value in Settings
{
if(!value[13] && WinExist(value[1])){
WinKill, % value[1]
}
}
GuiControl, Disable, Start
Reload
sleep, 2500
GuiControl, Enable, Start
Return
AddToAccountList:
Gui, UserEditor:New, ,User Editor
Gui, Color, E8E8E8
Gui, Add, GroupBox, x10 y10 w139 h365 , Loop Actions
Gui, UserEditor:Add, Text, x20 y30, Set account name
Gui, UserEditor:Add, Edit, x20 y50 w100 h20 vAccountName -VScroll
Gui, UserEditor:Add, Text, x20 y70, Set Email
Gui, UserEditor:Add, Edit, x20 y90 w100 h20 vAccountEmail -VScroll
Gui, UserEditor:Add, Text, x20 y110, Set Password
Gui, UserEditor:Add, Edit, x20 y130 w100 h20 vAccountPassword -VScroll
Gui, UserEditor:Add, CheckBox, x20 y160 vAutoM1, Auto M1?
Gui, UserEditor:Add, CheckBox, x20 y180 vAutoM2, Auto M2?
Gui, UserEditor:Add, CheckBox, x20 y200 vAutoSpecial1, Auto Special 1?
Gui, UserEditor:Add, CheckBox, x20 y220 vAutoSpecial2, Auto Special 2?
Gui, UserEditor:Add, CheckBox, x20 y240 vAutoRButton, Auto press r?
Gui, UserEditor:Add, CheckBox, x20 y260 vAutoTButton, Auto press t?
Gui, UserEditor:Add, CheckBox, x20 y280 vAutoLoot, Auto loot?
Gui, UserEditor:Add, CheckBox, x20 y300 vAutoReconnect, Auto reconnect?
Gui, UserEditor:Add, CheckBox, x20 y320 vDisableAccount, Disable account?
Gui, Add, GroupBox, x150 y10 w130 h105 , One Time Actions
Gui, UserEditor:Add, CheckBox,  x160 y30 vAutoPvP, Auto start PvP?
Gui, UserEditor:Add, CheckBox,  x160 y50 vFXDisable, FXDisable?
Gui, UserEditor:Add, CheckBox,  x160 y70 vbadGraphic, Bad graphic?
Gui, UserEditor:Add, Text, x163 y93, after
Gui, UserEditor:Add, Edit, x190 y90 w40 h20 vOneTimeActDelayed -VScroll Number, 15000
Gui, UserEditor:Add, Text, x237 y93, ms
Gui, Add, GroupBox, x150 y115 w130 h260 , Window Position/Size
Gui, UserEditor:Add, Text, x160 y130, Set winX
Gui, UserEditor:Add, Edit, x160 y145 w100 h20 vwinX -VScroll, 0
Gui, UserEditor:Add, Text, x160 y170, Set winY
Gui, UserEditor:Add, Edit, x160 y185 w100 h20 vwinY -VScroll, 0
Gui, UserEditor:Add, Text, x160 y210, Set winW
Gui, UserEditor:Add, Edit, x160 y225 w100 h20 vwinW -VScroll, 480
Gui, UserEditor:Add, Text, x160 y250, Set winH
Gui, UserEditor:Add, Edit, x160 y265 w100 h20 vwinH -VScroll, 480
Gui, UserEditor:Add, Button, x160 y295 w100 h30 gAddUser, Add
Gui, UserEditor:+MinSize340x
Gui, UserEditor:Show
Gosub, PrivacyCheck
Return
StopTask:
FailSafe := !FailSafe
if(FailSafe){
GuiControl, , Button2, Start
}else{
GuiControl, , Button2, Stop
}
Return
RemoveFromAccountList:
Gui, UserEditor:Submit
Gui, UserEditor:Destroy
Gui, Main:Default
LV_Delete(UserTableRowBeingEdited)
LV_ModifyCol(1)
LV_ModifyCol(2)
LV_ModifyCol(3)
Settings := []
Loop % LV_GetCount()
{
LV_GetText(AccountName, A_Index, 1)
LV_GetText(AccountEmail, A_Index, 2)
LV_GetText(AccountPassword, A_Index, 3)
LV_GetText(AutoM1, A_Index, 4)
LV_GetText(AutoM2, A_Index, 5)
LV_GetText(AutoSpecial1, A_Index, 6)
LV_GetText(AutoSpecial2, A_Index, 7)
LV_GetText(AutoRButton, A_Index, 8)
LV_GetText(AutoTButton, A_Index, 9)
LV_GetText(AutoLoot, A_Index, 10)
LV_GetText(AutoReconnect, A_Index, 11)
LV_GetText(FXDisable, A_Index, 12)
LV_GetText(DisableAccount, A_Index, 13)
LV_GetText(winX, A_Index, 14)
LV_GetText(winY, A_Index, 15)
LV_GetText(winW, A_Index, 16)
LV_GetText(winH, A_Index, 17)
LV_GetText(AutoPvP, A_Index, 18)
LV_GetText(OneTimeActDelayed, A_Index, 19)
LV_GetText(badGraphic, A_Index, 20)
Settings.Push([AccountName, AccountEmail, AccountPassword, AutoM1, AutoM2, AutoSpecial1, AutoSpecial2, AutoRButton, AutoTButton, AutoLoot, AutoReconnect, FXDisable, DisableAccount, winX, winY, winW, winH, AutoPvP, OneTimeActDelayed, badGraphic])
}
SaveSettings(Settings)
Gosub, PrivacyCheck
Return
AddUser:
Gui, UserEditor:Submit
Gui, UserEditor:Destroy
Gui, Main:Default
OneTimeActDelayed := OneTimeActDelayed = "" ? 0 : OneTimeActDelayed
LV_Add("", AccountName, AccountEmail, AccountPassword, AutoM1, AutoM2, AutoSpecial1, AutoSpecial2, AutoRButton, AutoTButton, AutoLoot, AutoReconnect, FXDisable, DisableAccount, winX, winY, winW, winH, AutoPvP, OneTimeActDelayed, badGraphic)
LV_ModifyCol(1)
LV_ModifyCol(2)
LV_ModifyCol(3)
Settings := []
Loop, % LV_GetCount()
{
LV_GetText(AccountName, A_Index, 1)
LV_GetText(AccountEmail, A_Index, 2)
LV_GetText(AccountPassword, A_Index, 3)
LV_GetText(AutoM1, A_Index, 4)
LV_GetText(AutoM2, A_Index, 5)
LV_GetText(AutoSpecial1, A_Index, 6)
LV_GetText(AutoSpecial2, A_Index, 7)
LV_GetText(AutoRButton, A_Index, 8)
LV_GetText(AutoTButton, A_Index, 9)
LV_GetText(AutoLoot, A_Index, 10)
LV_GetText(AutoReconnect, A_Index, 11)
LV_GetText(FXDisable, A_Index, 12)
LV_GetText(DisableAccount, A_Index , 13)
LV_GetText(winX, A_Index, 14)
LV_GetText(winY, A_Index, 15)
LV_GetText(winW, A_Index, 16)
LV_GetText(winH, A_Index, 17)
LV_GetText(AutoPvP, A_Index, 18)
LV_GetText(OneTimeActDelayed, A_Index, 19)
LV_GetText(badGraphic, A_Index, 20)
Settings.Push([AccountName, AccountEmail, AccountPassword, AutoM1, AutoM2, AutoSpecial1, AutoSpecial2, AutoRButton, AutoTButton, AutoLoot, AutoReconnect, FXDisable, DisableAccount, winX, winY, winW, winH, AutoPvP, OneTimeActDelayed, badGraphic])
}
SaveSettings(Settings)
Gosub, PrivacyCheck
Return
ListViewInteract:
if(A_GuiEvent = "DoubleClick")
{
UserTableRowBeingEdited := A_EventInfo
LV_GetText(AccountName, UserTableRowBeingEdited, 1)
LV_GetText(AccountEmail, UserTableRowBeingEdited, 2)
LV_GetText(AccountPassword, UserTableRowBeingEdited, 3)
LV_GetText(AutoM1, UserTableRowBeingEdited, 4)
LV_GetText(AutoM2, UserTableRowBeingEdited, 5)
LV_GetText(AutoSpecial1, UserTableRowBeingEdited, 6)
LV_GetText(AutoSpecial2, UserTableRowBeingEdited, 7)
LV_GetText(AutoRButton, UserTableRowBeingEdited, 8)
LV_GetText(AutoTButton, UserTableRowBeingEdited, 9)
LV_GetText(AutoLoot, UserTableRowBeingEdited, 10)
LV_GetText(AutoReconnect, UserTableRowBeingEdited, 11)
LV_GetText(FXDisable, UserTableRowBeingEdited, 12)
LV_GetText(DisableAccount, UserTableRowBeingEdited, 13)
LV_GetText(winX, UserTableRowBeingEdited, 14)
LV_GetText(winY, UserTableRowBeingEdited, 15)
LV_GetText(winW, UserTableRowBeingEdited, 16)
LV_GetText(winH, UserTableRowBeingEdited, 17)
LV_GetText(AutoPvP, UserTableRowBeingEdited, 18)
LV_GetText(OneTimeActDelayed, UserTableRowBeingEdited, 19)
LV_GetText(badGraphic, UserTableRowBeingEdited, 20)
Gui, UserEditor:New, ,User Editor
Gui, Color, E8E8E8
Gui, UserEditor:Add, Text, x10 y10, Set account name
Gui, UserEditor:Add, Edit, x10 y30 w100 h20 vAccountName -VScroll, %AccountName%
Gui, UserEditor:Add, CheckBox, x10 y60 checked%AutoM1% vAutoM1, Auto M1?
Gui, UserEditor:Add, CheckBox, x10 y75 checked%AutoM2% vAutoM2, Auto M2?
Gui, UserEditor:Add, CheckBox, x10 y90 checked%AutoSpecial1% vAutoSpecial1, Auto Special 1?
Gui, UserEditor:Add, CheckBox, x10 y105 checked%AutoSpecial2% vAutoSpecial2, Auto Special 2?
Gui, UserEditor:Add, CheckBox, x140 y15 checked%AutoRButton% vAutoRButton, Auto press r?
Gui, UserEditor:Add, CheckBox, x140 y30 checked%AutoTButton% vAutoTButton, Auto press t?
Gui, UserEditor:Add, CheckBox, x140 y45 checked%AutoLoot% vAutoLoot, Auto loot?
Gui, UserEditor:Add, CheckBox, x140 y60 checked%AutoReconnect% vAutoReconnect, Auto reconnect?
Gui, UserEditor:Add, CheckBox, x140 y75 checked%DisableAccount% vDisableAccount, Disable account?
Gui, Add, Text, x10 y125 w230 h1 +Border
Gui, UserEditor:Add, Text, x80 y130, ONE TIME ACTION
Gui, Add, Text, x10 y145 w230 h1 +Border
Gui, UserEditor:Add, Checkbox, x80 y150 checked%AutoPvP% vAutoPvP, Auto start PvP?
Gui, UserEditor:Add, CheckBox, x80 y165 checked%FXDisable% vFXDisable, FX disable?
Gui, UserEditor:Add, CheckBox, x80 y180 checked%badGraphic% vbadGraphic, Bad graphic?
Gui, UserEditor:Add, Text, x80 y195, after
Gui, UserEditor:Add, Edit, x105 y195 w40 h15 vOneTimeActDelayed -VScroll Number, %OneTimeActDelayed%
Gui, UserEditor:Add, Text, x145 y195, ms
Gui, UserEditor:Add, Text, x10 y215, Set Email
Gui, UserEditor:Add, Edit, x10 y230 w100 h20 vAccountEmail -VScroll, %AccountEmail%
Gui, UserEditor:Add, Text, x140 y215, Set Password
Gui, UserEditor:Add, Edit, x140 y230 w100 h20 vAccountPassword -VScroll, %AccountPassword%
Gui, UserEditor:Add, Text, x10 y255, Set winX
Gui, UserEditor:Add, Edit, x10 y270 w100 h20 vwinX -VScroll, %winX%
Gui, UserEditor:Add, Text, x140 y255, Set winY
Gui, UserEditor:Add, Edit, x140 y270 w100 h20 vwinY -VScroll, %winY%
Gui, UserEditor:Add, Text, x10 y295, Set winW
Gui, UserEditor:Add, Edit, x10 y310 w100 h20 vwinW -VScroll, %winW%
Gui, UserEditor:Add, Text, x140 y295, Set winH
Gui, UserEditor:Add, Edit, x140 y310 w100 h20 vwinH -VScroll, %winH%
Gui, UserEditor:Add, Button, x10 y335 w100 h30 gButtonSave, Save
Gui, UserEditor:Add, Button, x140 y335 w100 h30 gRemoveFromAccountList, Remove
Gui, UserEditor:Show
}
Return
ButtonSave:
Gui, UserEditor:Submit
Gui, UserEditor:Destroy
Gui, Main:Default
OneTimeActDelayed := OneTimeActDelayed = "" ? 15000 : OneTimeActDelayed
LV_Modify(UserTableRowBeingEdited, "",AccountName, AccountEmail, AccountPassword, AutoM1, AutoM2, AutoSpecial1, AutoSpecial2, AutoRButton, AutoTButton, AutoLoot, AutoReconnect, FXDisable, DisableAccount, winX, winY, winW, winH, AutoPvP, OneTimeActDelayed, badGraphic, A_EventInfo)
LV_ModifyCol(1)
LV_ModifyCol(2)
LV_ModifyCol(3)
Settings[UserTableRowBeingEdited][1] := AccountName
Settings[UserTableRowBeingEdited][2] := AccountEmail
Settings[UserTableRowBeingEdited][3] := AccountPassword
Settings[UserTableRowBeingEdited][4] := AutoM1
Settings[UserTableRowBeingEdited][5] := AutoM2
Settings[UserTableRowBeingEdited][6] := AutoSpecial1
Settings[UserTableRowBeingEdited][7] := AutoSpecial2
Settings[UserTableRowBeingEdited][8] := AutoRButton
Settings[UserTableRowBeingEdited][9] := AutoTButton
Settings[UserTableRowBeingEdited][10] := AutoLoot
Settings[UserTableRowBeingEdited][11] := AutoReconnect
Settings[UserTableRowBeingEdited][12] := FXDisable
Settings[UserTableRowBeingEdited][13] := DisableAccount
Settings[UserTableRowBeingEdited][14] := winX
Settings[UserTableRowBeingEdited][15] := winY
Settings[UserTableRowBeingEdited][16] := winW
Settings[UserTableRowBeingEdited][17] := winH
Settings[UserTableRowBeingEdited][18] := AutoPvP
Settings[UserTableRowBeingEdited][19] := OneTimeActDelayed
Settings[UserTableRowBeingEdited][20] := badGraphic
SaveSettings(Settings)
Gosub, PrivacyCheck
Return
SaveSettings(SettingsToSave){
IniDelete,Settings.ini, Settings
data := ""
for index, value in SettingsToSave{
value[19] := value[19] = "" ? 15000 : value[19]
value[16] := value[16] = "" || value[16] = "winW" ? 480 : value[16]
value[17] := value[17] = "" || value[17] = "winH" ? 480 : value[17]
data .= value[1] . ",!," . value[2] . ",!," . value[3] . ",!," . value[4] . ",!," . value[5] . ",!," . value[6] . ",!," . value[7] . ",!," . value[8] . ",!," . value[9] . ",!," . value[10] . ",!," . value[11] . ",!," . value[12] . ",!," . value[13] . ",!," . value[14] . ",!," . value[15] . ",!," . value[16] . ",!," . value[17] . ",!," . value[18] . ",!," . value[19] . ",!," . value[20] . "`n"
}
SaveUiSetting(1.4,"SettingsVersion")
IniWrite, %data% , Settings.ini, Settings
}
SaveUiSetting(Setting, Name){
IniWrite, %Setting%, Settings.ini, UiSettings, %Name%
}
LoadUiSetting(Setting, Name){
IniRead, Setting, Settings.ini, UiSettings, %Name%
Return, Setting
}
LoadSettings(){
global SettingsVersion := LoadUiSetting("SettingsVersion","SettingsVersion")
SettingsFile := []
Settings := []
IniRead, SettingsFile, Settings.ini, Settings
for index, value in strSplit(SettingsFile, "`n"){
if(index == SettingsFile.Length()+1)
continue
if(SettingsVersion != "1.4"){
if ( index <= 100){
row := StrSplit(value, ",")
row[21] := SubStr(row[21], 1 , 1)
Settings.Push(row)
}
}
if(SettingsVersion == "1.4") {
if (index <= 100){
row := StrSplit(value, ",!,")
row[21] := SubStr(row[21], 1 , 1)
Settings.Push(row)
}
}
}
Return, Settings
}
AwaitActiveWindow(ExpectedWindow){
WinGetActiveTitle, ActiveWindow
while(ActiveWindow != ExpectedWindow){
WinGetActiveTitle, ActiveWindow
Sleep, 1
}
}
GetAddress(PID, Base, Address, Offset = "") {
pointerBase := base + Address
if (Offset == "")
{
return pointerBase
}
y := ReadMemory(pointerBase,PID)
OffsetSplit := StrSplit(Offset, "+")
OffsetCount := OffsetSplit.MaxIndex()
Loop, %OffsetCount%
{
if (a_index = OffsetCount)
{
Address := (y + OffsetSplit[a_index])
}
Else
if(a_index = 1)
{
y := ReadMemory(y + OffsetSplit[a_index],PID)
}
Else
{
y := ReadMemory(y + OffsetSplit[a_index],PID)
}
}
Return Address
}
WriteProcessMemory(pid,address,valueToWrite, size = 4) {
VarSetCapacity(processhandle,32,0)
VarSetCapacity(value, 32, 0)
NumPut(valueToWrite,value,0,Uint)
processhandle:=DllCall("OpenProcess","Uint",0x38,"int",0,"int",pid)
Bvar:=DllCall("WriteProcessMemory","Uint",processhandle,"Uint",address+0,"Uint",&value,"Uint",size,"Uint",0)
DllCall("CloseHandle", "ptr", processHandle)
}
FloatToHex(f) {
form := A_FormatInteger
SetFormat Integer, HEX
v := DllCall("MulDiv", Float,f, Int,1, Int,1, UInt)
SetFormat Integer, %form%
Return v
}
runWith(version){
if (A_PtrSize=(version=32?4:8))
Return
SplitPath,A_AhkPath,,ahkDir
if (!FileExist(correct := ahkDir "\AutoHotkeyU" version ".exe")){
MsgBox,0x10,"Error",% "Couldn't find the " version " bit Unicode version of Autohotkey in:`n" correct
ExitApp
}
Run,"%correct%" "%A_ScriptName%",%A_ScriptDir%
ExitApp
}
ReadMemory_Str(MADDRESS, pOffset = 0, PID = "")
{
ProcessHandle := DllCall("OpenProcess", "Int", 24, "Char", 0, "UInt", pid, "Uint")
teststr =
Loop
{
Output := "x"
tempVar := DllCall("ReadProcessMemory", "UInt", ProcessHandle, "UInt", MADDRESS+pOffset, "str", Output, "Uint", 1, "Uint *", 0)
if (ErrorLevel or !tempVar)
{
DllCall("CloseHandle", "int", ProcessHandle)
return teststr
}
if Output =
break
teststr = %teststr%%Output%
MADDRESS++
}
DllCall("CloseHandle", "int", ProcessHandle)
return, teststr
}
