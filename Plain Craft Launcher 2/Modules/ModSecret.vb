﻿'由于包含加解密等安全信息，本文件中的部分代码已被删除

Imports System.Net
Imports System.Reflection
Imports System.Security.Cryptography

Friend Module ModSecret

#Region "杂项"

    '在开源版的注册表与常规版的注册表隔离，以防数据冲突
    Public Const RegFolder As String = "PCLang"
    '用于微软登录的 ClientId
    Public Const OAuthClientId As String = ""
    'CurseForge API Key
    Public Const CurseForgeAPIKey As String = ""

    Friend Sub SecretOnApplicationStart()
        '提升 UI 线程优先级
        Thread.CurrentThread.Priority = ThreadPriority.Highest
        '确保 .NET Framework 版本
        Try
            Dim VersionTest As New FormattedText("", Globalization.CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Fonts.SystemTypefaces.First, 96, New MyColor, DPI)
        Catch ex As UriFormatException '修复 #3555
            Environment.SetEnvironmentVariable("windir", Environment.GetEnvironmentVariable("SystemRoot"), EnvironmentVariableTarget.User)
            Dim VersionTest As New FormattedText("", Globalization.CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Fonts.SystemTypefaces.First, 96, New MyColor, DPI)
        End Try
        '检测当前文件夹权限
        Try
            Directory.CreateDirectory(Path & "PCL")
        Catch ex As Exception
            MsgBox(GetLang("LangModSecretPermissionA", Path, If(Path.StartsWithF("C:", True), GetLang("LangModSecretPermissionAddition"), "")),
                MsgBoxStyle.Critical, GetLang("LangModSecretPermissionError"))
            Environment.[Exit](Result.Cancel)
        End Try
        If Not CheckPermission(Path & "PCL") Then
            MsgBox(GetLang("LangModSecretPermissionB", If(Path.StartsWithF("C:", True), GetLang("LangModSecretPermissionAddition"), "")),
                MsgBoxStyle.Critical, GetLang("LangModSecretPermissionError"))
            Environment.[Exit](Result.Cancel)
        End If
        '开源版本提示
        MyMsgBox(GetLang("LangModSecretDialogOpenSourceVersionContent"), GetLang("LangModSecretDialogOpenSourceVersionTitle"))
    End Sub

    ''' <summary>
    ''' 获取设备标识码。
    ''' </summary>
    Friend Function SecretGetUniqueAddress() As String
        Return "0000-0000-0000-0000"
    End Function

    Friend Sub SecretLaunchJvmArgs(ByRef DataList As List(Of String))
        Dim DataJvmCustom As String = Setup.Get("VersionAdvanceJvm", Version:=McVersionCurrent)
        DataList.Insert(0, If(DataJvmCustom = "", Setup.Get("LaunchAdvanceJvm"), DataJvmCustom)) '可变 JVM 参数
        McLaunchLog("当前剩余内存：" & Math.Round(My.Computer.Info.AvailablePhysicalMemory / 1024 / 1024 / 1024 * 10) / 10 & "G")
        DataList.Add("-Xmn" & Math.Floor(PageVersionSetup.GetRam(McVersionCurrent) * 1024 * 0.15) & "m")
        DataList.Add("-Xmx" & Math.Floor(PageVersionSetup.GetRam(McVersionCurrent) * 1024) & "m")
        If Not DataList.Any(Function(d) d.Contains("-Dlog4j2.formatMsgNoLookups=true")) Then DataList.Add("-Dlog4j2.formatMsgNoLookups=true")
    End Sub

    ''' <summary>
    ''' 打码字符串中的 AccessToken。
    ''' </summary>
    Friend Function SecretFilter(Raw As String, FilterChar As Char) As String
        '打码 "accessToken " 后的内容
        If Raw.Contains("accessToken ") Then
            For Each Token In RegexSearch(Raw, "(?<=accessToken ([^ ]{5}))[^ ]+(?=[^ ]{5})")
                Raw = Raw.Replace(Token, New String(FilterChar, Token.Count))
            Next
        End If
        '打码当前登录的结果
        Dim AccessToken As String = McLoginLoader.Output.AccessToken
        If AccessToken Is Nothing OrElse AccessToken.Length < 10 OrElse Not Raw.ContainsF(AccessToken, True) OrElse
            McLoginLoader.Output.Uuid = McLoginLoader.Output.AccessToken Then 'UUID 和 AccessToken 一样则不打码
            Return Raw
        Else
            Return Raw.Replace(AccessToken, Left(AccessToken, 5) & New String(FilterChar, AccessToken.Length - 10) & Right(AccessToken, 5))
        End If
    End Function

#End Region

#Region "网络鉴权"

    Friend Function SecretCdnSign(UrlWithMark As String)
        If Not UrlWithMark.EndsWithF("{CDN}") Then Return UrlWithMark
        Return UrlWithMark.Replace("{CDN}", "").Replace(" ", "%20")
    End Function
    ''' <summary>
    ''' 设置 Headers 的 UA、Referer。
    ''' </summary>
    Friend Sub SecretHeadersSign(Url As String, ByRef Client As WebClient, Optional UseBrowserUserAgent As Boolean = False)
        If Url.Contains("baidupcs.com") OrElse Url.Contains("baidu.com") Then
            Client.Headers("User-Agent") = "LogStatistic" '#4951
        ElseIf UseBrowserUserAgent Then
            Client.Headers("User-Agent") = "PCL2/" & VersionStandardCode & " Mozilla/5.0 AppleWebKit/537.36 Chrome/63.0.3239.132 Safari/537.36"
        Else
            Client.Headers("User-Agent") = "PCL2/" & VersionStandardCode
        End If
        Client.Headers("Referer") = "http://" & VersionCode & ".pcl2.open.server/"
        If Url.Contains("api.curseforge.com") Then Client.Headers("x-api-key") = CurseForgeAPIKey
    End Sub
    ''' <summary>
    ''' 设置 Headers 的 UA、Referer。
    ''' </summary>
    Friend Sub SecretHeadersSign(Url As String, ByRef Request As HttpWebRequest, Optional UseBrowserUserAgent As Boolean = False)
        If Url.Contains("baidupcs.com") OrElse Url.Contains("baidu.com") Then
            Request.UserAgent = "LogStatistic" '#4951
        ElseIf UseBrowserUserAgent Then
            Request.UserAgent = "PCL2/" & VersionStandardCode & " Mozilla/5.0 AppleWebKit/537.36 Chrome/63.0.3239.132 Safari/537.36"
        Else
            Request.UserAgent = "PCL2/" & VersionStandardCode
        End If
        Request.Referer = "http://" & VersionCode & ".pcl2.open.server/"
        If Url.Contains("api.curseforge.com") Then Request.Headers("x-api-key") = CurseForgeAPIKey
    End Sub

#End Region

#Region "字符串加解密"

    ''' <summary>
    ''' 获取八位密钥。
    ''' </summary>
    Private Function SecretKeyGet(Key As String) As String
        Return "00000000"
    End Function
    ''' <summary>
    ''' 加密字符串。
    ''' </summary>
    Friend Function SecretEncrypt(SourceString As String, Optional Key As String = "") As String
        Key = SecretKeyGet(Key)
        Dim btKey As Byte() = Encoding.UTF8.GetBytes(Key)
        Dim btIV As Byte() = Encoding.UTF8.GetBytes("87160295")
        Dim des As New DESCryptoServiceProvider
        Using MS As New MemoryStream
            Dim inData As Byte() = Encoding.UTF8.GetBytes(SourceString)
            Using cs As New CryptoStream(MS, des.CreateEncryptor(btKey, btIV), CryptoStreamMode.Write)
                cs.Write(inData, 0, inData.Length)
                cs.FlushFinalBlock()
                Return Convert.ToBase64String(MS.ToArray())
            End Using
        End Using
    End Function
    ''' <summary>
    ''' 解密字符串。
    ''' </summary>
    Friend Function SecretDecrypt(SourceString As String, Optional Key As String = "") As String
        Key = SecretKeyGet(Key)
        Dim btKey As Byte() = Encoding.UTF8.GetBytes(Key)
        Dim btIV As Byte() = Encoding.UTF8.GetBytes("87160295")
        Dim des As New DESCryptoServiceProvider
        Using MS As New MemoryStream
            Dim inData As Byte() = Convert.FromBase64String(SourceString)
            Using cs As New CryptoStream(MS, des.CreateDecryptor(btKey, btIV), CryptoStreamMode.Write)
                cs.Write(inData, 0, inData.Length)
                cs.FlushFinalBlock()
                Return Encoding.UTF8.GetString(MS.ToArray())
            End Using
        End Using
    End Function

#End Region

#Region "主题"

    Public Color1 As New MyColor(52, 61, 74)
    Public Color2 As New MyColor(11, 91, 203)
    Public Color3 As New MyColor(19, 112, 243)
    Public Color4 As New MyColor(72, 144, 245)
    Public Color5 As New MyColor(150, 192, 249)
    Public Color6 As New MyColor(213, 230, 253)
    Public Color7 As New MyColor(222, 236, 253)
    Public Color8 As New MyColor(234, 242, 254)
    Public ColorBg0 As New MyColor(150, 192, 249)
    Public ColorBg1 As New MyColor(190, Color7)
    Public ColorGray1 As New MyColor(64, 64, 64)
    Public ColorGray2 As New MyColor(115, 115, 115)
    Public ColorGray3 As New MyColor(140, 140, 140)
    Public ColorGray4 As New MyColor(166, 166, 166)
    Public ColorGray5 As New MyColor(204, 204, 204)
    Public ColorGray6 As New MyColor(235, 235, 235)
    Public ColorGray7 As New MyColor(240, 240, 240)
    Public ColorGray8 As New MyColor(245, 245, 245)
    Public ColorSemiTransparent As New MyColor(1, Color8)

    Public ThemeNow As Integer = -1
    Public ColorHue As Integer = 210, ColorSat As Integer = 85, ColorLightAdjust As Integer = 0, ColorHueTopbarDelta As Object = 0
    Public ThemeDontClick As Integer = 0

    Public Sub ThemeRefresh(Optional NewTheme As Integer = -1)
        Hint(GetLang("LangModSecretHintNoTheme"))
    End Sub
    Public Sub ThemeRefreshMain()
        RunInUi(
        Sub()
            If Not FrmMain.IsLoaded Then Exit Sub
            '顶部条背景
            Dim Brush = New LinearGradientBrush With {.EndPoint = New Point(1, 0), .StartPoint = New Point(0, 0)}
            If ThemeNow = 5 Then
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0, .Color = New MyColor().FromHSL2(ColorHue, ColorSat, 25)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0.5, .Color = New MyColor().FromHSL2(ColorHue, ColorSat, 15)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 1, .Color = New MyColor().FromHSL2(ColorHue, ColorSat, 25)})
                FrmMain.PanTitle.Background = Brush
                FrmMain.PanTitle.Background.Freeze()
            ElseIf Not (ThemeNow = 12 OrElse ThemeDontClick = 2) Then
                If TypeOf ColorHueTopbarDelta Is Integer Then
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 0, .Color = New MyColor().FromHSL2(ColorHue - ColorHueTopbarDelta, ColorSat, 48 + ColorLightAdjust)})
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 0.5, .Color = New MyColor().FromHSL2(ColorHue, ColorSat, 54 + ColorLightAdjust)})
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 1, .Color = New MyColor().FromHSL2(ColorHue + ColorHueTopbarDelta, ColorSat, 48 + ColorLightAdjust)})
                Else
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 0, .Color = New MyColor().FromHSL2(ColorHue + ColorHueTopbarDelta(0), ColorSat, 48 + ColorLightAdjust)})
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 0.5, .Color = New MyColor().FromHSL2(ColorHue + ColorHueTopbarDelta(1), ColorSat, 54 + ColorLightAdjust)})
                    Brush.GradientStops.Add(New GradientStop With {.Offset = 1, .Color = New MyColor().FromHSL2(ColorHue + ColorHueTopbarDelta(2), ColorSat, 48 + ColorLightAdjust)})
                End If
                FrmMain.PanTitle.Background = Brush
                FrmMain.PanTitle.Background.Freeze()
            Else
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0, .Color = New MyColor().FromHSL2(ColorHue - 21, ColorSat, 53 + ColorLightAdjust)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0.33, .Color = New MyColor().FromHSL2(ColorHue - 7, ColorSat, 47 + ColorLightAdjust)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0.67, .Color = New MyColor().FromHSL2(ColorHue + 7, ColorSat, 47 + ColorLightAdjust)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 1, .Color = New MyColor().FromHSL2(ColorHue + 21, ColorSat, 53 + ColorLightAdjust)})
                FrmMain.PanTitle.Background = Brush
            End If
            '主页面背景
            If Setup.Get("UiBackgroundColorful") Then
                Brush = New LinearGradientBrush With {.EndPoint = New Point(0.1, 1), .StartPoint = New Point(0.9, 0)}
                Brush.GradientStops.Add(New GradientStop With {.Offset = -0.1, .Color = New MyColor().FromHSL2(ColorHue - 20, Math.Min(60, ColorSat) * 0.5, 80)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0.4, .Color = New MyColor().FromHSL2(ColorHue, ColorSat * 0.9, 90)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 1.1, .Color = New MyColor().FromHSL2(ColorHue + 20, Math.Min(60, ColorSat) * 0.5, 80)})
                FrmMain.PanForm.Background = Brush
            Else
                FrmMain.PanForm.Background = New MyColor(245, 245, 245)
            End If
            FrmMain.PanForm.Background.Freeze()
        End Sub)
    End Sub
    Public Sub ThemeCheckAll(EffectSetup As Boolean)
    End Sub
    Public Function ThemeCheckOne(Id As Integer) As Boolean
        Return True
    End Function
    Friend Function ThemeUnlock(Id As Integer, Optional ShowDoubleHint As Boolean = True, Optional UnlockHint As String = Nothing) As Boolean
        Return False
    End Function
    Public Function ThemeCheckGold(Optional Code As String = Nothing) As Boolean
        Return False
    End Function
    Public Function DonateCodeInput() As Boolean?
        Return Nothing
    End Function

#End Region

#Region "更新"

    Public IsUpdateStarted As Boolean = False
    Public IsUpdateWaitingRestart As Boolean = False
    Public Sub UpdateCheckByButton()
        UpdateStart("https://api.github.com/repos/PCL-Community/PCL2-Language/releases/latest", False)
        'Hint(GetLang("LangModSecretHintNoUpdate"))
    End Sub
    Public Sub UpdateStart(BaseUrl As String, Slient As Boolean, Optional ReceivedKey As String = Nothing, Optional ForceValidated As Boolean = False)
        If IsUpdateStarted Then
            Hint("正在检查更新 - Checking updates...")
            Exit Sub
        End If
        Dim UpdateLoader As New LoaderTask(Of Integer, Integer)("PCL 多语言更新", Sub()
                                                                                 Try
                                                                                     IsUpdateStarted = True
                                                                                     Dim latestReleaseJson As JObject = NetGetCodeByRequestRetry(BaseUrl, IsJson:=True)
                                                                                     Dim latestVersion As String = latestReleaseJson("tag_name").ToString()
                                                                                     If latestVersion.Equals(VersionBaseName) AndAlso Not Slient Then
                                                                                         Hint("最新版本 - You are using the latest version", HintType.Finish)
                                                                                         IsUpdateStarted = False
                                                                                         Exit Sub
                                                                                     End If
                                                                                     ' 下载更新文件
                                                                                     Dim fileList As JArray = latestReleaseJson("assets")
                                                                                     If fileList.Count.Equals(0) Then
                                                                                         Hint("无更新文件 - No update file available...")
                                                                                         IsUpdateStarted = False
                                                                                         Exit Sub
                                                                                     End If
                                                                                     Dim downloadUrl As String = fileList.ElementAt(0)("browser_download_url").ToString()
                                                                                     Dim updateFilePath As String = PathTemp & "PCL2_Lang_Update.zip"
                                                                                     NetDownload(downloadUrl, updateFilePath)

                                                                                     ExtractFile(updateFilePath, PathTemp)

                                                                                     ' 替换旧文件
                                                                                     UpdateReplace(Process.GetCurrentProcess().Id, PathWithName, PathTemp & "Plain Craft Launcher 2.exe", True)
                                                                                 Catch ex As Exception
                                                                                     IsUpdateStarted = False
                                                                                     Log(ex, "更新失败…… Update fail...", LogLevel.Msgbox)
                                                                                 End Try
                                                                             End Sub)
        UpdateLoader.Start(1)
    End Sub

    Public Sub UpdateRestart(TriggerRestartAndByEnd As Boolean)
        IsUpdateWaitingRestart = True
        If TriggerRestartAndByEnd Then
            Process.Start(PathWithName, $"--update ""{PathWithName}"" ""{PathTemp & "Plain Craft Launcher 2.exe"}"" True")
        End If
    End Sub

    Public Sub UpdateReplace(ProcessId As Integer, OldFileName As String, NewFileName As String, TriggerRestart As Boolean)
        Try
            Dim process As Process = Process.GetProcessById(ProcessId)
            process.Kill()
            File.Copy(NewFileName, OldFileName, True)
            File.Delete(NewFileName)
            If TriggerRestart Then
                Process.Start(OldFileName)
            End If
        Catch ex As Exception
            MsgBox("替换文件失败：" & ex.Message, MsgBoxStyle.Critical)
        End Try
    End Sub

#End Region

#Region "联网通知"

    Public ServerLoader As New LoaderTask(Of Integer, Integer)("PCL 服务", Sub() Log("[Server] 该版本中不包含更新通知功能……"), Priority:=ThreadPriority.BelowNormal)

#End Region

End Module
