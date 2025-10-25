'由于包含加解密等安全信息，本文件中的部分代码已被删除

Imports System.ComponentModel
Imports System.Security.Cryptography

Friend Module ModSecret

#Region "杂项"

    '标注 PCL 的不同分支，仅用于替换标记
    Public Const VersionBranchMain As String = "OpenSource"
    '在开源版的注册表与常规版的注册表隔离，以防数据冲突
    Public Const RegFolder As String = "PCLang"
    '用于微软登录的 ClientId
    Public OAuthClientId As String = If(Environment.GetEnvironmentVariable("PCL_MS_CLIENT_ID"), "")
    'CurseForge API Key
    Public CurseForgeAPIKey As String = If(Environment.GetEnvironmentVariable("PCL_CURSEFORGE_API_KEY"), "")
    '用于匿名数据收集的腾讯云日志服务上报 URL，形如 https://{region}.cls.tencentcs.com/track?topic_id={topic_id}
    Public Const ClsBaseUrl As String = ""

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
            Environment.[Exit](ProcessReturnValues.Cancel)
        End Try
        If Not CheckPermission(Path & "PCL") Then
            MsgBox(GetLang("LangModSecretPermissionB", If(Path.StartsWithF("C:", True), GetLang("LangModSecretPermissionAddition"), "")),
                MsgBoxStyle.Critical, GetLang("LangModSecretPermissionError"))
            Environment.[Exit](ProcessReturnValues.Cancel)
        End If
        '开源版本提示
        If Not Setup.Get("UiHiddenDebugVersionNotice") Then
            MyMsgBox(GetLang("LangModSecretDialogOpenSourceVersionContent"), GetLang("LangModSecretDialogOpenSourceVersionTitle"))
        End If
        Setup.Set("UiHiddenDebugVersionNotice", True)
    End Sub

    ''' <summary>
    ''' 获取设备标识码。
    ''' </summary>
    Friend Function SecretGetIdentify() As String
        Return "0000-0000-0000-0000"
    End Function

    Friend Sub SecretLaunchJvmArgs(ByRef DataList As List(Of String))
        Dim DataJvmCustom As String = Setup.Get("VersionAdvanceJvm", Version:=McVersionCurrent)
        DataList.Insert(0, ArgumentReplace(If(DataJvmCustom = "", Setup.Get("LaunchAdvanceJvm"), DataJvmCustom))) '可变 JVM 参数
        McLaunchLog("当前剩余内存：" & Math.Round(My.Computer.Info.AvailablePhysicalMemory / 1024 / 1024 / 1024 * 10) / 10 & "G")
        DataList.Add("-Xmn" & Math.Floor(PageVersionSetup.GetRam(McVersionCurrent) * 1024 * 0.15) & "m")
        DataList.Add("-Xmx" & Math.Floor(PageVersionSetup.GetRam(McVersionCurrent) * 1024) & "m")
        If Not DataList.Any(Function(d) d.Contains("-Dlog4j2.formatMsgNoLookups=true")) Then DataList.Add("-Dlog4j2.formatMsgNoLookups=true")
    End Sub

#End Region

#Region "网络鉴权"

    Friend Function SecretCdnSign(UrlWithMark As String) As String
        If Not UrlWithMark.EndsWithF("{CDN}") Then Return UrlWithMark
        Return UrlWithMark.Replace("{CDN}", "").Replace(" ", "%20")
    End Function
    ''' <summary>
    ''' 设置 Headers 的 UA、Referer。
    ''' </summary>
    Friend Sub SecretHeadersSign(Url As String, ByRef Req As HttpRequestMessage, Optional SimulateBrowserHeaders As Boolean = False)
        If Not Req.Headers.UserAgent.Any Then
            If Url.Contains("baidupcs.com") OrElse Url.Contains("baidu.com") Then
                Req.Headers.Add("User-Agent", "LogStatistic")  '#4951
            ElseIf SimulateBrowserHeaders Then
                Req.Headers.Add("User-Agent", $"PCL2/{VersionStandardCode} Mozilla/5.0 AppleWebKit/537.36 Chrome/63.0.3239.132 Safari/537.36")
            Else
                Req.Headers.Add("User-Agent", $"PCL2/{VersionStandardCode}")
            End If
        End If
        If Not SimulateBrowserHeaders Then Req.Headers.Add("Referer", $"http://{VersionCode}.open.pcl2.server/")
        If Url.Contains("api.curseforge.com") Then Req.Headers.Add("x-api-key", CurseForgeAPIKey)
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
        Try
            If ThemeNow = NewTheme AndAlso NewTheme >= 0 Then Return
            If NewTheme >= 0 Then ThemeNow = NewTheme

            Color1 = New MyColor().FromHSL2(ColorHue, ColorSat * 0.2, 25 + ColorLightAdjust * 0.3)
            Color2 = New MyColor().FromHSL2(ColorHue, ColorSat, 45 + ColorLightAdjust)
            Color3 = New MyColor().FromHSL2(ColorHue, ColorSat, 55 + ColorLightAdjust)
            Color4 = New MyColor().FromHSL2(ColorHue, ColorSat, 65 + ColorLightAdjust)
            Color5 = New MyColor().FromHSL2(ColorHue, ColorSat, 80 + ColorLightAdjust * 0.4)
            Color6 = New MyColor().FromHSL2(ColorHue, ColorSat, 91 + ColorLightAdjust * 0.1)
            Color7 = New MyColor().FromHSL2(ColorHue, ColorSat, 95)
            Color8 = New MyColor().FromHSL2(ColorHue, ColorSat, 97)
            ColorBg0 = Color4 * 0.4 + Color5 * 0.4 + ColorGray4 * 0.2
            ColorBg1 = New MyColor(190, Color7)

            ColorSemiTransparent = New MyColor(1, Color8)
            Application.Current.Resources("ColorBrush1") = New SolidColorBrush(Color1)
            Application.Current.Resources("ColorBrush2") = New SolidColorBrush(Color2)
            Application.Current.Resources("ColorBrush3") = New SolidColorBrush(Color3)
            Application.Current.Resources("ColorBrush4") = New SolidColorBrush(Color4)
            Application.Current.Resources("ColorBrush5") = New SolidColorBrush(Color5)
            Application.Current.Resources("ColorBrush6") = New SolidColorBrush(Color6)
            Application.Current.Resources("ColorBrush7") = New SolidColorBrush(Color7)
            Application.Current.Resources("ColorBrush8") = New SolidColorBrush(Color8)
            Application.Current.Resources("ColorBrushBg0") = New SolidColorBrush(ColorBg0)
            Application.Current.Resources("ColorBrushBg1") = New SolidColorBrush(ColorBg1)
            Application.Current.Resources("ColorObject1") = CType(Color1, Color)
            Application.Current.Resources("ColorObject2") = CType(Color2, Color)
            Application.Current.Resources("ColorObject3") = CType(Color3, Color)
            Application.Current.Resources("ColorObject4") = CType(Color4, Color)
            Application.Current.Resources("ColorObject5") = CType(Color5, Color)
            Application.Current.Resources("ColorObject6") = CType(Color6, Color)
            Application.Current.Resources("ColorObject7") = CType(Color7, Color)
            Application.Current.Resources("ColorObject8") = CType(Color8, Color)
            Application.Current.Resources("ColorObjectBg0") = CType(ColorBg0, Color)
            Application.Current.Resources("ColorObjectBg1") = CType(ColorBg1, Color)
            ThemeRefreshMain()
        Catch ex As Exception
            Log(ex, "刷新主题颜色失败", LogLevel.Hint)
        End Try
    End Sub
    Public Sub ThemeRefreshMain()
        RunInUi(
        Sub()
            If Not FrmMain.IsLoaded Then Return
            '顶部条背景
            Dim Brush = New LinearGradientBrush With {.EndPoint = New Point(1, 0), .StartPoint = New Point(0, 0)}
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
            '主页面背景
            If Setup.Get("UiBackgroundColorful") Then
                Brush = New LinearGradientBrush With {.EndPoint = New Point(0.1, 1), .StartPoint = New Point(0.9, 0)}
                Brush.GradientStops.Add(New GradientStop With {.Offset = -0.1, .Color = New MyColor().FromHSL2(ColorHue - 15, ColorSat * 0.8, 91)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 0.4, .Color = New MyColor().FromHSL2(ColorHue, ColorSat * 0.8, 91)})
                Brush.GradientStops.Add(New GradientStop With {.Offset = 1.1, .Color = New MyColor().FromHSL2(ColorHue + 15, ColorSat * 0.8, 91)})
                FrmMain.PanForm.Background = Brush
            Else
                FrmMain.PanForm.Background = New MyColor(245, 245, 245)
            End If
            FrmMain.PanForm.Background.Freeze()
        End Sub)
    End Sub
    Friend Sub ThemeCheckAll(EffectSetup As Boolean)
    End Sub
    Friend Function ThemeCheckOne(Id As Integer) As Boolean
        Return True
    End Function
    Friend Function ThemeUnlock(Id As Integer, Optional ShowDoubleHint As Boolean = True, Optional UnlockHint As String = Nothing) As Boolean
        Return False
    End Function
    Friend Function ThemeCheckGold(Optional Code As String = Nothing) As Boolean
        Return False
    End Function
    Friend Function DonateCodeInput() As Boolean?
        Return Nothing
    End Function

#End Region

#Region "更新"

    Public IsUpdateStarted As Boolean = False
    Public IsUpdateWaitingRestart As Boolean = False
    Public LatestVersion As String = VersionBaseName
    Public Sub UpdateCheckByButton()
        Hint("Checking...")
        If IsUpdateStarted Then
            Exit Sub
        End If
        Dim LatestVersion As String = Nothing
        RunInNewThread(Sub()
                           Try
                               UpdateLatestVersionInfo()
                               NoticeUserUpdate()
                           Catch ex As Exception
                               Log(ex, "[Update] 获取启动器更新信息失败", LogLevel.Hint)
                               Hint("获取启动器更新信息失败，请检查网络连接", HintType.Critical)
                           End Try
                       End Sub)
    End Sub
    Public Sub UpdateLatestVersionInfo()
        Dim LatestReleaseInfoJson As JObject = Nothing
        LatestReleaseInfoJson = GetJson(NetRequestByClientRetry("https://api.github.com/repos/PCL-Community/PCL2-Language/releases/latest", HttpMethod.Get, "", "application/x-www-form-urlencoded"))
        LatestVersion = LatestReleaseInfoJson("tag_name").ToString
    End Sub
    Public Sub NoticeUserUpdate()
        If Not LatestVersion = VersionBaseName Then
            If MyMsgBox($"{VersionBaseName} -> {LatestVersion}?", "Update?", "Go update!", GetLang("LangDialogBtnCancel")) = 1 Then
                UpdateStart(LatestVersion, False)
            End If
        Else
            Hint("Latest " + VersionBaseName, HintType.Finish)
        End If
    End Sub
    Public Sub UpdateStart(VersionStr As String, Slient As Boolean, Optional ReceivedKey As String = Nothing, Optional ForceValidated As Boolean = False)
        Dim DlLink As String = "https://github.com/PCL-Community/PCL2-Language/releases/download/" + VersionStr + "/PCL2_Lang.exe"
        Dim DlTargetPath As String = Path + "PCL\Plain Craft Launcher 2.exe"
        RunInNewThread(Sub()
                           Try
                               '构造步骤加载器
                               Dim Loaders As New List(Of LoaderBase)
                               '下载
                               Dim Address As New List(Of String)
                               Address.Add(DlLink)
                               Loaders.Add(New LoaderDownload("Download file", New List(Of NetFile) From {New NetFile(Address.ToArray, DlTargetPath, New FileChecker(MinSize:=1024 * 64))}) With {.ProgressWeight = 15})
                               If Not Slient Then
                                   Loaders.Add(New LoaderTask(Of Integer, Integer)("Replace file", Sub() UpdateRestart(True)))
                               End If
                               '启动
                               Dim Loader As New LoaderCombo(Of JObject)("Update", Loaders)
                               Loader.Start()
                               If Slient Then
                                   IsUpdateWaitingRestart = True
                               Else
                                   LoaderTaskbarAdd(Loader)
                                   FrmMain.BtnExtraDownload.ShowRefresh()
                                   FrmMain.BtnExtraDownload.Ribble()
                               End If
                           Catch ex As Exception
                               Log(ex, "[Update] 下载启动器更新文件失败", LogLevel.Hint)
                               Hint("下载启动器更新文件失败，请检查网络连接", HintType.Critical)
                           End Try
                       End Sub)
    End Sub
    Public Sub UpdateRestart(TriggerRestartAndByEnd As Boolean)
        Try
            Dim fileName As String = Path + "PCL\Plain Craft Launcher 2.exe"
            If Not File.Exists(fileName) Then
                Log("[System] 更新失败：未找到更新文件")
                Exit Sub
            End If
            ' id old new restart
            Dim text As String = String.Concat(New String() {"--update ", Process.GetCurrentProcess().Id, " """, PathWithName, """ """, fileName, """ ", TriggerRestartAndByEnd})
            Log("[System] 更新程序启动，参数：" + text, LogLevel.Normal, "出现错误")
            Process.Start(New ProcessStartInfo(fileName) With {.WindowStyle = ProcessWindowStyle.Hidden, .CreateNoWindow = True, .Arguments = text})
            If TriggerRestartAndByEnd Then
                FrmMain.EndProgram(False)
                Log("[System] 已由于更新强制结束程序", LogLevel.Normal, "出现错误")
            End If
        Catch ex As Win32Exception
            Log(ex, "自动更新时触发 Win32 错误，疑似被拦截", LogLevel.Debug, "出现错误")
            If MyMsgBox(String.Format("由于被 Windows 安全中心拦截，或者存在权限问题，导致 PCL 无法更新。{0}请将 PCL 所在文件夹加入白名单，或者手动用 {1}PCL\Plain Craft Launcher 2.exe 替换当前文件！", vbCrLf, ModBase.Path), "更新失败", "查看帮助", "确定", "", True, True, False, Nothing, Nothing, Nothing) = 1 Then
                TryStartEvent("打开帮助", "启动器/Microsoft Defender 添加排除项.json")
            End If
        End Try
    End Sub
    Public Sub UpdateReplace(ProcessId As Integer, OldFileName As String, NewFileName As String, TriggerRestart As Boolean)
        Try
            Dim ps = Process.GetProcessById(ProcessId)
            If Not ps.HasExited Then
                ps.Kill()
            End If
        Catch ex As Exception
        End Try
        Dim ex2 As Exception = Nothing
        Dim num As Integer = 0
        Do
            Try
                If File.Exists(OldFileName) Then
                    File.Delete(OldFileName)
                End If
                If Not File.Exists(OldFileName) Then
                    Exit Try
                End If
            Catch ex3 As Exception
                ex2 = ex3
            Finally
                Thread.Sleep(500)
            End Try
            num += 1
        Loop While num <= 4
        If (Not File.Exists(OldFileName)) AndAlso File.Exists(NewFileName) Then
            Try
                CopyFile(NewFileName, OldFileName)
            Catch ex4 As UnauthorizedAccessException
                MsgBox("PCL 更新失败：权限不足。请手动复制 PCL 文件夹下的新版本程序。" & vbCrLf & "若 PCL 位于桌面或 C 盘，你可以尝试将其挪到其他文件夹，这可能可以解决权限问题。" & vbCrLf + GetExceptionSummary(ex4), MsgBoxStyle.Critical, "更新失败")
            Catch ex5 As Exception
                MsgBox("PCL 更新失败：无法复制新文件。请手动复制 PCL 文件夹下的新版本程序。" & vbCrLf + GetExceptionSummary(ex5), MsgBoxStyle.Critical, "更新失败")
                Return
            End Try
            If TriggerRestart Then
                Try
                    Process.Start(OldFileName)
                Catch ex6 As Exception
                    MsgBox("PCL 更新失败：无法重新启动。" & vbCrLf + GetExceptionSummary(ex6), MsgBoxStyle.Critical, "更新失败")
                End Try
            End If
            Return
        End If
        If TypeOf ex2 Is UnauthorizedAccessException Then
            MsgBox(String.Concat(New String() {"由于权限不足，PCL 无法完成更新。请尝试：" & vbCrLf,
                                 If((Path.StartsWithF(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), False) OrElse Path.StartsWithF(Environment.GetFolderPath(Environment.SpecialFolder.Personal), False)),
                                 " - 将 PCL 文件移动到桌面、文档以外的文件夹（这或许可以一劳永逸地解决权限问题）" & vbCrLf, ""),
                                 If(Path.StartsWithF("C", True),
                                 " - 将 PCL 文件移动到 C 盘以外的文件夹（这或许可以一劳永逸地解决权限问题）" & vbCrLf, ""),
                                 " - 右键以管理员身份运行 PCL" & vbCrLf & " - 手动复制已下载到 PCL 文件夹下的新版本程序，覆盖原程序" & vbCrLf & vbCrLf,
                                 GetExceptionSummary(ex2)}), MsgBoxStyle.Critical, "更新失败")
            Return
        End If
        MsgBox("PCL 更新失败：无法删除原文件。请手动复制已下载到 PCL 文件夹下的新版本程序覆盖原程序。" & vbCrLf + GetExceptionSummary(ex2), MsgBoxStyle.Critical, "更新失败")
    End Sub
    ''' <summary>
    ''' 确保 PathTemp 下的 Latest.exe 是最新正式版的 PCL，它会被用于整合包打包。
    ''' 如果不是，则下载一个。
    ''' </summary>
    Friend Sub DownloadLatestPCL(Optional LoaderToSyncProgress As LoaderBase = Nothing)
        '注意：如果要自行实现这个功能，请换用另一个文件路径，以免与官方版本冲突
    End Sub

#End Region

#Region "联网配置"

    ''' <summary>
    ''' 联网获取的配置信息。
    ''' 若获取失败或仍在获取中，可能为 Nothing。
    ''' </summary>
    Public ServerConfig As JObject

    Public ServerLoader As New LoaderTask(Of Integer, Integer)("PCL 配置更新", AddressOf LoadOnlineInfo, Priority:=ThreadPriority.BelowNormal) With
        {.ReloadTimeout = 1000 * 60 * 60} '超时 1 小时

    Private Sub LoadOnlineInfo()
        Select Case Setup.Get("SystemSystemUpdate")
            Case 0
                UpdateLatestVersionInfo()
                If VersionBaseName <> LatestVersion Then
                    UpdateStart(LatestVersion, True) '静默更新
                End If
            Case 1
                UpdateLatestVersionInfo()
                NoticeUserUpdate()
            Case 2, 3
                Exit Sub
        End Select
    End Sub
#End Region

End Module
