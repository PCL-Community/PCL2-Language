Public Class PageLinkMain

    '===============================
    '  状态机与前端页面
    '===============================

#Region "状态管理"

    Private Enum States
        Waiting
        Loading
        Failed
        Finished
    End Enum
    Private State As States = States.Waiting

    ''' <summary>
    ''' 切换到指定的状态。
    ''' </summary>
    Private Sub ChangeState(NewState As States)
        If State = NewState Then Return
        Dim OldState = State
        State = NewState
        Log($"[Link] 主状态由 {GetStringFromEnum(OldState)} 变更为 {GetStringFromEnum(NewState)}")
        '触发状态切换
        RunInUi(
        Sub()
            Select Case NewState
                Case States.Waiting
                    SwitchToWaiting(OldState)
                Case States.Loading
                    SwitchToLoading(OldState)
                Case States.Failed
                    SwitchToFailed(OldState)
                Case States.Finished
                    SwitchToFinished(OldState)
            End Select
        End Sub)
    End Sub

    '让加载器的 成功/失败 事件触发状态切换
    Private Sub LoaderInit() Handles Me.Initialized
        PageLoaderInit(Load, PanLoad, PanContent, PanAlways, LinkLoader, AutoRun:=False)
        AddHandler LinkLoader.OnStateChangedUi,
        Sub(Loader As LoaderBase, NewState As LoadState, OldState As LoadState)
            Select Case NewState
                Case LoadState.Finished
                    ChangeState(States.Finished)
                Case LoadState.Failed
                    Telemetry("联机失败", "Exception", FilterUserName(Loader.Error.GetDetail, "*"))
                    ChangeState(States.Failed)
            End Select
        End Sub
    End Sub

    '页面动画兼容
    Private Sub UpdatePanelVisibility() Handles Me.PageEnter
        FrmLinkMain.PanSelect.Visibility = If(State = States.Waiting, Visibility.Visible, Visibility.Collapsed)
        FrmLinkMain.PanFinish.Visibility = If(State = States.Finished, Visibility.Visible, Visibility.Collapsed)
    End Sub

#End Region

#Region "初始页面 (Waiting)"

    '由任意状态切换到 Waiting
    Private Sub SwitchToWaiting(OldState As States)
        '加载器与进程状态
        LinkLoader.Abort()
        SyncLock LinkLoader.LockState
            LinkLoader.State = LoadState.Waiting
        End SyncLock
        ProcessStop()
        '页面切换
        If OldState <> States.Finished Then
            '从完成页面退出时，PageOnContentExit 结束会触发 PageEnter 事件，这会调用 UpdatePanelVisibility
            '如果在现在提前调用了，会丢失完成页面的退出动画
            UpdatePanelVisibility()
        End If
        PageOnContentExit()
    End Sub

    '===============================
    '  页面 UI
    '===============================

    '创建
    Private Sub Create_MouseLeftButtonUp() Handles PanSelectCreate.MouseLeftButtonUp
        '输入端口号
        Dim Port As String = MyMsgBoxInput("输入端口", $"在单人游戏的暂停菜单选择 {vbLQ}对局域网开放{vbRQ}，然后输入端口数字。{vbCrLf}其实也可以输入其他游戏的端口……",
            ValidateRules:=New ObjectModel.Collection(Of Validate) From {New ValidateInteger(1024, 65535)},
            HintText:="端口号")
        If Port Is Nothing Then Return
        '基础信息
        IsServerSide = True
        ServerPort = Port
        Dim GenerateRandomCode =
        Function() As String
            Dim Result As String = ""
            For i = 1 To 5
                Result &= RadixConvert(RandomInteger(0, 35), 10, 36)
            Next
            Return Result.Replace("O", "0").Replace("I", "1")
        End Function
        NetworkName = $"P{RadixConvert(ServerPort, 10, 16).PadLeft(4, "0"c)}-{GenerateRandomCode()}"
        NetworkSecret = GenerateRandomCode()
        Log($"[Link] 尝试创建房间，网络名 {NetworkName}，网络密码 {NetworkSecret}，端口 {ServerPort}")
        '启动
        ChangeState(States.Loading)
    End Sub

    '加入
    Private LastCode As String = Nothing
    Private Sub Join_MouseLeftButtonUp() Handles PanSelectJoin.MouseLeftButtonUp
        '输入邀请码
        Dim Code As String = MyMsgBoxInput("输入邀请码", "输入房主发给你的邀请码。",
                                           HintText:=If(String.IsNullOrEmpty(LastCode), "", "使用上一次的邀请码：" & LastCode))
        If Not String.IsNullOrEmpty(LastCode) AndAlso Code IsNot Nothing AndAlso Code = "" Then Code = LastCode
        If Code Is Nothing Then Return
        '基础格式校验
        Code = Code.Between("【", "】").Between("[", "]") '从完整消息中提取
        Code = Code.ToUpper.Replace("O", "0").Replace("I", "1") '输入修正
        If Not (Code.Length >= 14 AndAlso Code(0) = "P"c AndAlso Code(5) = "-"c AndAlso Code(11) = "-"c) Then
            If Code.StartsWithF("U/") Then 'HMCL
                Hint("请让房主使用 PCL 创建房间！", HintType.Red)
            ElseIf Code.Length = 10 Then 'PCL CE
                Hint("请让房主使用非社区版的 PCL 创建房间！", HintType.Red)
            ElseIf Code.StartsWithF("P") Then '远古版 PCL
                Hint("你的 PCL 版本与房主的 PCL 版本不一致，或输入的邀请码有误！", HintType.Red)
            Else
                Hint("邀请码有误，请让房主使用 PCL 创建房间！", HintType.Red)
            End If
            Return
        End If
        '离线登录警告
        If McLoginLoader.State = LoadState.Finished AndAlso McLoginLoader.Output.Type = "Legacy" AndAlso Not Setup.Get("LinkOfflineHint") Then
            Dim Solution As String
            If McVersionCurrent IsNot Nothing AndAlso McVersionCurrent.Version.McVersion >= New Version(1, 21, 5) Then
                Solution = $"请换用正版登录，或是让房主安装 {vbLQ}更高级联机设置{vbRQ} Mod 并禁用正版验证。"
            ElseIf McVersionCurrent IsNot Nothing AndAlso McVersionCurrent.Version.McVersion >= New Version(1, 12, 0) Then
                Solution = $"请换用正版登录，或是让房主安装 {vbLQ}自定义局域网联机{vbRQ} Mod 并关闭在线模式。"
            Else
                Solution = $"请换用正版登录，或是让房主用服务端开服，关闭 online-mode，然后在创建房间时输入服务端的端口号。"
            End If
            Select Case MyMsgBox($"如果不用正版登录可能会进不了服，显示 {vbLQ}无效会话{vbRQ}。" & vbCrLf & Solution,
                                 "离线登录警告", "继续", "继续且不再提示", "取消", IsWarn:=True)
                Case 2
                    Setup.Set("LinkOfflineHint", True)
                Case 3
                    Return
            End Select
        End If
        '基础信息
        IsServerSide = False
        ServerPort = RadixConvert(Code.Substring(1, 4), 16, 10)
        NetworkName = Code.Substring(0, 11)
        NetworkSecret = Code.Substring(12, 5)
        Log($"[Link] 尝试加入房间，网络名 {NetworkName}，网络密码 {NetworkSecret}，端口 {ServerPort}")
        '启动
        LastCode = Code
        ChangeState(States.Loading)
    End Sub

#End Region

#Region "加载页面 (Loading | Failed)"

    '由 Waiting 或 Failed 状态切换到 Loading
    Private Sub SwitchToLoading(OldState As States)
        '清理变量
        Peers = Nothing
        FailCount = 0
        '加载器与进程状态
        LinkLoader.Start(IsForceRestart:=True)
        '页面切换会由 Loader 调用 MyPageRight 来触发
        'UI 更新
        UpdateProgressBar(0)
        LabLoadTitle.Text = If(IsServerSide, "创建房间中", "加入房间中")
        UpdateLoadingPage("正在初始化……", "准备初始化")
    End Sub

    '由 Loading 状态切换到 Failed
    Private Sub SwitchToFailed(OldState As States)
        '加载器与进程状态
        LinkLoader.Abort()
        ProcessStop()
        'UI 更新
        UpdateProgressBar(1)
        '显示错误信息
        LabLoadTitle.Text = FailReason
        Dim Brief As String = LinkLoader.Error.GetBrief
        Dim InnerEx As Exception = LinkLoader.Error
        If InnerEx.Message.StartsWithF("$") Then Brief = InnerEx.Message
        Do Until InnerEx.InnerException Is Nothing
            InnerEx = InnerEx.InnerException
            If InnerEx.Message.StartsWithF("$") Then Brief = InnerEx.Message
        Loop
        LabLoadDesc.Text = If(Brief.StartsWithF("$"), Brief.TrimStart("$"), LinkLoader.Error.GetDetail)
        Log(LinkLoader.Error, LabLoadTitle.Text)
    End Sub

    '===============================
    '  页面 UI
    '===============================

    Private Sub UpdateLoadingPage(Title As String, FailBrief As String)
        If FailReason = FailBrief & "失败" Then Return
        FailReason = FailBrief & "失败"
        Log("[Link] 开始步骤：" & Title)
        RunInUiWait(
        Sub()
            If FrmLinkMain Is Nothing OrElse Not FrmLinkMain.LabLoadDesc.IsLoaded Then Return
            FrmLinkMain.LabLoadDesc.Text = Title
        End Sub)
    End Sub
    Private FailReason As String = "准备初始化"

    '取消加载
    Private Sub BtnLoadCancel_Click() Handles BtnLoadCancel.Click
        ChangeState(States.Waiting)
    End Sub

    '点击重试
    Private Sub CardLoad_MouseLeftButtonUp() Handles CardLoad.MouseLeftButtonUp
        ChangeState(States.Loading)
    End Sub

    '进度条
    Private Sub UpdateProgressBar(Optional Value As Double = -1)
        If Value = -1 Then Value = LinkLoader.Progress
        Dim DisplayingProgress As Double = ColumnProgressA.Width.Value
        If Math.Round(Value - DisplayingProgress, 3) = 0 Then Return
        If DisplayingProgress <= Value Then
            Dim NewProgress As Double = If(Value = 1, 1, DisplayingProgress +
                (Value - DisplayingProgress) ^ 2 * 0.5)
            AniStart({
                AaGridLengthWidth(ColumnProgressA, NewProgress - ColumnProgressA.Width.Value, 200),
                AaGridLengthWidth(ColumnProgressB, (1 - NewProgress) - ColumnProgressB.Width.Value, 200)
            }, "Link Progress")
        Else
            ColumnProgressA.Width = New GridLength(Value, GridUnitType.Star)
            ColumnProgressB.Width = New GridLength(1 - Value, GridUnitType.Star)
            AniStop("Link Progress")
        End If
    End Sub
    Private Sub CardLoad_SizeChanged() Handles CardLoad.SizeChanged
        RectProgressClip.Rect = New Rect(0, 0, CardLoad.ActualWidth, 12)
    End Sub

#End Region

#Region "完成页面 (Finished)"

    '由 Loading 状态切换到 Finished
    Private Sub SwitchToFinished(OldState As States)
        '由于只可能从加载器的完成事件触发，不需要管加载器
        UpdatePanelVisibility() '页面的实际切换会由 Loader 调用 MyPageRight 来触发

        'UI 更新
        If IsServerSide Then
            LabFinishTitle.Text = "已创建房间"
            LabFinishDesc.Text = $"把邀请码发给朋友，让大家加入房间吧！{vbCrLf}邀请码：{NetworkName}-{NetworkSecret}"
            BtnFinishCopy.Text = "复制邀请码"
            BtnFinishExit.Text = "关闭"
            '下边栏
            BtnFinishPing.ToolTip = "网络延迟"
            LineFinishPort.Visibility = Visibility.Visible
            BtnFinishPort.Visibility = Visibility.Visible
            LabFinishPort.Visibility = Visibility.Visible
            LabFinishPort.Text = ServerPort
        Else
            LabFinishTitle.Text = "已加入房间"
            LabFinishDesc.Text = $"在多人游戏中选择直接连接，粘贴地址即可加入游戏！{vbCrLf}服务器地址：{ClientAddress}" '"如果提示无效会话，不要退出联机房间，重新启动游戏即可！"
            BtnFinishCopy.Text = "复制地址"
            BtnFinishExit.Text = "离开"
            '下边栏
            BtnFinishPing.ToolTip = "与房主的延迟"
            LineFinishPort.Visibility = Visibility.Collapsed
            BtnFinishPort.Visibility = Visibility.Collapsed
            LabFinishPort.Visibility = Visibility.Collapsed
        End If
        Copy() '复制信息
        Update() '立即刷新
    End Sub

    '===============================
    '  页面 UI
    '===============================

    '退出
    Private Sub BtnFinishExit_Click() Handles BtnFinishExit.Click
        TryExit(True)
    End Sub
    ''' <summary>
    ''' 退出联机。
    ''' 返回是否弹出了警告窗口并且玩家选择了取消。
    ''' </summary>
    Public Function TryExit(SendWarning As Boolean) As Boolean
        If State = States.Waiting OrElse State = States.Failed Then Return False
        If IsServerSide AndAlso PeopleCount > 1 Then
            If MyMsgBox("你确定要关闭联机房间吗？" & vbCrLf & "所有玩家都需要重新输入邀请码才可加入游戏！", "关闭房间", "确定", "取消", IsWarn:=True) = 2 Then Return True
        End If
        ChangeState(States.Waiting)
        Return False
    End Function

    '复制
    Private Sub Copy() Handles BtnFinishCopy.Click
        If IsServerSide Then
            ClipboardSet($"在 PCL 启动器中输入邀请码【{NetworkName}-{NetworkSecret}】，即可加入联机房间！", False)
            Hint("已复制邀请码！", HintType.Green)
        Else
            ClipboardSet(ClientAddress, False)
            Hint("已复制服务器地址！", HintType.Green)
        End If
    End Sub

#End Region

    '===============================
    '  后端
    '===============================

    ''' <summary>
    ''' EasyTier 所在的文件夹路径，以 \ 结尾。
    ''' </summary>
    Private PathEasyTier As String = PathAppdata & "EasyTier\"
    ''' <summary>
    ''' 当前是服务端还是客户端。
    ''' </summary>
    Private IsServerSide As Boolean
    ''' <summary>
    ''' 服务端映射前的端口号。
    ''' </summary>
    Private ServerPort As Integer
    ''' <summary>
    ''' 在客户端映射后的地址。
    ''' 除非已作为客户端启动 EasyTier，否则一直为 Nothing。
    ''' </summary>
    Private ClientAddress As String = Nothing
    ''' <summary>
    ''' 网络信息。
    ''' </summary>
    Private NetworkName As String, NetworkSecret As String

#Region "加载"

    Private WithEvents LinkLoader As New LoaderCombo(Of Integer)("联机", {
        New LoaderTask(Of Integer, Integer)("获取配置", AddressOf InitConfig) With {.Block = False, .ProgressWeight = 8},
        New LoaderTask(Of Integer, List(Of NetFile))("准备下载联机模块", AddressOf InitPrepareDownload) With {.ProgressWeight = 2},
        New LoaderDownload("下载联机模块", New List(Of NetFile)) With {.ProgressWeight = 40},
        New LoaderTask(Of Integer, Integer)("启动联机模块", AddressOf InitLaunch) With {.ProgressWeight = 50}
    })

    '1. 获取服务器配置
    Private Sub InitConfig(Task As LoaderTask(Of Integer, Integer))
        UpdateLoadingPage("正在联网获取配置……", "联网获取配置")
        If VersionBranchMain <> "Official" Then
            Throw New Exception($"$开源版无法联网获取配置。{vbCrLf}你可以在 PCL 官方版的缓存文件夹下查看 ServerConfig 的当前内容， 并在代码中进行相应修改。")
        End If
        ServerLoader.WaitForExit(LoaderToSyncProgress:=Task)
        If ServerConfig Is Nothing Then Throw New Exception("无法从服务器获取配置")
        If Not String.IsNullOrEmpty(ServerConfig("Link")("DisableReason")) Then '检查是否已禁用联机功能
            Throw New Exception("$" & ServerConfig("Link")("DisableReason").ToString)
        End If
    End Sub

    '2. 获取需要下载的文件
    Private ServerVersion As Integer
    Private Sub InitPrepareDownload(Task As LoaderTask(Of Integer, List(Of NetFile)))
        '获取 CPU 架构
        UpdateLoadingPage("正在获取 CPU 架构……", "获取 CPU 架构")
        Dim Architecture As String = GetType(String).Assembly.GetName().ProcessorArchitecture
        Select Case Architecture
            Case Reflection.ProcessorArchitecture.X86
                Architecture = "i686"
            Case Reflection.ProcessorArchitecture.Amd64
                Architecture = "x86_64"
            Case Reflection.ProcessorArchitecture.Arm
                Architecture = "arm64"
            Case Else
                Log($"[Link] CPU 是不支持的 {Architecture} 架构，这可能会导致联机模块无法启动！", LogLevel.Debug)
                Architecture = "arm64"
        End Select
        Log("[Link] CPU 架构：" & Architecture)
        Telemetry("联机开始")
        '检查 EasyTier 版本
        UpdateLoadingPage("正在检查联机模块版本……", "检查联机模块版本")
        If Not (File.Exists(PathEasyTier & "联机模块 CLI.exe") AndAlso File.Exists(PathEasyTier & "联机模块.exe") AndAlso
                File.Exists(PathEasyTier & "Packet.dll")) Then
            Setup.Set("LinkEasyTierVersion", -1)
        End If
        Dim LocalVersion As Integer = Setup.Get("LinkEasyTierVersion")
        ServerVersion = ServerConfig("Link")("EasyTierVersion")
        Dim RequiredFiles As New List(Of NetFile)
        Log($"[Link] EasyTier 本地版本：{LocalVersion}，需求版本：{ServerVersion}")
        If LocalVersion < ServerVersion Then
            RequiredFiles.Add(New NetFile(
                ServerConfig("Link")("Downloads").Select(Function(UrlEntry) UrlEntry.ToString.Replace("{arch}", Architecture)),
                PathEasyTier & "EasyTier.zip",
                New FileChecker(MinSize:=1024 * 1024 * 2)))
        End If
        '开始下载
        UpdateLoadingPage("正在下载联机模块……", "下载联机模块")
        Task.Output = RequiredFiles
    End Sub

    '3. 启动联机模块
    Private Shared HostName As String
    Private Sub InitLaunch(Task As LoaderTask(Of Integer, Integer))
        '解压文件
        UpdateLoadingPage("正在解压联机模块……", "解压联机模块")
        If File.Exists(PathEasyTier & "EasyTier.zip") Then
            '解压
            Dim ExtractPath As String = RequestTaskTempFolder()
            ExtractFile(PathEasyTier & "EasyTier.zip", ExtractPath,
                ProgressIncrementHandler:=Sub(Progress) Task.Progress += Progress * 0.06)
            Dim ExtractedPath As String = New DirectoryInfo(ExtractPath).EnumerateDirectories.FirstOrDefault?.FullName
            Log("[Link] 联机模块解压时的临时路径：" & ExtractedPath)
            CopyDirectory(ExtractedPath, PathEasyTier)
            '重命名
            File.Delete(PathEasyTier & "联机模块.exe")
            Rename(PathEasyTier & "easytier-core.exe", PathEasyTier & "联机模块.exe")
            File.Delete(PathEasyTier & "联机模块 CLI.exe")
            Rename(PathEasyTier & "easytier-cli.exe", PathEasyTier & "联机模块 CLI.exe")
            '清理
            File.Delete(PathEasyTier & "EasyTier.zip")
            Setup.Set("LinkEasyTierVersion", ServerVersion)
        End If
        Task.Progress = 0.1
        '获取启动参数
        UpdateLoadingPage("正在启动联机模块……", "启动联机模块")
        Dim Arguments As String = ServerConfig("Link")("Argument")
        Arguments += $" --network-name={NetworkName} --network-secret={NetworkSecret}"
        HostName = If(IsServerSide, "Server-", "Client-") & RadixConvert(Math.Abs(Identify.GetHashCode), 10, 36)
        If IsServerSide Then
            Arguments += $" -i 10.114.114.114 --hostname={HostName} --tcp-whitelist={ServerPort} --udp-whitelist={ServerPort}"
        Else
            Arguments += $" -d --hostname={HostName} --tcp-whitelist=0 --udp-whitelist=0"
            '端口转发
            Dim Port As Integer = GetAvailablePort()
            ClientAddress = $"localhost:{Port}"
            Arguments += $" --port-forward tcp://[{IPAddress.IPv6Loopback}]:{Port}/10.114.114.114:{ServerPort}"
            Arguments += $" --port-forward udp://[{IPAddress.IPv6Loopback}]:{Port}/10.114.114.114:{ServerPort}"
            Arguments += $" --port-forward tcp://{IPAddress.Loopback}:{Port}/10.114.114.114:{ServerPort}"
            Arguments += $" --port-forward udp://{IPAddress.Loopback}:{Port}/10.114.114.114:{ServerPort}"
        End If
        For Each Peer As String In ServerConfig("Link")("Peers")
            Arguments += $" -p=""{Peer}"""
        Next
        If Not Setup.Get("LinkShareMode") Then Arguments += " --private-mode true"
        '启动进程
        ProcessStart(Arguments)
        Task.Progress = 0.15
        '等待连接
        Dim TimeoutCounter As Integer = 0
        Do
            Thread.Sleep(500) '为避免还没启动好先跑 CLI 了，先等半秒
            '刷新信息
            CheckCrash()
            RefreshPeerLoader.WaitForExit(IsForceRestart:=True)
            '查找目标节点
            Dim Ping = GetPeerPing()
            If Ping <> 0 Then
                Log($"[Link] 已与目标建立连接，当前 Ping 为 {Ping:0.0}ms")
                Telemetry("联机成功", "Server", IsServerSide, "Ping", Ping)
                Exit Do '退出循环
            End If
            '更新进度
            Dim LastProgress = Task.Progress
            Dim PeerCount As Integer = If(Peers Is Nothing, -1, Peers.Count)
            Select Case PeerCount
                Case -1 'CLI 无返回
                    Task.Progress = MathClamp(Task.Progress + 0.02, 0.15, 0.25)
                Case 0 'CLI 有返回，但未连接到任何节点
                    UpdateLoadingPage("正在连接到节点……", "连接节点")
                    Task.Progress = MathClamp(Task.Progress + 0.02, If(IsServerSide, 0.5, 0.3), If(IsServerSide, 0.99, 0.5))
                Case Else '已连接到节点，但未连接到房主
                    UpdateLoadingPage("正在连接到房主……", "连接房主")
                    Task.Progress = MathClamp(Task.Progress + 0.02, Math.Min(0.45 + PeerCount * 0.05, 0.65), 0.99)
            End Select
            '超时判定
            If LastProgress <> Task.Progress Then
                TimeoutCounter = 0
            ElseIf TimeoutCounter < 20 Then
                TimeoutCounter += 1
            Else '进度停滞超过 10s
                Select Case PeerCount
                    Case -1 'CLI 无返回
                        Panic("无法启动联机模块", "近期日志：" & vbCrLf & LogHistory.Join(vbCrLf))
                    Case 0 'CLI 有返回，但未连接到任何节点
                        Panic("无法连接到节点", $"请检查你的网络环境是否良好。")
                    Case Else '已连接到节点，但未连接到房主
                        Panic("无法连接到房主", $"可能的原因：{vbCrLf}- 你或者房主的网络环境不佳{vbCrLf}- 房主已关闭房间{vbCrLf}- 邀请码输错了")
                End Select
            End If
        Loop Until Task.IsAborted
        If Task.IsAborted Then Throw New ThreadInterruptedException
    End Sub

#End Region

#Region "进程与日志"

    ''' <summary>
    ''' EasyTier Core 进程。
    ''' </summary>
    Private Shared ProcessCore As Process
    Private Shared ProcessOutputHandle As AutoResetEvent, ProcessErrorHandle As AutoResetEvent

    ''' <summary>
    ''' 若程序正在运行，则结束程序进程。
    ''' 即使失败也不会抛出异常。
    ''' </summary>
    Public Shared Sub ProcessStop()
        Try
            '关闭未捕获的进程
            For Each ProcessObject In Process.GetProcesses
                If ProcessObject.Id = ProcessCore?.Id Then Continue For
                If ProcessObject.ProcessName <> "联机模块" AndAlso ProcessObject.ProcessName <> "联机模块 CLI" Then Continue For
                Try
                    Log("[Link] 停止残留的联机模块，PID：" & ProcessObject.Id & "，进程名：" & ProcessObject.ProcessName)
                    ProcessObject.Kill()
                    ProcessObject.Close()
                Catch exx As Exception
                    Log(exx, $"结束进程失败（{ProcessObject.ProcessName}，PID {ProcessObject.Id}）")
                End Try
            Next
            '关闭由自身启动的进程
            If ProcessCore IsNot Nothing AndAlso Not ProcessCore.HasExited Then
                Log("[Link] 停止所启动的联机模块，PID：" & ProcessCore.Id)
                ProcessCore.Kill()
                ProcessCore.Close()
                ProcessCore = Nothing
            End If
            '释放资源
            ProcessOutputHandle?.Dispose()
            ProcessErrorHandle?.Dispose()
        Catch ex As Exception
            Log(ex, "停止联机模块失败")
        End Try
    End Sub
    ''' <summary>
    ''' 出现意外错误，给出错误信息并结束联机。
    ''' </summary>
    Private Sub Panic(Brief As String, Detail As String)
        If State = States.Loading Then
            FailReason = Brief
            LinkLoader.Failed(New Exception(Detail))
        Else
            MyMsgBox(Detail, "联机出错：" & Brief, IsWarn:=True)
            ChangeState(States.Waiting)
            Telemetry("联机失败", "Exception", FilterUserName(Brief & "：" & Detail, "*"))
        End If
        '收集到的 CLI 错误：

        'Error: Timeout : deadline has elapsed
        'Caused by
        '    deadline has elapsed

        'Error: failed to get peer manager client
        'Caused by
        '    0:  rust tun error failed to connect to server: Url {scheme:  "tcp", cannot_be_a_base: false, username: "", password: None, host: Some(Domain("127.0.0.1")), port: Some(15888), path: "", query: None, fragment: None }
        '    1:  failed to connect to server: Url {scheme:  "tcp", cannot_be_a_base: false, username: "", password: None, host: Some(Domain("127.0.0.1")), port: Some(15888), path: "", query: None, fragment: None }
        '    2:  IO error
        '    3:  由于目标计算机积极拒绝， 无法连接。 (os error 10061)
    End Sub

    ''' <summary>
    ''' 启动进程。
    ''' </summary>
    Private Sub ProcessStart(Arguments As String)
        Dim Info = New ProcessStartInfo With {
            .FileName = PathEasyTier & "联机模块.exe",
            .Arguments = Arguments,
            .UseShellExecute = False,
            .CreateNoWindow = True,
            .RedirectStandardError = True,
            .RedirectStandardOutput = True,
            .StandardOutputEncoding = Encoding.UTF8,
            .StandardErrorEncoding = Encoding.UTF8
        }
        Log("[Link] 正在启动 EasyTier：" & Arguments)
        ProcessCore = New Process With {.StartInfo = Info}
        Dim LogLineHandler =
        Function(sender As Object, e As DataReceivedEventArgs, Handle As AutoResetEvent)
            Try
                If e.Data Is Nothing Then
                    Handle.[Set]()
                    Return Nothing
                End If
                ProcessLogLine(e.Data)
            Catch unused As ObjectDisposedException
            Catch ex As Exception
                Log(ex, "读取 EasyTier 信息失败")
            End Try
            Return Nothing
        End Function
        ProcessOutputHandle = New AutoResetEvent(False)
        AddHandler ProcessCore.OutputDataReceived, Function(sender, e) LogLineHandler(sender, e, ProcessOutputHandle)
        ProcessErrorHandle = New AutoResetEvent(False)
        AddHandler ProcessCore.ErrorDataReceived, Function(sender, e) LogLineHandler(sender, e, ProcessErrorHandle)
        ProcessCore.Start()
        ProcessCore.BeginOutputReadLine()
        ProcessCore.BeginErrorReadLine()
    End Sub
    Private Sub ProcessLogLine(Line As String)
        '记录日志
        Log("[EasyTier] " & Line)
        LogHistory.Enqueue(Line)
        If LogHistory.Count >= 10 Then LogHistory.Dequeue()
        '检查日志内容
        If Line.ContainsF("new peer connection added", True) Then
            Log("[Link] 已建立连接：" & If(RegexSeek(Line, "(?<=remote_addr.+?"")[^""}]{3,}"), Line), LogLevel.Debug)
            Update()
        ElseIf Line.ContainsF("peer connection removed", True) Then
            Log("[Link] 已断开连接：" & If(RegexSeek(Line, "(?<=remote_addr.+?"")[^""}]{3,}"), Line), LogLevel.Debug)
            Update()
        End If
    End Sub
    Private LogHistory As New Queue(Of String)(10)

#End Region

#Region "CLI 节点信息获取"

    Private Class Peer
        ''' <summary>
        ''' 该节点的类型。
        ''' </summary>
        Public ReadOnly Type As Types
        Public Enum Types
            ''' <summary>
            ''' 客户端。
            ''' </summary>
            Client
            ''' <summary>
            ''' 服务器。
            ''' </summary>
            Server
            ''' <summary>
            ''' 公共节点。
            ''' </summary>
            Misc
            ''' <summary>
            ''' 自己，或者自己的重复（它可能返回多个自己）。
            ''' </summary>
            Self
        End Enum
        ''' <summary>
        ''' 与该节点的延迟 (ms)。
        ''' 若是自己则为 0。
        ''' </summary>
        Public ReadOnly Ping As Double
        ''' <summary>
        ''' 名称。
        ''' </summary>
        Public ReadOnly Name As String

        ''' <summary>
        ''' 从 CLI 给出的信息行分析对应的数据。
        ''' </summary>
        Public Sub New(Info As String)
            '具体每个部分的索引见 GetPeerData()
            Dim Parts = Info.Split("|").Select(Function(s) If(s.All(Function(c) c = " "c), s, s.Trim)).Where(Function(s) s <> "").ToList
            If Parts.Count <> 10 Then Throw New Exception($"信息列数有误")
            '延迟
            Ping = If(Parts(3) = "-", 0, Parts(3))
            '类别
            Dim PeerName = Parts(1)
            If PeerName = HostName Then
                Type = Types.Self
            ElseIf PeerName.StartsWithF("Client") Then
                Type = Types.Client
            ElseIf Parts(0).StartsWithF("10.114.114.114") Then '只允许这个 IP 作为房主，避免网络被多个房主搞炸的情况
                Type = Types.Server
            Else
                Type = Types.Misc
            End If
            '主机名
            Name = PeerName
        End Sub
        Public Overrides Function ToString() As String
            Return $"{Type} - {Name} - Ping {Ping:0.0}ms"
        End Function
    End Class

    ''' <summary>
    ''' 当前的节点列表，使用 RefreshPeerLoader 来刷新。
    ''' 若尚未成功获取过则为 Nothing，但保证在加载完成后至少是一个列表。
    ''' </summary>
    Private Peers As List(Of Peer) = Nothing

    ''' <summary>
    ''' 调用 EasyTier CLI 获取已连接节点信息。
    ''' 这会过滤掉尚未完成连接的其他节点以及自己。
    ''' 若在加载完成后连续获取失败 3 次，则会强制断开连接。
    ''' </summary>
    Private RefreshPeerLoader As New LoaderTask(Of Integer, List(Of Peer))("EasyTier CLI", AddressOf RefreshPeer)
    Private Sub RefreshPeer()
        '| ipv4              | hostname              | cost     | lat(ms) | loss | rx      | tx      | tunnel | NAT            | version        |
        '|-------------------|-----------------------|----------|---------|------|---------|---------|--------|----------------|----------------|
        '| 10.114.114.1/24   | Client-RJ458A         | Local    | -       | -    | -       | -       | -      | Unknown        | 2.4.5-4c4d172e |
        '|                   | PublicServer_公用服务器  | p2p      | 48.40   | 0.0% | 875 B   | 1.26 kB | tcp    | NoPat          | 2.4.5-4c4d172e |
        '| 10.114.114.114/24 | Server-J6P6IW         | p2p      | 5.63    | 0.0% | 1.65 kB | 1.64 kB | udp    | PortRestricted | 2.4.5-4c4d172e |
        '| 10.114.114.114/24 | Server-J6PHIW (连接中) | relay(2) | 1000.00 | 0.0% | 0 B     | 0 B     |        | PortRestricted | 2.4.5-4c4d172e |
        Try
            Dim CliResult = StartProcessAndGetOutput(PathEasyTier & "联机模块 CLI.exe", "peer", 2000, Encoding:=Encoding.UTF8, PrintLog:=False)
            '解析
            If Not CliResult.Contains("lat(ms)") Then Throw New Exception("CLI 调用失败：" & vbCrLf & CliResult)
            If GetUuid() Mod If(ModeDebug, 4, 30) = 0 Then Log("[EasyTier] CLI 输出抽样：" & vbCrLf & CliResult)
            Dim NewPeers As New List(Of Peer)
            For Each Line In CliResult.Split(vbCrLf.ToCharArray, StringSplitOptions.RemoveEmptyEntries).Skip(2)
                Try
                    Dim Peer = New Peer(Line)
                    If Peer.Type = Peer.Types.Self Then Continue For '自己
                    NewPeers.Add(Peer)
                Catch exx As Exception
                    Log(exx, $"错误的信息行（{Line}）")
                End Try
            Next
            '完成
            Peers = NewPeers
            FailCount = 0
        Catch ex As Exception
            Log(ex, "获取节点信息失败")
            If State = States.Finished Then
                FailCount += 1
                If FailCount >= 4 Then Panic("获取节点信息失败", ex.Message)
            End If
        End Try
    End Sub
    ''' <summary>
    ''' CLI 调用连续失败的次数。
    ''' </summary>
    Private FailCount As Integer = 0

    ''' <summary>
    ''' 根据当前的节点列表获取 Ping 值。
    ''' 服务端会返回所有节点中最低的 Ping，客户端会返回服务端的 Ping。
    ''' 0 代表尚不可用。
    ''' </summary>
    Private Function GetPeerPing() As Double
        If Peers Is Nothing Then Return 0
        Dim PingTargets As IEnumerable(Of Peer)
        If IsServerSide Then
            PingTargets = Peers
        Else
            PingTargets = Peers.Where(Function(p) p.Type = Peer.Types.Server)
        End If
        If Not PingTargets.Any Then
            Return 0
        Else
            Return Math.Max(1, PingTargets.Select(Function(p) p.Ping).Min())
        End If
    End Function

    ''' <summary>
    ''' 获取当前房间中的人数，包括自己。
    ''' 0 代表不可用。
    ''' </summary>
    Private ReadOnly Property PeopleCount As Integer
        Get
            If Peers Is Nothing Then Return 0
            Return Peers.Where(Function(p) p.Type <> Peer.Types.Misc).Count() + 1 '加上自己
        End Get
    End Property

#End Region

#Region "定时状态更新"

    '启动
    Private IsTimerStarted As Boolean = False
    Private Sub StartTimerThread() Handles Me.Loaded
        If IsTimerStarted Then Return
        RunInNewThread(
        Sub()
            Dim Counter As Integer = 0
            Do While True
                Try
                    Thread.Sleep(200)
                    Counter += 200
                    '每 4 秒执行一次
                    If Counter >= 4000 Then
                        Counter = 0
                        Update()
                    End If
                    '每 200ms 更新进度条
                    If State = States.Loading Then RunInUi(AddressOf UpdateProgressBar)
                Catch ex As Exception
                    Log(ex, "联机模块主时钟出错", LogLevel.Feedback)
                    Thread.Sleep(10000)
                End Try
            Loop
        End Sub, "Link Timer")
    End Sub

    '每 4 秒或进入页面时更新一次信息
    Private Sub Update() Handles Me.Loaded
        If State <> States.Finished Then Return
        '重新获取信息
        SyncLock RefreshPeerLoader.LockState
            If RefreshPeerLoader.State <> LoadState.Loading Then RefreshPeerLoader.Start(IsForceRestart:=True)
        End SyncLock
        '更新 Ping 与人数显示
        If FrmMain.PageCurrent = FormMain.PageType.Link Then
            RunInUi(
            Sub()
                Dim Ping As Double = GetPeerPing()
                If Ping Mod 500 = 0 OrElse $"{Ping:0.0}" = "1.0" OrElse FailCount > 0 Then
                    LabFinishPing.Text = "连接中"
                    AniStop("Link Logo Rotation")
                Else
                    LabFinishPing.Text = If(Ping >= 10, $"{Ping:0} ms", $"{Ping:0.0} ms")
                    AniStart(AaRotateTransform(ImgFinishLogo, 500, 5000), "Link Logo Rotation") 'Logo 旋转动画
                End If
                LabFinishPlayer.Text = PeopleCount & "  人"
            End Sub)
        End If
        '检查核心状态
        CheckCrash()
        '检查节点状态
        If Not Peers.Any Then
            Panic("网络连接已断开", "请检查你的网络环境是否正常。")
            Return
        End If
        If Not IsServerSide AndAlso Not Peers.Any(Function(p) p.Type = Peer.Types.Server) Then
            MyMsgBox("房主已离开房间！", "联机结束")
            ChangeState(States.Waiting)
            Return
        End If
    End Sub
    ''' <summary>
    ''' 检查联机模块是否崩溃。
    ''' </summary>
    Private Sub CheckCrash()
        If ProcessCore IsNot Nothing AndAlso Not ProcessCore.HasExited Then Return
        Panic("联机模块已崩溃", "近期日志：" & vbCrLf & LogHistory.Join(vbCrLf))
    End Sub

#End Region

End Class
