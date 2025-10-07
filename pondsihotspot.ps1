# from > https://github.com/guguan123/guguan123.github.io/blob/main/tools/pondsihotspot.ps1
# author > guguan123@qq.com
# AC certificate for self-signing > https://guguan123.github.io/keys/PC2412-AC.cer

param(
    [switch]$Version,                   # 查看版本信息
    [switch]$Help,                      # 获取帮助
    [switch]$Force,                     # 忽略权限检测
    [switch]$CheckAdapterStatus,        # 检查WiFi网卡状态
    [switch]$CheckHotspotStatus,        # 查看WiFi热点状态
    [switch]$EnableHotspot,             # 启用热点的开关
    [switch]$DisableHotspot,            # 禁用热点的开关
    [switch]$EnableAdapter,             # 启用无线网络适配器的开关
    [switch]$DisableAdapter             # 禁用无线网络适配器的开关
)


# 参数示例：
# -EnableHotspot: 直接开启WiFi热点。
# -DisableHotspot: 直接关闭WiFi热点。
# -EnableAdapter: 直接启用无线网络适配器。
# -DisableAdapter: 直接禁用无线网络适配器。
# -Force: 忽略管理员权限检测运行脚本。
# -help: 获取帮助
# -CheckAdapterStatus: 检查WiFi网卡状态
# -CheckHotspotStatus: 查看WiFi热点状态
# -Version: 查看版本信息
# 如果无输入参数则自动开/关热点
#
# tip: Start-Process ms-settings:network-mobilehotspot  # 打开热点设置（Windows设置程序）


# 检查当前操作系统信息
if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    # 定义 Windows 10 的最低版本
    $win10Version = New-Object System.Version "10.0"
    # 对比当前操作系统版本信息是否低于10
    if ([System.Environment]::OSVersion.Version -lt $win10Version) {
        Write-Warning "System versions lower than Windows 10!"
    }
} else {
    Write-Warning "This system is not running Windows."
    if (!$Force) {
        Exit 1
    }
}
# 获取当前PowerShell版本信息（暂不需要）
#$psMajorVersion = $PSVersionTable.PSVersion.Major
#if ($psMajorVersion -lt 7) {
#    Write-Warning "PowerShell version is $($PSVersionTable.PSVersion). You are using a version lower than PowerShell 7!"
#}


# 检查管理员权限
function Test-AdministratorRights {
    # 检查是否有管理员权限
    if (!$Force) {
        # 获取当前用户的 Windows 身份验证
        $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        # 创建 Windows 身份验证的 WindowsPrincipal 对象
        $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($WindowsIdentity)
        # 检查用户是否属于管理员组
        $IsAdmin = $WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } else { # 如果输入 -Force 开关就强制认为有管理员权限
        $IsAdmin = $true
    }
    return $IsAdmin
}

# 等待异步操作完成的函数
Function Await($WinRtTask, $ResultType) { 
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType) 
    $netTask = $asTask.Invoke($null, @($WinRtTask)) 
    $netTask.Wait(-1) | Out-Null 
    $netTask.Result 
} 

# 等待异步操作完成的函数（针对没有返回结果的操作）
Function AwaitAction($WinRtAction) { 
    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0] 
    $netTask = $asTask.Invoke($null, @($WinRtAction)) 
    $netTask.Wait(-1) | Out-Null 
}

# 检查WiFi网卡状态（该功能未完善！）
function Get-WifiAdapterStatus {
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wireless*' }
    if ($wifiAdapters.Count -gt 0) {
        $wifiAdapters
    } else {
        Write-Output "No wireless network adapter found."
    }
}

# 查看WiFi热点状态（该功能未完善！）
function Get-WiFiHotspotStatus {
    if (!$tetheringManager.TetheringOperationalState) {
        if ($tetheringManager.TetheringOperationalState -eq 1) {
            $tetheringConfiguration = $tetheringManager.GetCurrentTetheringConfiguration()
            $passphrase = "Not accessible through API" # Windows API does not expose the hotspot password for security reasons
            Write-Output "Hotspot Status: On, SSID: $($tetheringConfiguration.SSID), Password: $($passphrase)"
        } else {
            Write-Output "Hotspot Status: Off"
        }
    }
}

# 启用或禁用 WiFi 适配器的函数
Function EnableDisableWiFiAdapter($enable) {
    try {
        $wifiAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wireless*' }  # 获取无线网络适配器
        if ($wifiAdapter) {
            if ($enable) {
                Enable-NetAdapter -Name $wifiAdapter.Name -Confirm:$false  # 启用适配器
            } else {
                Disable-NetAdapter -Name $wifiAdapter.Name -Confirm:$false  # 禁用适配器
            }
        } else {
            Write-Output "Wireless adapter not found."  # 如果未找到适配器则显示消息并退出
            exit
        }
    } catch {
        Write-Error "An error occurred while trying to enable/disable the wireless adapter: $_"  # 处理异常情况
        exit
    }
}

# 启用或禁用热点的函数
Function ManageHotspot($enable) {
    try {
        if ($enable) { 
            Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])  # 开启热点
            Write-Output "Network sharing has been enabled."  # 显示消息
        } else { 
            Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])  # 关闭热点
            Write-Output "Network sharing has been disabled."  # 显示消息
        }
    } catch {
        Write-Output "An error occurred: $_"  # 处理异常情况
    }
}

# 设置全局变量
$IsAdmin = Test-AdministratorRights   # 当前是否以管理员的方式运行
if ($IsAdmin) {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime  # 加载 Windows Runtime 程序集
    # 获取 AsTask 方法
    $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
}
$connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()  # 获取网络连接配置文件
if ($null -eq $connectionProfile) {Write-Warning "No internet connection profile found. Please check your network connection."} # 如果找不到连接配置文件，则显示消息并退出
$tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)  # 创建网络热点管理器

# 解析命令行参数并执行相应操作
# 检查参数是否包含帮助开关
if ($Version) {
    Write-Output "pondsihotspot.ps1 v0.4"
    Write-Output "Last changed on 2022-4-12"
}
elseif ($Help) {
    # 使用$MyInvocation.MyCommand.Name获取当前脚本文件的完整路径；使用Split-Path获取文件名部分
    $scriptFileName = Split-Path -Path $MyInvocation.MyCommand.Name -Leaf
    # Output help information
    Write-Output "Usage: $($scriptFileName) [options]"
    Write-Output ""
    Write-Output "-EnableHotspot"
    Write-Output "    Directly enables WiFi hotspot."
    Write-Output ""
    Write-Output "-DisableHotspot"
    Write-Output "    Directly disables WiFi hotspot."
    Write-Output ""
    Write-Output "-EnableAdapter"
    Write-Output "    Directly enables the wireless network adapter."
    Write-Output ""
    Write-Output "-DisableAdapter"
    Write-Output "    Directly disables the wireless network adapter."
    Write-Output ""
    Write-Output "-Force"
    Write-Output "    Runs the script ignoring administrator privileges."
    Write-Output ""
    Write-Output "$($scriptFileName) -Help"
    Write-Output ""
    Write-Output "-Version"
    Write-Output "    Displays the version of $($scriptFileName). Additional parameters are ignored."
    Write-Output ""
    Write-Output "If no input parameters are provided, it automatically toggles the hotspot."
}
elseif ($CheckAdapterStatus) {Get-WifiAdapterStatus}
elseif ($CheckHotspotStatus) {Get-WiFiHotspotStatus}
elseif ($EnableAdapter) {
    if ($IsAdmin) {
        EnableDisableWiFiAdapter $true
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
elseif ($EnableHotspot) {
    if ($IsAdmin) {
        if ($EnableAdapter) {
            Start-Sleep -Seconds 5  # 如果还附带有"-EnableAdapter"开关就等待5秒钟以确保适配器启用
        }
        ManageHotspot $true
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
elseif ($DisableHotspot) {
    if ($IsAdmin) {
        ManageHotspot $false
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
elseif ($DisableAdapter) {
    if ($IsAdmin) {
        EnableDisableWiFiAdapter $false
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
elseif (-not $args) {
    if ($IsAdmin) {
        # 如果没有给出直接的命令，则根据当前状态执行默认操作
        try {
            if ($tetheringManager.TetheringOperationalState -eq 1) { 
                ManageHotspot $false
            } else { 
                ManageHotspot $true
            }
        } catch {
            Write-Output "An error occurred: $_"
        }
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
elseif ($args) {
    $scriptFileName = Split-Path -Path $MyInvocation.MyCommand.Name -Leaf
    Write-Output "$($scriptFileName): unknown option $($args)"
    Exit 1
}
