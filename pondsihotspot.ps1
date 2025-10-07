# from > https://github.com/guguan123/guguan123.github.io/blob/main/tools/pondsihotspot.ps1
# author > guguan123@qq.com
# AC certificate for self-signing > https://guguan123.github.io/keys/PC2412-AC.cer

param(
    [switch]$Version,                   # �鿴�汾��Ϣ
    [switch]$Help,                      # ��ȡ����
    [switch]$Force,                     # ����Ȩ�޼��
    [switch]$CheckAdapterStatus,        # ���WiFi����״̬
    [switch]$CheckHotspotStatus,        # �鿴WiFi�ȵ�״̬
    [switch]$EnableHotspot,             # �����ȵ�Ŀ���
    [switch]$DisableHotspot,            # �����ȵ�Ŀ���
    [switch]$EnableAdapter,             # �������������������Ŀ���
    [switch]$DisableAdapter             # �������������������Ŀ���
)


# ����ʾ����
# -EnableHotspot: ֱ�ӿ���WiFi�ȵ㡣
# -DisableHotspot: ֱ�ӹر�WiFi�ȵ㡣
# -EnableAdapter: ֱ����������������������
# -DisableAdapter: ֱ�ӽ�������������������
# -Force: ���Թ���ԱȨ�޼�����нű���
# -help: ��ȡ����
# -CheckAdapterStatus: ���WiFi����״̬
# -CheckHotspotStatus: �鿴WiFi�ȵ�״̬
# -Version: �鿴�汾��Ϣ
# ���������������Զ���/���ȵ�
#
# tip: Start-Process ms-settings:network-mobilehotspot  # ���ȵ����ã�Windows���ó���


# ��鵱ǰ����ϵͳ��Ϣ
if ([System.Environment]::OSVersion.Platform -eq 'Win32NT') {
    # ���� Windows 10 ����Ͱ汾
    $win10Version = New-Object System.Version "10.0"
    # �Աȵ�ǰ����ϵͳ�汾��Ϣ�Ƿ����10
    if ([System.Environment]::OSVersion.Version -lt $win10Version) {
        Write-Warning "System versions lower than Windows 10!"
    }
} else {
    Write-Warning "This system is not running Windows."
    if (!$Force) {
        Exit 1
    }
}
# ��ȡ��ǰPowerShell�汾��Ϣ���ݲ���Ҫ��
#$psMajorVersion = $PSVersionTable.PSVersion.Major
#if ($psMajorVersion -lt 7) {
#    Write-Warning "PowerShell version is $($PSVersionTable.PSVersion). You are using a version lower than PowerShell 7!"
#}


# ������ԱȨ��
function Test-AdministratorRights {
    # ����Ƿ��й���ԱȨ��
    if (!$Force) {
        # ��ȡ��ǰ�û��� Windows �����֤
        $WindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        # ���� Windows �����֤�� WindowsPrincipal ����
        $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($WindowsIdentity)
        # ����û��Ƿ����ڹ���Ա��
        $IsAdmin = $WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } else { # ������� -Force ���ؾ�ǿ����Ϊ�й���ԱȨ��
        $IsAdmin = $true
    }
    return $IsAdmin
}
$IsAdmin = Test-AdministratorRights   # ��ǰ�Ƿ��Թ���Ա�ķ�ʽ����

# �ȴ��첽������ɵĺ���
Function Await($WinRtTask, $ResultType) { 
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType) 
    $netTask = $asTask.Invoke($null, @($WinRtTask)) 
    $netTask.Wait(-1) | Out-Null 
    $netTask.Result 
} 

# �ȴ��첽������ɵĺ��������û�з��ؽ���Ĳ�����
Function AwaitAction($WinRtAction) { 
    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0] 
    $netTask = $asTask.Invoke($null, @($WinRtAction)) 
    $netTask.Wait(-1) | Out-Null 
}

# ���WiFi����״̬���ù���δ���ƣ���
function Get-WifiAdapterStatus {
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wireless*' }
    if ($wifiAdapters.Count -gt 0) {
        $wifiAdapters
    } else {
        Write-Output "No wireless network adapter found."
    }
}
# ���WiFi����״̬���Ľ��󣺷��������������б�֧�ֶ����
function Get-WifiAdapterStatus {
    # �������������а��� 'Wireless' ������������
    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like '*Wireless*' }
    
    if ($wifiAdapters.Count -gt 0) {
        # ���������������б�
        return $wifiAdapters
    } else {
        # ���û���ҵ������������� $null
        return $null
    }
}

# ���û���� WiFi �������ĺ������Ľ��󣺴��������ҵ��� WiFi ��������
Function EnableDisableWiFiAdapter($enable) {
    try {
        $wifiAdapters = Get-WifiAdapterStatus  # ��ȡ������������������
        
        if ($null -ne $wifiAdapters) {
            foreach ($adapter in $wifiAdapters) {
                if ($enable) {
                    Write-Output "Enabling wireless adapter: $($adapter.Name)"
                    Enable-NetAdapter -Name $adapter.Name -Confirm:$false  # ����������
                } else {
                    Write-Output "Disabling wireless adapter: $($adapter.Name)"
                    Disable-NetAdapter -Name $adapter.Name -Confirm:$false  # ����������
                }
            }
            Write-Output "Operation completed for all wireless adapters."
        } else {
            Write-Output "Wireless adapter not found."  # ���δ�ҵ�����������ʾ��Ϣ���˳�
        }
    } catch {
        Write-Error "An error occurred while trying to enable/disable the wireless adapter: $_"  # �����쳣���
    }
}

# ���û�����ȵ�ĺ���
Function ManageHotspot($enable) {
    try {
        if ($enable) { 
            Await ($tetheringManager.StartTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])  # �����ȵ�
            Write-Output "Network sharing has been enabled."  # ��ʾ��Ϣ
        } else { 
            Await ($tetheringManager.StopTetheringAsync()) ([Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult])  # �ر��ȵ�
            Write-Output "Network sharing has been disabled."  # ��ʾ��Ϣ
        }
    } catch {
        Write-Output "An error occurred: $_"  # �����쳣���
    }
}

# ��Ҫ Windows Runtime API �Ĳ���������Ƿ����
if ($EnableHotspot -or $DisableHotspot -or ($PSBoundParameters.Count -eq 0 -and [string]::IsNullOrWhiteSpace($args))) {
    # ��� Windows Runtime API �Ƿ����
    $apiAvailable = $true
    try {
        if ($IsAdmin) {
            Add-Type -AssemblyName System.Runtime.WindowsRuntime  # ���� Windows Runtime ����
            # ��ȡ AsTask ����
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        }
        $connectionProfile = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()  # ��ȡ�������������ļ�
        if ($null -eq $connectionProfile) { 
            throw "No internet connection profile found. Please check your network connection."
        }
        $tetheringManager = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($connectionProfile)  # ���������ȵ������
    } catch {
        $apiAvailable = $false
        Write-Warning "Windows Runtime API for networking is not available: $_"
    }
}

# ���������в�����ִ����Ӧ����
if ($args.Count -gt 0) { # --- ����Ƿ���δ�����λ�ò�����δ֪ѡ� ---
    $scriptFileName = Split-Path -Path $MyInvocation.MyCommand.Name -Leaf
    # ����δ֪�ģ�λ�ã�����
    Write-Output "$($scriptFileName): unknown option(s) provided: $($args -join ', ')"
    Exit 1
} if ($Version) {
    Write-Output "pondsihotspot.ps1 v0.5"
    Write-Output "Last changed on 2025-10-07"
} if ($Help) {
    # ʹ��$MyInvocation.MyCommand.Name��ȡ��ǰ�ű��ļ�������·����ʹ��Split-Path��ȡ�ļ�������
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

} if ($CheckAdapterStatus) {
    $status = Get-WifiAdapterStatus
    if ($null -ne $status) {
        Write-Output "--- Wireless Adapter Status ---"
        $status | Select-Object Name, InterfaceDescription, Status, State, LinkSpeed | Format-Table -AutoSize
    } else {
        Write-Output "No wireless network adapter found."
    }

} if ($EnableAdapter) {
    if ($IsAdmin) {
        EnableDisableWiFiAdapter $true
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }

} if ($DisableAdapter) {
    if ($IsAdmin) {
        EnableDisableWiFiAdapter $false
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }

} if ($CheckHotspotStatus) { 
    if ($apiAvailable) {
        Write-Output "--- Hotspot Status ---"
        $tetheringManager.TetheringOperationalState | Format-List  # ���� Format-Table��ȡ��������Ҫ�������ʽ
    } else {
        Write-Error "Cannot check hotspot status due to unavailable API."
    }
} if ($EnableHotspot) {
    if ($IsAdmin) {
        if ($EnableAdapter) {
            Start-Sleep -Seconds 5  # �����������"-EnableAdapter"���ؾ͵ȴ�5������ȷ������������
        }
        if ($apiAvailable) {
            ManageHotspot $true
        } else {
            Write-Error "Cannot enable hotspot due to unavailable API."
            Exit 1
        }
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }

} if ($DisableHotspot) {
    if ($IsAdmin) {
        if ($apiAvailable) {
            ManageHotspot $false
        } else {
            Write-Error "Cannot disable hotspot due to unavailable API."
            Exit 1
        }
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }

# $PSBoundParameters ���������Ѱ󶨵����������Ĺ�ϣ��
} if ($PSBoundParameters.Count -eq 0 -and [string]::IsNullOrWhiteSpace($args)) {
    if ($IsAdmin) {
        # ���û�и���ֱ�ӵ��������ݵ�ǰ״ִ̬��Ĭ�ϲ���
        if ($apiAvailable) {
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
            Write-Warning "Cannot toggle hotspot due to unavailable API."
        }
    } else {
        Write-Error "The script requires administrator privileges to run!"
        Exit 1
    }
}
