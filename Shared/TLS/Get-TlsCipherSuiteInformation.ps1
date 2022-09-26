# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

. $PSScriptRoot\..\Get-RemoteRegistryValue.ps1
function Get-TlsCipherSuiteInformation {
    [OutputType("System.Object")]
    param(
        [string]$MachineName = $env:COMPUTERNAME,
        [scriptblock]$CatchActionFunction
    )

    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
    }
    process {
        try {
            # 'Get-TlsCipherSuite' takes account of the cipher suites which are configured by the help of GPO.
            # No need to query the ciphers defined via GPO if this call is successful.
            Write-Verbose "Trying to query TlsCipherSuites via 'Get-TlsCipherSuite'"
            $tlsCipherSuites = Get-TlsCipherSuite -ErrorAction Stop
        } catch {
            # If we can't get the ciphers via cmdlet, we need to query them via registry call and need to check
            # if ciphers suites are defined via GPO as well. If there are some, these take precedence over what
            # is in the default location.
            Write-Verbose "Failed to query TlsCipherSuites via 'Get-TlsCipherSuite' fallback to registry"

            if ($null -ne $CatchActionFunction) {
                & $CatchActionFunction
            }

            $policyTlsRegistryParams = @{
                MachineName         = $MachineName
                Subkey              = "SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
                GetValue            = "Functions"
                ValueType           = "String"
                CatchActionFunction = $CatchActionFunction
            }

            Write-Verbose "Trying to query cipher suites configured via GPO from registry"
            $policyDefinedCiphers = Get-RemoteRegistryValue @policyTlsRegistryParams

            if ($null -ne $policyDefinedCiphers) {
                Write-Verbose "Ciphers specified via GPO found - these take precedence over what is in the default location"
                $tlsCipherSuites = $policyDefinedCiphers.Split(",")
            } else {
                Write-Verbose "No cipher suites configured via GPO found - going to query the local TLS cipher suites"
                $tlsRegistryParams = @{
                    MachineName         = $MachineName
                    SubKey              = "SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"
                    GetValue            = "Functions"
                    ValueType           = "MultiString"
                    CatchActionFunction = $CatchActionFunction
                }

                $tlsCipherSuites = Get-RemoteRegistryValue @tlsRegistryParams
            }
        }
    }
    end {
        return $tlsCipherSuites
    }
}
