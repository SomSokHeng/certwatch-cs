# vso-certwatch

TLS certificate expiry and validity monitor in C#. Exit code 1 if any host is not OK, so it drops into cron or CI.

    dotnet build -c Release
    dotnet run -c Release -- example.com,github.com --warn 30 --json
    dotnet run -c Release -- @hosts.txt --port 8443

Status: OK, WARN (within --warn days), EXPIRED, INVALID (chain/name error), ERR.
