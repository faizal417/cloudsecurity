$tenantId = "<your-tenant-id>"
$appId = "<your-client-id>"
$secret = "<your-client-secret>"

$body = @{
    client_id     = $appId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $secret
    grant_type    = "client_credentials"
}

$tokenResponse = Invoke-RestMethod -Method Post `
  -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
  -Body $body
