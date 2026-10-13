param()

$ErrorActionPreference = "Stop"
$ModulePath = "github.com/AnixOps/anix-agent/v5"
$ProtoFiles = @(
    "api/grpc/v2board.proto"
)

foreach ($CommandName in @("protoc", "protoc-gen-go", "protoc-gen-go-grpc")) {
    if (-not (Get-Command $CommandName -ErrorAction SilentlyContinue)) {
        throw "$CommandName not found"
    }
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Push-Location $RepoRoot
try {
    protoc `
        --go_out=. `
        "--go_opt=module=$ModulePath" `
        --go-grpc_out=. `
        "--go-grpc_opt=module=$ModulePath" `
        $ProtoFiles

    Write-Host "Generated legacy gRPC bindings."
}
finally {
    Pop-Location
}
