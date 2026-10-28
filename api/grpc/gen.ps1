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

    # The anx management API is a copy of the closed anx repository's
    # boundary (contracts/anx): it has no go_package, so the import path is
    # given here.
    $AnxMgmt = "anx/mgmt/v1/mgmt.proto"
    $AnxMgmtPackage = "$ModulePath/api/anxmgmt/v1;anxmgmtpb"
    protoc `
        -I contracts/anx/proto `
        --go_out=. `
        "--go_opt=module=$ModulePath" `
        "--go_opt=M$AnxMgmt=$AnxMgmtPackage" `
        --go-grpc_out=. `
        "--go-grpc_opt=module=$ModulePath" `
        "--go-grpc_opt=M$AnxMgmt=$AnxMgmtPackage" `
        "contracts/anx/proto/$AnxMgmt"

    Write-Host "Generated legacy gRPC bindings and the anx management client."
}
finally {
    Pop-Location
}
