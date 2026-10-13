#!/bin/bash
# AnixOps Agent Build Script for Linux/macOS
# Usage: ./build.sh [-p platform] [-a arch] [--all] [--clean]
#
# Release builds must be produced by GitHub Actions. This script is kept for
# development or emergency operator use only and requires ALLOW_LOCAL_BUILD=1
# for any build. --clean remains available for removing local build artifacts.

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# 设置必需的环境变量
export GOEXPERIMENT="jsonv2"
export CGO_ENABLED=0

# 项目信息
PROJECT_NAME="anix-agent"
OUTPUT_DIR="build"
VERSION=$(git describe --tags --always 2>/dev/null | sed 's/^v//' || echo "dev")
BUILD_TIME=$(date '+%Y-%m-%d %H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# LDFlags
LDFLAGS="-s -w -X 'github.com/AnixOps/anix-agent/v5/cmd.version=${VERSION}'"

# 默认值
PLATFORM=""
ARCH=""
TAGS="xray sing hy2"
BUILD_ALL=false
CLEAN=false

# 支持的平台
declare -a PLATFORMS=(
    "linux:amd64:"
    "linux:arm64:"
    "linux:386:"
    "windows:amd64:.exe"
    "windows:arm64:.exe"
    "darwin:amd64:"
    "darwin:arm64:"
)

# 打印帮助
print_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Release builds must be produced by GitHub Actions release workflows."
    echo "For development or emergency operator builds, set ALLOW_LOCAL_BUILD=1."
    echo ""
    echo "Options:"
    echo "  -p, --platform    Target platform (linux, windows, darwin)"
    echo "  -a, --arch        Target architecture (amd64, arm64, 386)"
    echo "  -t, --tags        Build tags (default: xray sing hy2)"
    echo "  --all             Build for all platforms"
    echo "  --clean           Clean build directory"
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                      # Build for current platform"
    echo "  $0 -p linux -a amd64    # Build for Linux amd64"
    echo "  $0 -t \"xray\"           # Build with only xray core"
    echo "  $0 --all                # Build for all platforms"
}

require_local_build_opt_in() {
    if [ "${ALLOW_LOCAL_BUILD:-}" = "1" ]; then
        return 0
    fi

    echo -e "${RED}!! build.sh performs a local source-tree build.${NC}" >&2
    echo -e "${RED}!! Release builds must be produced by GitHub Actions release workflows.${NC}" >&2
    echo -e "${RED}!! For development or emergency operator use, rerun with ALLOW_LOCAL_BUILD=1.${NC}" >&2
    return 1
}

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -t|--tags)
            TAGS="$2"
            shift 2
            ;;
        --all)
            BUILD_ALL=true
            shift
            ;;
        --clean)
            CLEAN=true
            shift
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            print_help
            exit 1
            ;;
    esac
done

# 清理
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$OUTPUT_DIR"
    echo -e "${GREEN}Clean completed.${NC}"
    exit 0
fi

require_local_build_opt_in || exit 1

# 创建输出目录
mkdir -p "$OUTPUT_DIR"

# 编译函数
build_binary() {
    local goos=$1
    local goarch=$2
    local ext=$3
    
    local output_name="${PROJECT_NAME}_${goos}_${goarch}${ext}"
    local output_path="${OUTPUT_DIR}/${output_name}"
    
    echo -e "${GREEN}Building ${output_name}...${NC}"
    
    GOOS=$goos GOARCH=$goarch go build \
        -trimpath \
        -tags "$TAGS" \
        -ldflags "$LDFLAGS" \
        -o "$output_path" \
        .
    
    if [ $? -eq 0 ]; then
        local size=$(ls -lh "$output_path" | awk '{print $5}')
        echo -e "${CYAN}  -> ${output_name} (${size})${NC}"
        return 0
    else
        echo -e "${RED}  -> Failed to build ${output_name}${NC}"
        return 1
    fi
}

# 打印头部信息
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  AnixOps Agent Build Script${NC}"
echo -e "${CYAN}========================================${NC}"
echo -e "${WHITE}Version:    ${VERSION}${NC}"
echo -e "${WHITE}Git Commit: ${GIT_COMMIT}${NC}"
echo -e "${WHITE}Build Time: ${BUILD_TIME}${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

START_TIME=$(date +%s)
SUCCESS_COUNT=0
FAIL_COUNT=0

if [ "$BUILD_ALL" = true ]; then
    # 编译所有平台
    echo -e "${YELLOW}Building for all platforms...${NC}"
    echo ""
    
    for platform_info in "${PLATFORMS[@]}"; do
        IFS=':' read -r goos goarch ext <<< "$platform_info"
        if build_binary "$goos" "$goarch" "$ext"; then
            ((SUCCESS_COUNT++))
        else
            ((FAIL_COUNT++))
        fi
    done
else
    # 使用指定平台或检测当前平台
    if [ -z "$PLATFORM" ]; then
        PLATFORM=$(go env GOOS)
    fi
    if [ -z "$ARCH" ]; then
        ARCH=$(go env GOARCH)
    fi
    
    # 确定扩展名
    EXT=""
    if [ "$PLATFORM" = "windows" ]; then
        EXT=".exe"
    fi
    
    if build_binary "$PLATFORM" "$ARCH" "$EXT"; then
        ((SUCCESS_COUNT++))
    else
        ((FAIL_COUNT++))
    fi
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${GREEN}Build completed in ${DURATION} seconds${NC}"
echo -e "${GREEN}Success: ${SUCCESS_COUNT}, Failed: ${FAIL_COUNT}${NC}"
echo -e "${CYAN}========================================${NC}"

# 列出生成的文件
if [ -d "$OUTPUT_DIR" ] && [ "$(ls -A $OUTPUT_DIR)" ]; then
    echo ""
    echo -e "${YELLOW}Generated files:${NC}"
    ls -lh "$OUTPUT_DIR" | tail -n +2 | awk '{printf "  %-35s %8s\n", $9, $5}'
fi
