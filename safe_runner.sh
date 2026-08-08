#!/bin/bash
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
EVIDENCE_FILE="/storage/emulated/0/危险报告.txt"
TEMP_DIR=$(mktemp -d)
FOUND_RISK=0
declare -A ALERT_HASH_TABLE
cleanup() {
    [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
}
trap cleanup EXIT
alert() {
    local msg="$1"
    local evidence="$2"
    local hash=$(echo -n "$evidence" | md5sum | cut -d' ' -f1)
    if [[ -n "${ALERT_HASH_TABLE[$hash]}" ]]; then
        return 0
    fi
    ALERT_HASH_TABLE["$hash"]=1
    echo -e "${RED}[警报] $msg${NC}"
    {
        echo "=========================================="
        echo "[!] 警报: $msg"
        echo "------------------------------------------"
        echo "[证] 证据:"
        echo "    $evidence"
        echo "=========================================="
        echo ""
    } >> "$EVIDENCE_FILE"
    FOUND_RISK=1
}
pre_process_ast() {
    local file="$1"
    sed -E '/^[[:space:]]*#/d; /if[[:space:]]+false;?[[:space:]]*then/,/fi/d' "$file" > "$TEMP_DIR/clean_code.sh"
}
taint_analysis() {
    local file="$1"
    if grep -qE "(read|curl|wget).*\;.*(eval|exec)" "$file" 2>/dev/null; then
        local match=$(grep -E "(read|curl|wget).*\;.*(eval|exec)" "$file" | head -n 1)
        alert "外部输入直接流入危险执行点 (污点注入)" "$match"
    fi
    grep -E '^[a-zA-Z_]+=' "$file" > "$TEMP_DIR/vars.txt" 2>/dev/null
    grep -E '\$[a-zA-Z_]+\$[a-zA-Z_]+' "$file" > "$TEMP_DIR/execs.txt" 2>/dev/null
    while read -r exec_line; do
        var1=$(echo "$exec_line" | grep -oE '\$[a-zA-Z_]+' | head -n 1 | tr -d '$')
        var2=$(echo "$exec_line" | grep -oE '\$[a-zA-Z_]+' | tail -n 1 | tr -d '$')
        val1=$(grep "^${var1}=" "$TEMP_DIR/vars.txt" 2>/dev/null | cut -d'=' -f2-)
        val2=$(grep "^${var2}=" "$TEMP_DIR/vars.txt" 2>/dev/null | cut -d'=' -f2-)
        if [ -n "$val1" ] && [ -n "$val2" ]; then
            combined="$val1$val2"
            if echo "$combined" | grep -qE "(rm.*-rf|chmod.*777|bash.*-i)" 2>/dev/null; then
                alert "跨行变量拼接执行危险命令" "拼接结果: $combined (原代码: $exec_line)"
            fi
        fi
    done < "$TEMP_DIR/execs.txt"
}
scan_basic_threats() {
    local file="$1"
    local patterns=(
        "rm.*-r.*-f.*/"
        "chmod.*a=rwx"
        "chmod.*777"
        "wget.*|.*sh"
        "curl.*|.*bash"
        "nc.*-e"
        "/dev/tcp/"
        "bash.*-i"
        "LD_PRELOAD.*="
        "IFS.*="
    )
    for pattern in "${patterns[@]}"; do
        if grep -qE "$pattern" "$file" 2>/dev/null; then
            local match=$(grep -E "$pattern" "$file" 2>/dev/null | head -n 1)
            alert "深层检测命中危险特征" "$match"
        fi
    done
}
scan_advanced_context() {
    local file="$1"
    local patterns=(
        'eval.*\${!'
        'exec.*\${.*\[@\]}'
        'base64.*-d.*|.*sh'
        'openssl.*enc.*-d.*|.*bash'
    )
    for pattern in "${patterns[@]}"; do
        if grep -qE "$pattern" "$file" 2>/dev/null; then
            local match=$(grep -E "$pattern" "$file" 2>/dev/null | head -n 1)
            alert "发现高级混淆或执行链特征" "$match"
        fi
    done
}
main() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE} SafeRunner V18.1 (生产级去重版) ${NC}"
    echo -e "${BLUE}========================================${NC}\n"
    {
        echo "##################################################"
        echo "#        SafeRunner V18.1 安全扫描报告           #"
        echo "##################################################"
        echo ""
        echo "扫描时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "目标文件: $1"
        echo ""
        echo "--------------------------------------------------"
        echo ""
    } > "$EVIDENCE_FILE"
    echo -ne "${YELLOW}请输入要检测的脚本路径: ${NC}"
    read -r target_script
    [ ! -f "$target_script" ] && { echo -e "${RED}错误: 文件不存在！${NC}"; exit 1; }
    sed -i "s|目标文件: .*|目标文件: $target_script|" "$EVIDENCE_FILE"
    echo -e "${BLUE}[1/4] AST预处理: 剔除注释与死代码...${NC}"
    pre_process_ast "$target_script"
    local clean_file="$TEMP_DIR/clean_code.sh"
    echo -e "${BLUE}[2/4] 污点追踪: 外部输入与跨行拼接分析...${NC}"
    taint_analysis "$clean_file"
    echo -e "${BLUE}[3/4] 基础威胁扫描: 高危命令模糊匹配...${NC}"
    scan_basic_threats "$clean_file"
    echo -e "${BLUE}[4/4] 高级上下文扫描: 执行链与混淆检测...${NC}"
    scan_advanced_context "$clean_file"
    {
        echo "--------------------------------------------------"
        echo ""
        if [ $FOUND_RISK -eq 1 ]; then
            echo ">>> 扫描结论: 极度危险 (千万别跑) <<<"
        else
            echo ">>> 扫描结论: 暂未发现明显威胁 <<<"
        fi
        echo ""
        echo "##################################################"
    } >> "$EVIDENCE_FILE"
    echo -e "\n----------------------------------------"
    if [ $FOUND_RISK -eq 1 ]; then
        echo -e "${RED}>>> 结论: 极度危险 (千万别跑) <<<${NC}"
        echo -e "${YELLOW}整齐报告已保存至: $EVIDENCE_FILE${NC}"
        exit 1
    else
        echo -e "${GREEN}>>> 结论: 暂未发现明显威胁 <<<${NC}"
        echo -e "${YELLOW}整齐报告已保存至: $EVIDENCE_FILE${NC}"
        exit 0
    fi
}
main
