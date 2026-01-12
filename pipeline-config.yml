import sys
import json

# 检查是否提供了文件路径作为命令行参数
if len(sys.argv) < 4:
    print("Usage: python check_vulnerabilities.py <json_file_path>")
    sys.exit(1)

# 从命令行获取 JSON 文件路径
json_file_path = sys.argv[1]
json_putOnRecord_file_path = sys.argv[2]
repoName = sys.argv[3]


# # 从命令行获取 JSON 文件路径
# json_file_path = "D:\\Download\\Downloads\\SecurityTest20230201-master (6)\\SecurityTest20230201-master\\SecurityTest\\TestSuite\\test_license_scan.json"
# json_putOnRecord_file_path = "D:\\fetchNewProjects\\repo_putOnRecord_dependencies.json"
# repoName = "opensourceways/jenkins-log-scanner"
# 加载 JSON 文件，指定编码为 utf-8
try:
    with open(json_file_path, encoding='utf-8') as f:
        data = json.load(f)
except UnicodeDecodeError:
    print(f"Error: Failed to decode the file '{json_file_path}'. Please check the file encoding.")
    sys.exit(1)
try:
    with open(json_putOnRecord_file_path, encoding='utf-8') as f:
        putOnRecordData = json.load(f)
except UnicodeDecodeError:
    print(f"Error: Failed to decode the file '{json_file_path}'. Please check the file encoding.")
    sys.exit(1)

cnt = 0
putOnRecordCnt = 0


def findPutOnRecord(vulnerabilityId, repoName, pkgName):
    for putOnRecordDataItem in putOnRecordData:
        if putOnRecordDataItem["VulnerabilityID"] == vulnerabilityId and putOnRecordDataItem[
            "full_name"] == repoName and putOnRecordDataItem["PkgName"] == pkgName:
            return True
    return False


def analyze_and_report(json_data):
    # 1. 数据解析
    if isinstance(json_data, str):
        data = json.loads(json_data)
    else:
        data = json_data

    results = data.get("Results", [])

    # 定义全局标志位
    HAS_HIGH_RISK = False

    # 2. 建立 License 映射索引: (Target, PkgName) -> Info
    license_index = {}
    for res in results:
        if res.get("Class") == "license":
            target_path = res.get("Target")
            for lic in res.get("Licenses", []):
                pkg_name = lic.get("PkgName")
                license_index[(target_path, pkg_name)] = {
                    "Name": lic.get("Name"),
                    "Severity": lic.get("Severity", "UNKNOWN").upper()
                }

    print("=" * 110)
    print(f"{'LICENSE 扫描明细报告 (直接依赖)':^110}")
    print("=" * 110)

    # 3. 核心分析循环
    for res in results:
        if res.get("Class") == "lang-pkgs":
            target = res.get("Target")
            packages = res.get("Packages", [])

            # 筛选直接依赖
            direct_deps = [p for p in packages if p.get("Relationship") == "direct"]
            if not direct_deps:
                continue

            print(f"\n📂 扫描目标: {target}")
            print(f"   {'-' * 100}")
            print(f"   {'状态':<4} | {'直接依赖包名':<55} | {'License':<15} | {'风险级别':<10}")
            print(f"   {'-' * 100}")

            stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

            for pkg in direct_deps:
                p_name = pkg.get("Name")
                # 检索 License 信息
                info = license_index.get((target, p_name), {"Name": "Unknown", "Severity": "UNKNOWN"})
                sev = info["Severity"]

                # 更新统计
                if sev in stats:
                    stats[sev] += 1
                else:
                    stats["UNKNOWN"] += 1

                # 检查并更新全局高危标志
                if sev in ["HIGH", "CRITICAL"]:
                    HAS_HIGH_RISK = True
                    status_icon = "[!]"
                else:
                    status_icon = "[OK]"

                # 打印每一行详情
                print(f"   {status_icon:<4} | {p_name:<55} | {info['Name']:<15} | {sev:<10}")

            # 打印当前 Target 的统计数据（包含所有级别）
            print(f"   {'-' * 100}")
            summary = " | ".join([f"{k}: {v}" for k, v in stats.items()])
            print(f"   📊 统计摘要: {summary}")

    # 4. 最终全局风险判定
    print("\n" + "=" * 110)
    print(f"{'全局风险判定结果':^110}")
    print("-" * 110)
    if HAS_HIGH_RISK:
        print(f"{'🔴 警告：项目中存在 HIGH 或 CRITICAL 级别的 License 风险！':^110}")
    else:
        print(f"{'🟢 通过：项目中未发现高危 License 风险。':^110}")
    print("=" * 110)

    return HAS_HIGH_RISK


# 运行分析
HAS_HIGH_RISK_FOUND = analyze_and_report(data)

if HAS_HIGH_RISK_FOUND:
    print(f"存在高危license，见上述详情.")
    sys.exit(1)
else:
    print(f"license合规扫描通过.")
    sys.exit(0)
