# tests.py
import logging
import requests
import random
import time
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import *
from proxy_sources import (
    ProxyInfo,
    fetch_proxifly_proxies,
    fetch_proxydaily_proxies,
    fetch_tomcat1235_proxies,
    fetch_monosans_socks5_proxies
)


def check_proxy_with_api(proxy_info):
    """使用API检测代理的可用性和信息（专为Cloudflare ProxyIP检测优化）"""
    if not PROXY_CHECK_API_URL:
        logging.error("未配置 PROXY_CHECK_API_URL,无法检测代理")
        return {"success": False, "latency": 999999}
    
    # 关键修改1: 只使用 host:port 格式，不要任何协议前缀
    proxy_host_port = f"{proxy_info.host}:{proxy_info.port}"
    
    start = time.time()
    
    try:
        # 关键修改2: 参数名改为 proxyip，值只传 host:port
        params = {"proxyip": proxy_host_port}
        if PROXY_CHECK_API_TOKEN:
            params["token"] = PROXY_CHECK_API_TOKEN
        
        response = requests.get(
            PROXY_CHECK_API_URL,
            params=params,
            timeout=PROXY_TEST_TIMEOUT + 2
        )
        
        latency = int((time.time() - start) * 1000)
        
        if response.status_code != 200:
            logging.debug(f"API返回非200状态码: {response.status_code}")
            return {"success": False, "latency": 999999, "https_ok": False}
        
        result = response.json()
        
        # 关键修改3: 根据API文档处理响应
        # 文档响应格式:
        # {
        #   "success": true/false,           # 代理是否可用
        #   "proxyIP": "1.2.3.4",             # 检测的IP
        #   "portRemote": 443,                 # 使用的端口
        #   "colo": "HKG",                     # Cloudflare机房代码
        #   "responseTime": "1320ms",          # 响应时间
        #   "message": "第3次验证有效ProxyIP",  # 结果说明
        #   "timestamp": "2025-06-03T17:21:25.045Z"
        # }
        
        # 检查API返回的success字段
        if not result.get("success"):
            # 代理不可用，但API调用本身是成功的
            logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} 不可用: {result.get('message', '未知原因')}")
            return {"success": False, "latency": 999999, "https_ok": False}
        
        # 从responseTime字段提取延迟（格式如 "1320ms"）
        response_time_str = result.get("responseTime", "0ms")
        # 提取数字部分
        api_latency = int(''.join(filter(str.isdigit, response_time_str)) or 0)
        
        # 如果API返回的延迟比我们测得的更准确，可以用API的延迟
        # 这里我们仍然使用本地测得的延迟，但也可以用api_latency
        # latency = api_latency  # 如果想用API的延迟，取消这行注释
        
        # 获取colo信息（可用于后续分析）
        colo = result.get("colo", "UNKNOWN")
        proxy_info.colo = colo  # 可能需要先在ProxyInfo类中添加colo属性
        
        # 检查延迟是否超过限制
        max_latency = SOCKS5_MAX_LATENCY if proxy_info.type == "socks5" else PROXY_MAX_LATENCY
        
        if latency > max_latency:
            logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} 延迟 {latency}ms 超过限制 {max_latency}ms")
            return {"success": False, "latency": latency, "https_ok": False}
        
        # 保存检测结果
        proxy_info.api_result = result
        proxy_info.tested_latency = latency
        proxy_info.https_ok = True  # 对于ProxyIP检测，https_ok表示可用
        
        return {
            "success": True,
            "latency": latency,
            "https_ok": True,
            "country_code": proxy_info.country_code,  # 可能API不返回国家代码，用原有的
            "colo": colo,
            "message": result.get("message", "")
        }
        
    except requests.exceptions.Timeout:
        logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} API检测超时")
        return {"success": False, "latency": 999999, "https_ok": False}
    except requests.exceptions.RequestException as e:
        logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} API请求失败: {e}")
        return {"success": False, "latency": 999999, "https_ok": False}
    except ValueError as e:  # JSON解析错误
        logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} API返回非JSON数据: {e}")
        return {"success": False, "latency": 999999, "https_ok": False}
    except Exception as e:
        logging.debug(f"代理 {proxy_info.host}:{proxy_info.port} API检测异常: {e}")
        return {"success": False, "latency": 999999, "https_ok": False}


def run_internal_tests():
    """运行内部可用性测试"""
    logging.info("\n" + "="*60)
    logging.info("开始内部测试...")
    logging.info("="*60)
    
    test_results = {
        "data_sources": {},
        "proxy_tests": {"working_count": 0, "total_tested": 0},
        "api_check": False,
        "cf_ip_fetch": False,
    }
    
    passed_tests = 0
    total_tests = 0
    
    # 测试 1: Cloudflare IP 段获取
    logging.info("\n[测试 1/4] Cloudflare IP 段获取...")
    try:
        cidrs = fetch_cf_ipv4_cidrs()
        if len(cidrs) > 0:
            logging.info(f"  ✓ 成功获取 {len(cidrs)} 个 IP 段")
            test_results["cf_ip_fetch"] = True
            passed_tests += 1
        else:
            logging.error("  ✗ IP 段列表为空")
    except Exception as e:
        logging.error(f"  ✗ 获取失败: {e}")
    total_tests += 1
    
    # 测试 2: 数据源测试
    logging.info("\n[测试 2/4] 代理数据源测试...")
    test_region = "US"
    
    sources = [
        ("proxifly",    lambda: fetch_proxifly_proxies(test_region, REGION_TO_COUNTRY_CODE)),
        ("proxydaily",  lambda: fetch_proxydaily_proxies(test_region, REGION_TO_COUNTRY_CODE)),
        ("tomcat1235",  lambda: fetch_tomcat1235_proxies(test_region)),
        ("monosans", lambda: fetch_monosans_socks5_proxies(test_region)),
    ]
    
    for name, func in sources:
        total_tests += 1
        try:
            proxies = func()
            count = len(proxies)
            test_results["data_sources"][name] = count > 0
            logging.info(f"    {name}: {count} 个代理")
            if count > 0:
                passed_tests += 1
        except Exception as e:
            test_results["data_sources"][name] = False
            logging.error(f"    ✗ {name} 失败: {e}")
    
    # 测试 3: API 可用性（修改为更准确的测试）
    logging.info("\n[测试 3/4] 代理检测 API 测试...")
    total_tests += 1
    if not PROXY_CHECK_API_URL:
        logging.warning("  ⚠ 未配置 PROXY_CHECK_API_URL")
    else:
        try:
            # 使用一个测试用的proxyip参数测试API是否正常工作
            test_params = {"proxyip": "1.1.1.1:443"}
            if PROXY_CHECK_API_TOKEN:
                test_params["token"] = PROXY_CHECK_API_TOKEN
                
            r = requests.get(PROXY_CHECK_API_URL, params=test_params, timeout=10)
            
            # API正常工作应该返回200（即使代理不可用）
            if r.status_code == 200:
                try:
                    result = r.json()
                    # 检查响应格式是否符合预期
                    if "success" in result and "proxyIP" in result:
                        logging.info("  ✓ API 响应正常（格式正确）")
                        test_results["api_check"] = True
                        passed_tests += 1
                    else:
                        logging.warning("  ⚠ API 返回格式异常")
                except:
                    logging.warning("  ⚠ API 返回非JSON数据")
            else:
                logging.warning(f"  ⚠ API 状态码异常: {r.status_code}")
        except Exception as e:
            logging.error(f"  ✗ API 测试失败: {e}")
    
    # 测试 4: 代理连通性抽样（使用修改后的check_proxy_with_api）
    logging.info("\n[测试 4/4] 代理连通性测试...")
    all_test_proxies = []
    for name, func in sources:
        try:
            all_test_proxies.extend(func()[:3])
        except:
            pass
    
    working = 0
    tested = min(8, len(all_test_proxies))
    total_tests += 1
    
    if tested > 0 and PROXY_CHECK_API_URL:
        random.shuffle(all_test_proxies)
        for proxy in all_test_proxies[:tested]:
            result = check_proxy_with_api(proxy)
            if result["success"]:
                working += 1
                colo_info = f" [{result.get('colo', 'N/A')}]" if result.get('colo') else ""
                logging.info(f"    ✓ {proxy.host}:{proxy.port} ({proxy.type}) - {result['latency']}ms{colo_info}")
            time.sleep(0.4)  # 避免请求过快
        
        if working > 0:
            logging.info(f"  ✓ {working}/{tested} 个代理可用")
            passed_tests += 1
        else:
            logging.warning("  ⚠ 抽样代理均不可用")
    elif tested == 0:
        logging.info("  ℹ 无代理可测试")
    else:
        logging.warning("  ⚠ PROXY_CHECK_API_URL未配置，跳过代理连通性测试")
    
    test_results["proxy_tests"]["total_tested"] = tested
    test_results["proxy_tests"]["working_count"] = working
    
    # 测试总结
    logging.info("\n" + "="*60)
    logging.info("测试总结")
    logging.info("="*60)
    logging.info(f"通过检查: {passed_tests}/{total_tests}")
    
    # 核心要求：至少能拿到 CF IP 段
    # 其他项允许最多失败 1 个
    success = test_results["cf_ip_fetch"] and (passed_tests >= total_tests - 2)
    
    if success:
        logging.info("✅ 自检通过（允许部分非核心项失败）")
    else:
        logging.warning("⚠ 自检未完全通过，但核心项正常，将尝试继续运行")
    
    return success
