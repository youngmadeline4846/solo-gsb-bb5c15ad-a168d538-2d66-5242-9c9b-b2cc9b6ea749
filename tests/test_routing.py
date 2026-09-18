"""IPv4 路由解析核心逻辑的单元测试。"""
import random

import pytest
from ipaddress import ip_address, ip_network

from app.routing import (
    METRIC_MAX,
    METRIC_MIN,
    ROUTES_MAX_ENTRIES,
    TARGETS_MAX_ENTRIES,
    InvalidCIDRError,
    RouteInputError,
    normalize_metric,
    parse_ipv4_address,
    resolve_routes,
)


# ---------- 地址解析 ----------

def test_parse_ipv4_address_basic():
    value, text = parse_ipv4_address("10.0.0.1")
    assert value == (10 << 24) + 1
    assert text == "10.0.0.1"


def test_parse_ipv4_address_strips_whitespace_and_canonicalizes():
    assert parse_ipv4_address("  8.8.8.8  ") == (int(ip_address("8.8.8.8")), "8.8.8.8")
    assert parse_ipv4_address("0.0.0.0") == (0, "0.0.0.0")
    assert parse_ipv4_address("255.255.255.255") == ((1 << 32) - 1, "255.255.255.255")


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "10.0.0",
        "999.0.0.1",
        "10.0.0.1/32",   # 目标/下一跳不接受前缀
        "10.0.0.01",     # 前导零歧义写法
        "0x0a000001",
        "2001:db8::1",   # IPv6
        "::1",
    ],
)
def test_parse_ipv4_address_rejects_invalid(bad):
    with pytest.raises(InvalidCIDRError):
        parse_ipv4_address(bad)


def test_parse_ipv4_address_rejects_non_string():
    with pytest.raises(InvalidCIDRError):
        parse_ipv4_address(0x0A000001)  # type: ignore[arg-type]


# ---------- metric ----------

@pytest.mark.parametrize("metric", [METRIC_MIN, METRIC_MAX, 1, 100])
def test_normalize_metric_accepts_range(metric):
    assert normalize_metric(metric) == metric


@pytest.mark.parametrize("metric", [-1, 65536, True, False, 1.0, "10", None])
def test_normalize_metric_rejects_invalid(metric):
    with pytest.raises(ValueError):
        normalize_metric(metric)


# ---------- 路由解析语义 ----------

def _basic_routes():
    return [
        ("172.16.0.0/12", "192.0.2.1", 100),  # 0 不相关网段
        ("10.0.0.0/8", "10.0.0.1", 50),       # 1 /8
        ("10.0.0.0/8", "10.0.0.2", 50),       # 2 /8 ECMP
        ("10.0.0.0/8", "10.0.0.9", 60),       # 3 同前缀更高 metric，忽略
        ("10.1.0.0/16", "10.1.0.1", 20),      # 4 更具体
        ("10.1.0.0/16", "10.1.0.2", 30),      # 5 更具体但 metric 高，忽略
        ("10.1.0.0/16", "10.1.0.1", 20),      # 6 重复下一跳，去重
    ]


def test_resolve_lpm_metric_ecmp_and_unreachable():
    out = resolve_routes(_basic_routes(), ["10.1.0.5", "10.2.3.4", "8.8.8.8"])
    results = out["results"]

    # 结果保持 targets 输入顺序
    assert [item["target"] for item in results] == ["10.1.0.5", "10.2.3.4", "8.8.8.8"]

    # 最长前缀 /16 胜出，内部只留最低 metric，重复下一跳去重
    first = results[0]
    assert first["reachable"] is True
    assert first["next_hops"] == ["10.1.0.1"]
    assert first["matched_cidr"] == "10.1.0.0/16"
    assert first["metric"] == 20

    # /8 上 metric=50 的两条构成 ECMP，按 routes 输入顺序排列；metric=60 忽略
    second = results[1]
    assert second["reachable"] is True
    assert second["next_hops"] == ["10.0.0.1", "10.0.0.2"]
    assert second["matched_cidr"] == "10.0.0.0/8"
    assert second["metric"] == 50

    # 未命中任何路由
    third = results[2]
    assert third["reachable"] is False
    assert third["next_hops"] == []
    assert third["matched_cidr"] is None
    assert third["metric"] is None

    # 命中计数：ECMP 各计一次；未出现的下一跳（192.0.2.1 / 10.0.0.9 / 10.1.0.2）
    # 不在汇总中；顺序为下一跳在结果中首次出现的顺序
    assert dict(out["next_hop_counts"]) == {
        "10.1.0.1": 1,
        "10.0.0.1": 1,
        "10.0.0.2": 1,
    }
    assert out["unreachable_count"] == 1
    assert out["route_count"] == 7
    assert out["target_count"] == 3


def test_resolve_ecmp_hops_counted_separately_per_target():
    routes = [
        ("10.0.0.0/8", "10.0.0.1", 10),
        ("10.0.0.0/8", "10.0.0.2", 10),
        ("10.0.0.0/8", "10.0.0.3", 10),
    ]
    out = resolve_routes(routes, ["10.0.0.9", "10.1.2.3"])
    assert all(item["next_hops"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
               for item in out["results"])
    # 同一目标的 3 个等价下一跳分别计数：每个下一跳命中 2 个目标
    assert dict(out["next_hop_counts"]) == {
        "10.0.0.1": 2,
        "10.0.0.2": 2,
        "10.0.0.3": 2,
    }
    assert out["unreachable_count"] == 0


def test_resolve_longer_prefix_beats_lower_metric_on_shorter():
    # 短前缀 metric 更低也不能压过长前缀：先比前缀长度，再比 metric
    routes = [
        ("0.0.0.0/0", "1.1.1.1", 0),
        ("10.0.0.0/8", "10.0.0.1", 999),
    ]
    out = resolve_routes(routes, ["10.0.0.1"])
    item = out["results"][0]
    assert item["matched_cidr"] == "10.0.0.0/8"
    assert item["metric"] == 999
    assert item["next_hops"] == ["10.0.0.1"]


def test_resolve_dedup_keeps_routes_input_order():
    # 即便 metric 相同的路由输入乱序，去重结果严格按 routes 输入顺序
    routes = [
        ("10.0.0.0/16", "10.0.0.9", 5),
        ("10.0.0.0/16", "10.0.0.1", 5),
        ("10.0.0.0/16", "10.0.0.9", 5),  # 与第 0 条重复
        ("10.0.0.0/16", "10.0.0.5", 5),
    ]
    item = resolve_routes(routes, ["10.0.0.2"])["results"][0]
    assert item["next_hops"] == ["10.0.0.9", "10.0.0.1", "10.0.0.5"]


def test_resolve_default_route_covers_everything_without_expansion():
    routes = [("0.0.0.0/0", "192.0.2.1", 200)]
    out = resolve_routes(routes, ["0.0.0.0", "255.255.255.255", "128.0.0.1"])
    assert out["unreachable_count"] == 0
    assert all(item["matched_cidr"] == "0.0.0.0/0" for item in out["results"])
    assert dict(out["next_hop_counts"]) == {"192.0.2.1": 3}


def test_resolve_empty_inputs():
    assert resolve_routes([], []) == {
        "route_count": 0,
        "target_count": 0,
        "results": [],
        "next_hop_counts": {},
        "unreachable_count": 0,
    }


def test_resolve_empty_routes_marks_unreachable():
    out = resolve_routes([], ["8.8.8.8", "9.9.9.9"])
    assert out["unreachable_count"] == 2
    assert all(not item["reachable"] for item in out["results"])


def test_resolve_targets_uniqueness_required():
    with pytest.raises(RouteInputError) as excinfo:
        resolve_routes([], ["1.1.1.1", "2.2.2.2", "1.1.1.1"])
    assert excinfo.value.duplicate_targets == [
        {"target": "1.1.1.1", "indexes": [0, 2]}
    ]


def test_resolve_duplicate_target_after_normalization():
    # 带空白的等价写法规范化后视为同一目标
    with pytest.raises(RouteInputError) as excinfo:
        resolve_routes([], ["10.0.0.1", " 10.0.0.1 "])
    assert excinfo.value.duplicate_targets == [
        {"target": "10.0.0.1", "indexes": [0, 1]}
    ]


def test_resolve_duplicate_targets_reported_in_first_seen_order():
    with pytest.raises(RouteInputError) as excinfo:
        resolve_routes(
            [],
            ["3.3.3.3", "1.1.1.1", "3.3.3.3", "2.2.2.2", "1.1.1.1"],
        )
    assert [group["target"] for group in excinfo.value.duplicate_targets] == [
        "3.3.3.3",
        "1.1.1.1",
    ]


def test_resolve_invalid_route_cidr_and_hop_raise():
    for bad_cidr in ["10.0.0.1/8", "0.0.0.0/33", "2001:db8::/32", "garbage"]:
        with pytest.raises(InvalidCIDRError):
            resolve_routes([(bad_cidr, "10.0.0.1", 0)], ["10.0.0.2"])
    for bad_hop in ["10.0.0.1/32", "::1", "nope", "10.0.0.01"]:
        with pytest.raises(InvalidCIDRError):
            resolve_routes([("10.0.0.0/8", bad_hop, 0)], ["10.0.0.2"])


def test_resolve_invalid_target_raises():
    for bad in ["1.0.0.0/24", "::1", "nope", "10.0.0.01", ""]:
        with pytest.raises(InvalidCIDRError):
            resolve_routes([], [bad])


def test_resolve_invalid_metric_raises_value_error():
    for metric in [-1, 65536, True]:
        with pytest.raises(ValueError):
            resolve_routes([("0.0.0.0/0", "1.1.1.1", metric)], ["1.1.1.1"])


def test_resolve_limits():
    with pytest.raises(ValueError):
        resolve_routes([("10.0.0.0/8", "10.0.0.1", 0)] * (ROUTES_MAX_ENTRIES + 1), [])
    with pytest.raises(ValueError):
        resolve_routes([], ["1.1.1.1"] * (TARGETS_MAX_ENTRIES + 1))

    # 恰好在上限内可以处理
    routes = [("10.0.0.0/16", "10.0.0.1", 0)]
    targets = [f"10.0.{i // 256}.{i % 256}" for i in range(TARGETS_MAX_ENTRIES)]
    # 前 256 个落在 10.0.0.0/24..10.0.0.x，其余在 10.0.1.x；均在 /16 内
    assert len(targets) == TARGETS_MAX_ENTRIES
    out = resolve_routes(routes, targets)
    assert out["unreachable_count"] == 0
    assert dict(out["next_hop_counts"]) == {"10.0.0.1": TARGETS_MAX_ENTRIES}


# ---------- 随机属性测试：以 ipaddress 为 oracle ----------

def _brute_resolve(routes, targets):
    """参考实现：对每个目标逐条路由用 ipaddress 判定（不展开网段）。"""
    results = {}
    counts: dict[str, int] = {}
    unreachable = 0
    for raw_target in targets:
        addr = int(ip_address(raw_target))
        covering = []
        for index, (cidr, next_hop, metric) in enumerate(routes):
            net = ip_network(cidr)
            if int(net.network_address) <= addr <= int(net.broadcast_address):
                covering.append((net.prefixlen, metric, next_hop.strip(), index, str(net)))
        if not covering:
            results[raw_target] = (False, [], None, None)
            unreachable += 1
            continue
        longest = max(item[0] for item in covering)
        candidates = [item for item in covering if item[0] == longest]
        best_metric = min(item[1] for item in candidates)
        candidates = sorted(
            (item for item in candidates if item[1] == best_metric),
            key=lambda item: item[3],
        )
        hops: list[str] = []
        seen: set[str] = set()
        for _, _, hop, _, _ in candidates:
            hop = str(ip_address(hop))
            if hop not in seen:
                seen.add(hop)
                hops.append(hop)
        results[raw_target] = (True, hops, candidates[0][4], best_metric)
        for hop in hops:
            counts[hop] = counts.get(hop, 0) + 1
    return results, counts, unreachable


def test_resolve_matches_brute_force_oracle():
    rng = random.Random(20260918)
    for _ in range(300):
        routes = []
        for _ in range(rng.randint(0, 50)):
            prefixlen = rng.randint(0, 32)
            net = ip_network((rng.getrandbits(32), prefixlen), strict=False)
            routes.append(
                (str(net), str(ip_address(rng.getrandbits(32))), rng.randint(0, 65535))
            )
        targets = list(
            dict.fromkeys(
                str(ip_address(rng.getrandbits(32))) for _ in range(rng.randint(0, 80))
            )
        )

        out = resolve_routes(list(routes), list(targets))
        expected_results, expected_counts, expected_unreachable = _brute_resolve(
            routes, targets
        )

        assert out["unreachable_count"] == expected_unreachable
        assert dict(out["next_hop_counts"]) == expected_counts
        assert len(out["results"]) == len(targets)
        for index, item in enumerate(out["results"]):
            reachable, hops, cidr, metric = expected_results[targets[index]]
            assert item["target"] == str(ip_address(targets[index]))
            assert item["reachable"] is reachable
            assert item["next_hops"] == hops
            assert item["matched_cidr"] == cidr
            assert item["metric"] == metric
