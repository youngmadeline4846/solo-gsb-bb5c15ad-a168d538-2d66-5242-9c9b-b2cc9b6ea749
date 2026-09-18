"""IPv4 路由解析核心逻辑（纯标准库实现，无 Web 依赖）。

给定一组静态路由（CIDR、下一跳、metric）与一组唯一的目标 IPv4 地址，
对每个目标按标准路由转发语义解析：

1. **最长前缀匹配（LPM）**：在所有覆盖该目标的路由中，先取前缀长度最大
   （网段最具体）的路由集合；
2. **最低 metric 胜出**：再在该集合内保留 metric 最小的全部路由；
3. 这些路由的下一跳构成等价多路径（ECMP）结果，按 ``routes`` 输入顺序
   对下一跳去重后返回；没有任何路由覆盖该目标时标记为 unreachable。

全程只做 32 位整数的区间包含判断，**不逐地址展开网段**（``0.0.0.0/0``
与 ``10.0.0.0/8`` 的处理代价相同）。
"""
from __future__ import annotations

from collections import defaultdict
from ipaddress import IPv4Address, ip_address

from .analyzer import InvalidCIDRError, parse_cidr_v4

#: 单次请求允许的最大路由条数
ROUTES_MAX_ENTRIES = 1000

#: 单次请求允许的最大目标数
TARGETS_MAX_ENTRIES = 500

#: metric 取值范围（16 位无符号整数）
METRIC_MIN = 0
METRIC_MAX = 65535


class RouteInputError(ValueError):
    """路由解析输入不合法：目标地址重复。

    ``duplicate_targets`` 给出每个重复目标及其所有出现位置（按首次出现
    排序），每项形如 ``{"target", "indexes"}``。
    """

    def __init__(self, duplicate_targets: list[dict]) -> None:
        self.duplicate_targets = duplicate_targets
        super().__init__(f"{len(duplicate_targets)} 个重复目标地址")


def parse_ipv4_address(text: str) -> tuple[int, str]:
    """严格解析单个 IPv4 地址（纯地址，不含前缀）。

    返回 ``(地址整数, 规范化点分字符串)``。空白会被剥离；CIDR 记法、
    IPv6、非法地址（如 ``999.1.1.1``）与带前导零的歧义写法（如
    ``10.0.0.01``）均抛出 :class:`InvalidCIDRError`。
    """
    if not isinstance(text, str):
        raise InvalidCIDRError("IPv4 地址必须是字符串")
    raw = text.strip()
    if not raw:
        raise InvalidCIDRError("IPv4 地址不能为空")
    if "/" in raw:
        raise InvalidCIDRError(
            f"目标/下一跳必须是纯 IPv4 地址，不能带前缀: {text!r}"
        )
    try:
        address = ip_address(raw)
    except ValueError as exc:
        raise InvalidCIDRError(f"非法 IPv4 地址: {text!r}（{exc}）") from exc
    if not isinstance(address, IPv4Address):
        raise InvalidCIDRError(f"仅支持 IPv4，不支持 IPv6: {text!r}")
    # str(IPv4Address) 即规范化点分形式；带前导零等歧义写法已被
    # ip_address（Python 3.9.5+）直接拒绝。
    return int(address), str(address)


def normalize_metric(metric: object) -> int:
    """校验 metric：仅接受非 bool 整数，范围 0～65535。"""
    if isinstance(metric, bool) or not isinstance(metric, int):
        raise ValueError(f"非法 metric: {metric!r}（必须是 0～65535 的整数）")
    if not METRIC_MIN <= metric <= METRIC_MAX:
        raise ValueError(f"metric 超出范围 0～65535: {metric}")
    return metric


def resolve_routes(
    routes: list[tuple[str, str, int]],
    targets: list[str],
) -> dict:
    """对每个目标解析最长前缀 + 最低 metric 的等价下一跳集合。

    ``routes`` 为有序的 ``(cidr, next_hop, metric)`` 列表，``targets``
    为有序的唯一目标 IPv4 地址列表。

    返回可直接 JSON 序列化的字典：

    - ``route_count`` / ``target_count``：输入数量；
    - ``results``：**保持 targets 输入顺序**，每项含 ``target``、
      ``reachable``、``next_hops``（命中时为按 routes 输入顺序去重的 ECMP
      下一跳，未命中时为空）、``matched_cidr``（命中时为命中前缀的规范化
      CIDR）与 ``metric``（命中时为胜出 metric）；
    - ``next_hop_counts``：按各下一跳在结果中**首次出现的顺序**汇总它命中
      的目标数；同一目标的多个等价下一跳分别计数（ECMP 各计一次）。

    路由/目标数量越界抛出 :class:`ValueError`；非法 CIDR / IPv4 地址抛出
    :class:`InvalidCIDRError`；目标重复抛出 :class:`RouteInputError`。
    """
    if len(routes) > ROUTES_MAX_ENTRIES:
        raise ValueError(
            f"路由数不能超过 {ROUTES_MAX_ENTRIES}，实际 {len(routes)}"
        )
    if len(targets) > TARGETS_MAX_ENTRIES:
        raise ValueError(
            f"目标数不能超过 {TARGETS_MAX_ENTRIES}，实际 {len(targets)}"
        )

    parsed_routes: list[dict] = []
    for index, (raw_cidr, raw_next_hop, raw_metric) in enumerate(routes):
        start, end, cidr = parse_cidr_v4(raw_cidr)
        _, next_hop = parse_ipv4_address(raw_next_hop)
        metric = normalize_metric(raw_metric)
        prefixlen = int(cidr.rsplit("/", 1)[1])
        parsed_routes.append(
            {
                "index": index,
                "start": start,
                "end": end,
                "cidr": cidr,
                "prefixlen": prefixlen,
                "next_hop": next_hop,
                "metric": metric,
            }
        )

    parsed_targets: list[tuple[int, str]] = []
    positions: dict[str, list[int]] = defaultdict(list)
    for index, raw_target in enumerate(targets):
        value, target = parse_ipv4_address(raw_target)
        parsed_targets.append((value, target))
        positions[target].append(index)

    duplicate_targets = [
        {"target": target, "indexes": indexes}
        for target, indexes in positions.items()
        if len(indexes) > 1
    ]
    if duplicate_targets:
        raise RouteInputError(duplicate_targets)

    results: list[dict] = []
    # dict 保序：按下一跳在结果中首次出现的顺序累计计数
    next_hop_counts: dict[str, int] = {}
    unreachable_count = 0

    for target_value, target in parsed_targets:
        best_prefix = -1
        best_metric: int | None = None
        best_routes: list[dict] = []

        for route in parsed_routes:
            if not (route["start"] <= target_value <= route["end"]):
                continue
            if route["prefixlen"] > best_prefix:
                best_prefix = route["prefixlen"]
                best_metric = route["metric"]
                best_routes = [route]
            elif route["prefixlen"] == best_prefix:
                # 先在同一最长前缀内选最低 metric
                assert best_metric is not None
                if route["metric"] < best_metric:
                    best_metric = route["metric"]
                    best_routes = [route]
                elif route["metric"] == best_metric:
                    best_routes.append(route)
                # 更高 metric 的同前缀路由忽略
            # 更短前缀的路由在出现更长前缀后忽略

        if not best_routes:
            unreachable_count += 1
            results.append(
                {
                    "target": target,
                    "reachable": False,
                    "next_hops": [],
                    "matched_cidr": None,
                    "metric": None,
                }
            )
            continue

        # 同长度且覆盖同一目标的网段必然是同一网络，故 CIDR / metric 唯一
        matched_cidr = best_routes[0]["cidr"]
        metric = best_routes[0]["metric"]

        # 按 routes 输入顺序对下一跳去重（dict 按首次插入保序）
        ordered_hops: dict[str, None] = {}
        for route in best_routes:
            ordered_hops.setdefault(route["next_hop"], None)
        next_hops = list(ordered_hops)

        for hop in next_hops:
            # 同一 ECMP 结果的每个等价下一跳分别计数
            next_hop_counts[hop] = next_hop_counts.get(hop, 0) + 1

        results.append(
            {
                "target": target,
                "reachable": True,
                "next_hops": next_hops,
                "matched_cidr": matched_cidr,
                "metric": metric,
            }
        )

    return {
        "route_count": len(parsed_routes),
        "target_count": len(parsed_targets),
        "results": results,
        "next_hop_counts": next_hop_counts,
        "unreachable_count": unreachable_count,
    }
