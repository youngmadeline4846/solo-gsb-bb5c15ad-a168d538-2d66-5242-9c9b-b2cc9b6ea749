"""FastAPI 接口测试。"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_analyze(rules):
    return client.post("/analyze", json={"rules": rules})


def post_compare(left, right):
    return client.post("/compare", json={"left": left, "right": right})


def test_root_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_full_partial_shadowed():
    resp = post_analyze(
        [
            {"action": "allow", "cidr": "10.0.0.0/8"},
            {"action": "deny", "cidr": "10.1.0.0/16"},
            {"action": "ALLOW", "cidr": "192.168.0.0/16"},
            {"action": "deny", "cidr": "10.0.0.0/7"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] == 4
    assert [r["status"] for r in body["rules"]] == [
        "full",
        "shadowed",
        "full",
        "partial",
    ]
    # action 大小写不敏感并规范化
    assert body["rules"][2]["action"] == "allow"
    assert body["rules"][0]["status_label"] == "全生效"
    assert body["rules"][3]["effective_cidrs"] == ["11.0.0.0/8"]
    assert body["summary"] == {
        "full": 2,
        "partial": 1,
        "shadowed": 1,
        "effective_allow_addresses": (1 << 24) + (1 << 16),
        "effective_deny_addresses": 1 << 24,
    }


def test_bare_ip_accepted_as_32():
    resp = post_analyze([{"action": "allow", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["cidr"] == "8.8.8.8/32"
    assert rule["total_addresses"] == 1
    assert rule["status"] == "full"


def test_empty_rules_422():
    assert client.post("/analyze", json={"rules": []}).status_code == 422
    assert client.post("/analyze", json={}).status_code == 422


def test_invalid_cidr_422():
    for bad in ["10.0.0.0/33", "10.0.0.1/8", "garbage", "9.9.9.9/99"]:
        resp = post_analyze([{"action": "allow", "cidr": bad}])
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]


def test_ipv6_422():
    for bad in ["2001:db8::/32", "::1", "fe80::1/64"]:
        assert post_analyze([{"action": "allow", "cidr": bad}]).status_code == 422, bad


def test_bad_action_422():
    assert post_analyze(
        [{"action": "permit", "cidr": "10.0.0.0/8"}]
    ).status_code == 422


def test_missing_field_422():
    assert client.post("/analyze", json={"rules": [{"cidr": "10.0.0.0/8"}]}).status_code == 422
    assert client.post("/analyze", json={"rules": [{"action": "allow"}]}).status_code == 422


def test_non_list_body_422():
    assert client.post("/analyze", json={"rules": "nope"}).status_code == 422


def test_malformed_json_422():
    resp = client.post(
        "/analyze",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ---------- /compare ----------

def test_compare_equivalent_empty_sets():
    resp = post_compare(
        {"rules": [], "default_action": "allow"},
        {"rules": [], "default_action": "ALLOW"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_default_only_full_space_diff():
    resp = post_compare(
        {"rules": [], "default_action": "deny"},
        {"rules": [], "default_action": "allow"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is False
    assert body["differences"] == [
        {
            "left_action": "deny",
            "right_action": "allow",
            "address_count": 1 << 32,
            "cidrs": ["0.0.0.0/0"],
        }
    ]


def test_compare_rules_only_one_side():
    resp = post_compare(
        {"rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        {"rules": [], "default_action": "deny"},
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_compare_order_sensitivity_and_bidirectional_groups():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.1.0.0/16"},
            ],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "deny", "cidr": "10.1.0.0/16"},
                {"action": "allow", "cidr": "10.0.0.0/8"},
            ],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_shadowed_rule_still_equivalent():
    resp = post_compare(
        {
            "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.0.0.1/32"},
            ],
            "default_action": "Deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_validation_422():
    base = {"rules": [], "default_action": "deny"}

    # 缺少 default_action
    resp = client.post("/compare", json={"left": {"rules": []}, "right": base})
    assert resp.status_code == 422

    # 非法 default_action / action
    assert post_compare(
        {"rules": [], "default_action": "permit"}, base
    ).status_code == 422
    assert post_compare(
        {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        base,
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用 /analyze 校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        resp = post_compare(
            {"rules": [{"action": "allow", "cidr": bad}],
             "default_action": "deny"},
            base,
        )
        assert resp.status_code == 422, bad

    # 缺少一侧 / 请求体为空
    assert client.post("/compare", json={"left": base}).status_code == 422
    assert client.post("/compare", json={}).status_code == 422


# ---------- /explain ----------

def post_explain(rules, default_action, query):
    return client.post(
        "/explain",
        json={"rules": rules, "default_action": default_action, "query": query},
    )


def test_explain_basic_attribution():
    resp = post_explain(
        [
            {"action": "allow", "cidr": "10.0.0.0/16"},
            {"action": "deny", "cidr": "10.0.1.0/24"},
            {"action": "deny", "cidr": "10.2.0.0/16"},
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "10.0.0.0/8"
    assert body["total_addresses"] == 1 << 24

    attribution = body["attribution"]
    # 规则 1 在 query 内被完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0]["action"] == "allow"
    assert attribution[0]["cidrs"] == ["10.0.0.0/16"]
    assert attribution[1]["action"] == "deny"
    assert attribution[1]["cidrs"] == ["10.2.0.0/16"]
    assert attribution[2]["action"] == "deny"
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_normalized():
    resp = post_explain(
        [{"action": "ALLOW", "cidr": "8.8.8.0/24"}],
        "Deny",
        "8.8.8.8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "8.8.8.8/32"
    assert body["total_addresses"] == 1
    # action / default_action 大小写不敏感并规范化
    assert body["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    resp = post_explain([], "allow", "192.168.0.0/16")
    assert resp.status_code == 200
    assert resp.json()["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_validation_422():
    # 缺少 default_action / query、空请求体
    assert client.post(
        "/explain", json={"rules": [], "query": "10.0.0.0/8"}
    ).status_code == 422
    assert client.post(
        "/explain", json={"rules": [], "default_action": "deny"}
    ).status_code == 422
    assert client.post("/explain", json={}).status_code == 422

    # 非法 query：格式错误、主机位非零、IPv6
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        assert post_explain([], "deny", bad).status_code == 422, bad

    # 非法 default_action / action / 规则 CIDR（沿用现有校验）
    assert post_explain([], "permit", "10.0.0.0/8").status_code == 422
    assert post_explain(
        [{"action": "permit", "cidr": "10.0.0.0/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422
    assert post_explain(
        [{"action": "allow", "cidr": "10.0.0.1/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422


# ---------- /cidrs/hierarchy ----------

def post_hierarchy(entries):
    return client.post("/cidrs/hierarchy", json={"entries": entries})


def test_hierarchy_basic_tree():
    resp = post_hierarchy(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub", "cidr": "10.1.0.0/16"},
            {"id": "host", "cidr": "10.1.1.1"},
            {"id": "other", "cidr": "8.8.8.0/24"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 4
    assert body["root_count"] == 2

    # 根按网络地址稳定排序：8.8.8.0/24 在 10.0.0.0/8 之前
    other, net = body["roots"]
    assert other["id"] == "other"
    assert other["cidr"] == "8.8.8.0/24"
    assert other["parent_id"] is None
    assert other["children"] == []
    assert other["total_addresses"] == 256
    assert other["exclusive_address_count"] == 256
    assert other["exclusive_cidrs"] == ["8.8.8.0/24"]

    assert net["id"] == "net"
    assert net["cidr"] == "10.0.0.0/8"
    assert net["parent_id"] is None
    assert net["total_addresses"] == 1 << 24
    # /8 的直接子节点仅 10.1.0.0/16（host 是孙节点，不重复扣除）
    assert net["exclusive_address_count"] == (1 << 24) - (1 << 16)

    sub = net["children"][0]
    assert sub["id"] == "sub"
    assert sub["parent_id"] == "net"
    assert sub["total_addresses"] == 1 << 16
    # /16 扣除直接子节点 10.1.1.1/32
    assert sub["exclusive_address_count"] == (1 << 16) - 1
    assert sub["exclusive_cidrs"][0] == "10.1.0.0/24"

    host = sub["children"][0]
    assert host["id"] == "host"
    assert host["cidr"] == "10.1.1.1/32"  # 纯 IP 规范化为 /32
    assert host["parent_id"] == "sub"
    assert host["total_addresses"] == 1
    assert host["exclusive_address_count"] == 1
    assert host["exclusive_cidrs"] == ["10.1.1.1/32"]
    assert host["children"] == []


def test_hierarchy_longest_prefix_supernet_is_parent():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.1.0.0/16"},
            {"id": "c", "cidr": "10.1.2.0/24"},
        ]
    )
    assert resp.status_code == 200
    roots = resp.json()["roots"]
    assert [n["id"] for n in roots] == ["a"]
    b = roots[0]["children"][0]
    assert b["id"] == "b"
    # /24 的唯一 parent 是前缀最长的严格超网 /16，而非 /8
    assert [c["id"] for c in b["children"]] == ["c"]
    assert b["children"][0]["parent_id"] == "b"


def test_hierarchy_integer_ids_and_root_order():
    resp = post_hierarchy(
        [
            {"id": 2, "cidr": "192.168.0.0/16"},
            {"id": 1, "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 200
    assert [n["id"] for n in resp.json()["roots"]] == [1, 2]


def test_hierarchy_duplicate_network_422_lists_ids():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.0.0.0/08"},  # 规范化后与 a 相同
            {"id": "c", "cidr": "8.8.8.8/32"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == []
    assert detail["duplicate_networks"] == [
        {
            "cidr": "10.0.0.0/8",
            "entries": [
                {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
                {"index": 1, "id": "b", "cidr": "10.0.0.0/8"},
            ],
        }
    ]


def test_hierarchy_duplicate_id_422_lists_indexes():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "11.0.0.0/8"},
            {"id": 5, "cidr": "12.0.0.0/8"},
            {"id": 5, "cidr": "13.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 1]},
        {"id": 5, "indexes": [2, 3]},
    ]
    assert detail["duplicate_networks"] == []


def test_hierarchy_both_duplicates_reported_together():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail["duplicate_ids"]) == 1
    assert len(detail["duplicate_networks"]) == 1


def test_hierarchy_validation_422():
    # 空列表 / 缺少 entries
    assert post_hierarchy([]).status_code == 422
    assert client.post("/cidrs/hierarchy", json={}).status_code == 422

    # 超过 500 条
    too_many = [{"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(501)]
    assert post_hierarchy(too_many).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_hierarchy([{"id": "a", "cidr": bad}]).status_code == 422, bad

    # 非法 id：bool / float / 对象 / 空字符串 / 缺字段
    for bad_id in [True, 1.5, ["x"], {"k": 1}, "   "]:
        assert post_hierarchy(
            [{"id": bad_id, "cidr": "10.0.0.0/8"}]
        ).status_code == 422, bad_id
    assert post_hierarchy([{"cidr": "10.0.0.0/8"}]).status_code == 422
    assert post_hierarchy([{"id": "a"}]).status_code == 422


def test_hierarchy_max_500_entries_accepted():
    entries = [
        {"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    resp = post_hierarchy(entries)
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 500
    # 500 个互不相交的 /32：全部为 root，独占 1 个地址
    assert body["root_count"] == 500
    assert all(n["exclusive_address_count"] == 1 for n in body["roots"])
    # 按网络地址稳定排序（与输入顺序一致）
    assert [n["id"] for n in body["roots"]] == list(range(500))


def test_hierarchy_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert resp.json()["rules"][0]["status"] == "full"


# ---------- /routes/resolve ----------

def post_resolve(routes, targets):
    return client.post(
        "/routes/resolve", json={"routes": routes, "targets": targets}
    )


def test_resolve_lpm_metric_ecmp_and_order():
    routes = [
        {"cidr": "172.16.0.0/12", "next_hop": "192.0.2.1", "metric": 100},
        {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 50},
        {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 50},
        {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.9", "metric": 60},
        {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 20},
        {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.2", "metric": 30},
        {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 20},
    ]
    resp = post_resolve(routes, ["10.1.0.5", "10.2.3.4", "8.8.8.8"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 7
    assert body["target_count"] == 3

    results = body["results"]
    # 响应保持 targets 输入顺序
    assert [item["target"] for item in results] == ["10.1.0.5", "10.2.3.4", "8.8.8.8"]

    # 最长前缀 /16 + 最低 metric 20，重复下一跳按 routes 顺序去重
    assert results[0] == {
        "target": "10.1.0.5",
        "reachable": True,
        "next_hops": ["10.1.0.1"],
        "matched_cidr": "10.1.0.0/16",
        "metric": 20,
    }
    # /8 上 metric=50 的两条等价；metric=60 与 /16 高 metric 均不入选
    assert results[1] == {
        "target": "10.2.3.4",
        "reachable": True,
        "next_hops": ["10.0.0.1", "10.0.0.2"],
        "matched_cidr": "10.0.0.0/8",
        "metric": 50,
    }
    # 未命中
    assert results[2] == {
        "target": "8.8.8.8",
        "reachable": False,
        "next_hops": [],
        "matched_cidr": None,
        "metric": None,
    }

    # 汇总按首次出现顺序；未命中的下一跳不计入
    assert body["next_hop_counts"] == {
        "10.1.0.1": 1,
        "10.0.0.1": 1,
        "10.0.0.2": 1,
    }
    assert body["unreachable_count"] == 1


def test_resolve_ecmp_each_hop_counted_separately():
    routes = [
        {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
        {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 10},
    ]
    resp = post_resolve(routes, ["10.0.0.9", "10.1.1.1"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["next_hop_counts"] == {"10.0.0.1": 2, "10.0.0.2": 2}
    assert body["unreachable_count"] == 0


def test_resolve_default_route_reaches_all():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 1000},
    ]
    resp = post_resolve(routes, ["0.0.0.0", "255.255.255.255"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["unreachable_count"] == 0
    assert [item["matched_cidr"] for item in body["results"]] == [
        "0.0.0.0/0",
        "0.0.0.0/0",
    ]
    assert body["next_hop_counts"] == {"192.0.2.254": 2}


def test_resolve_empty_routes_and_targets_ok():
    resp = post_resolve([], [])
    assert resp.status_code == 200
    assert resp.json() == {
        "route_count": 0,
        "target_count": 0,
        "results": [],
        "next_hop_counts": {},
        "unreachable_count": 0,
    }

    resp = post_resolve([], ["8.8.8.8"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["reachable"] is False
    assert body["unreachable_count"] == 1


def test_resolve_normalizes_cidr_and_addresses():
    # 纯 IP 的 cidr 规范化为 /32；目标/下一跳规范化点分形式
    routes = [{"cidr": "8.8.8.8", "next_hop": " 1.1.1.1 ", "metric": 0}]
    resp = post_resolve(routes, [" 8.8.8.8 "])
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["target"] == "8.8.8.8"
    assert item["matched_cidr"] == "8.8.8.8/32"
    assert item["next_hops"] == ["1.1.1.1"]


def test_resolve_duplicate_targets_422_lists_indexes():
    resp = post_resolve([], ["1.1.1.1", "2.2.2.2", "1.1.1.1"])
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_targets"
    assert detail["duplicate_targets"] == [
        {"target": "1.1.1.1", "indexes": [0, 2]}
    ]

    # 规范化（去空白）后重复同样 422
    resp = post_resolve([], ["10.0.0.1", " 10.0.0.1 "])
    assert resp.status_code == 422
    assert resp.json()["detail"]["duplicate_targets"] == [
        {"target": "10.0.0.1", "indexes": [0, 1]}
    ]


def test_resolve_metric_bounds():
    for metric in [0, 65535]:
        resp = post_resolve(
            [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": metric}],
            ["1.2.3.4"],
        )
        assert resp.status_code == 200, metric
        assert resp.json()["results"][0]["metric"] == metric

    for metric in [-1, 65536]:
        resp = post_resolve(
            [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": metric}],
            ["1.2.3.4"],
        )
        assert resp.status_code == 422, metric


def test_resolve_validation_422():
    base = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 0}

    # 缺少顶层字段 / 请求体为空
    assert client.post("/routes/resolve", json={}).status_code == 422
    assert client.post(
        "/routes/resolve", json={"routes": []}
    ).status_code == 422
    assert client.post(
        "/routes/resolve", json={"targets": []}
    ).status_code == 422

    # 缺少路由必填字段
    assert post_resolve(
        [{"cidr": "10.0.0.0/8", "metric": 0}], ["10.0.0.1"]
    ).status_code == 422
    assert post_resolve(
        [{"next_hop": "10.0.0.1", "metric": 0}], ["10.0.0.1"]
    ).status_code == 422
    assert post_resolve(
        [{"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1"}], ["10.0.0.1"]
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_resolve([{**base, "cidr": bad}], ["10.0.0.1"]).status_code == 422, bad

    # next_hop 必须是纯 IPv4：拒绝前缀、IPv6、前导零、空白、非字符串
    for bad in [
        "10.0.0.1/32",
        "::1",
        "2001:db8::1",
        "nope",
        "10.0.0.01",
        "",
        "   ",
        10,
        True,
        ["10.0.0.1"],
    ]:
        assert post_resolve(
            [{**base, "next_hop": bad}], ["10.0.0.1"]
        ).status_code == 422, bad

    # targets 必须是纯 IPv4 字符串
    for bad in ["1.1.1.1/32", "::1", "nope", "10.0.0.01", "", "   ", 123, True]:
        assert post_resolve([], [bad]).status_code == 422, bad

    # metric 必须是严格整数且在范围内：bool / 浮点 / 字符串均拒绝
    for metric in [True, False, 1.5, "100", None]:
        assert post_resolve(
            [{**base, "metric": metric}], ["10.0.0.1"]
        ).status_code == 422, metric

    # 类型错误
    assert client.post(
        "/routes/resolve", json={"routes": "x", "targets": []}
    ).status_code == 422
    assert client.post(
        "/routes/resolve", json={"routes": [], "targets": "x"}
    ).status_code == 422


def test_resolve_entry_limits():
    base = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 0}

    # 路由超过 1000 / 目标超过 500 -> 422
    assert post_resolve([dict(base) for _ in range(1001)], []).status_code == 422
    too_many_targets = [f"1.0.{i // 256}.{i % 256}" for i in range(501)]
    assert post_resolve([], too_many_targets).status_code == 422

    # 恰好 1000 条路由 + 500 个目标可正常解析
    routes = [
        {"cidr": f"10.{i // 256}.{i % 256}.0/24", "next_hop": "10.0.0.1", "metric": 0}
        for i in range(1000)
    ]
    targets = [f"10.0.0.{i}" for i in range(256)] + [
        f"10.0.1.{i}" for i in range(244)
    ]
    assert len(targets) == 500
    resp = post_resolve(routes, targets)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert body["target_count"] == 500
    assert len(body["results"]) == 500


def test_resolve_docs_and_existing_endpoints_unchanged():
    # 新接口注册在 OpenAPI 中
    spec = client.get("/openapi.json").json()
    assert "/routes/resolve" in spec["paths"]
    assert client.get("/docs").status_code == 200

    # 既有接口行为不变
    assert client.get("/health").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert resp.json()["rules"][0]["status"] == "full"
    assert client.post(
        "/cidrs/hierarchy",
        json={"entries": [{"id": "a", "cidr": "10.0.0.0/8"}]},
    ).status_code == 200
