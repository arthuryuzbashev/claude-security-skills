#!/usr/bin/env python3
"""Lint Sigma detection rules (YAML or JSON) before they go into a SIEM.

Checks required fields (title, id as UUID, status, logsource, detection,
condition), valid status and level values, that the condition only names
selections that exist, ATT&CK tags (format, current v20.1 tactic names,
revoked or deprecated technique IDs), known value modifiers and their
values (all, i/m/s, numeric, time, cidr, exists), related types, date format,
falsepositives and duplicate ids across files. Sigma 2 correlation rules
(`correlation:`) and filter rules (`filter:`) are linted with their own
checks.

Ships its own small YAML reader that covers what Sigma rules use (mappings,
lists, lists of mappings, quoted and block scalars, inline [a, b] lists).

Usage:
  sigma_lint.py rules/
  sigma_lint.py rule.yml other.yml --json
  sigma_lint.py rules/ --fail-on medium
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
# ATT&CK Enterprise v20.1 tactic shortnames. v19 renamed TA0005 to Stealth and added
# TA0112 Defense Impairment; "defense-evasion" is the legacy name (SIG-033).
TACTIC_TAGS = {"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
               "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
               "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"}
LEGACY_TACTIC_TAGS = {"defense-evasion"}
# Value modifiers from the Sigma specification v2.1.0 modifiers appendix.
NUMERIC_MODIFIERS = {"gt", "gte", "lt", "lte"}
TIME_MODIFIERS = {"minute": (0, 59), "hour": (0, 23), "day": (1, 31), "week": (1, 52), "month": (1, 12),
                  "year": (1, 9999)}
REGEX_FLAGS = {"i", "m", "s"}
MODIFIERS = {"contains", "startswith", "endswith", "all", "base64", "base64offset", "re", "i", "m", "s",
             "windash", "cidr", "wide", "utf16le", "utf16be", "utf16", "exists", "expand", "fieldref",
             "gt", "gte", "lt", "lte", "cased", "neq"} | set(TIME_MODIFIERS)
RELATED_TYPES = {"derived", "obsolete", "merged", "renamed", "similar"}
CORRELATION_TYPES = {"event_count", "value_count", "temporal", "temporal_ordered",
                     "value_sum", "value_avg", "value_percentile"}
CORRELATION_FIELD_TYPES = {"value_count", "value_sum", "value_avg", "value_percentile"}
CORRELATION_OPS = {"gt", "gte", "lt", "lte", "eq", "neq"}
TIMESPAN_RE = re.compile(r"^\d+[smhd]$")
ATTACK_VERSION = "20.1"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
CONDITION_WORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}


# ATT&CK Enterprise v20.1 technique data for tag checks: every live technique ID,
# revoked ID -> current ID (chains followed), and deprecated IDs.
ATTACK_IDS = frozenset((
    "T1001 T1001.001 T1001.002 T1001.003 T1003 T1003.001 T1003.002 T1003.003 T1003.004 T1003.005 "
    "T1003.006 T1003.007 T1003.008 T1005 T1006 T1007 T1008 T1010 T1011 T1011.001 T1012 T1014 T1016 "
    "T1016.001 T1016.002 T1018 T1020 T1020.001 T1021 T1021.001 T1021.002 T1021.003 T1021.004 T1021.005 "
    "T1021.006 T1021.007 T1021.008 T1025 T1027 T1027.001 T1027.002 T1027.003 T1027.004 T1027.005 "
    "T1027.006 T1027.007 T1027.008 T1027.009 T1027.010 T1027.011 T1027.012 T1027.013 T1027.014 T1027.015 "
    "T1027.016 T1027.017 T1027.018 T1029 T1030 T1033 T1036 T1036.001 T1036.002 T1036.003 T1036.004 "
    "T1036.005 T1036.006 T1036.007 T1036.008 T1036.009 T1036.010 T1036.011 T1036.012 T1037 T1037.001 "
    "T1037.002 T1037.003 T1037.004 T1037.005 T1039 T1040 T1041 T1046 T1047 T1048 T1048.001 T1048.002 "
    "T1048.003 T1049 T1052 T1052.001 T1053 T1053.002 T1053.003 T1053.005 T1053.006 T1053.007 T1055 "
    "T1055.001 T1055.002 T1055.003 T1055.004 T1055.005 T1055.008 T1055.009 T1055.011 T1055.012 T1055.013 "
    "T1055.014 T1055.015 T1056 T1056.001 T1056.002 T1056.003 T1056.004 T1057 T1059 T1059.001 T1059.002 "
    "T1059.003 T1059.004 T1059.005 T1059.006 T1059.007 T1059.008 T1059.009 T1059.010 T1059.011 T1059.012 "
    "T1059.013 T1068 T1069 T1069.001 T1069.002 T1069.003 T1070 T1070.003 T1070.004 T1070.005 T1070.006 "
    "T1070.007 T1070.008 T1070.009 T1070.010 T1071 T1071.001 T1071.002 T1071.003 T1071.004 T1071.005 "
    "T1072 T1074 T1074.001 T1074.002 T1078 T1078.001 T1078.002 T1078.003 T1078.004 T1080 T1082 T1083 "
    "T1087 T1087.001 T1087.002 T1087.003 T1087.004 T1090 T1090.001 T1090.002 T1090.003 T1090.004 T1091 "
    "T1092 T1095 T1098 T1098.001 T1098.002 T1098.003 T1098.004 T1098.005 T1098.006 T1098.007 T1102 "
    "T1102.001 T1102.002 T1102.003 T1104 T1105 T1106 T1110 T1110.001 T1110.002 T1110.003 T1110.004 T1111 "
    "T1112 T1113 T1114 T1114.001 T1114.002 T1114.003 T1115 T1119 T1120 T1123 T1124 T1125 T1127 T1127.001 "
    "T1127.002 T1127.003 T1129 T1132 T1132.001 T1132.002 T1133 T1134 T1134.001 T1134.002 T1134.003 "
    "T1134.004 T1134.005 T1135 T1136 T1136.001 T1136.002 T1136.003 T1137 T1137.001 T1137.002 T1137.003 "
    "T1137.004 T1137.005 T1137.006 T1140 T1176 T1176.001 T1176.002 T1185 T1187 T1189 T1190 T1195 "
    "T1195.001 T1195.002 T1195.003 T1197 T1199 T1200 T1201 T1202 T1203 T1204 T1204.001 T1204.002 "
    "T1204.003 T1204.004 T1204.005 T1205 T1205.001 T1205.002 T1207 T1210 T1211 T1212 T1213 T1213.001 "
    "T1213.002 T1213.003 T1213.004 T1213.005 T1213.006 T1216 T1216.001 T1216.002 T1217 T1218 T1218.001 "
    "T1218.002 T1218.003 T1218.004 T1218.005 T1218.007 T1218.008 T1218.009 T1218.010 T1218.011 T1218.012 "
    "T1218.013 T1218.014 T1218.015 T1219 T1219.001 T1219.002 T1219.003 T1220 T1221 T1222 T1222.001 "
    "T1222.002 T1480 T1480.001 T1480.002 T1482 T1484 T1484.001 T1484.002 T1485 T1485.001 T1486 T1489 "
    "T1490 T1491 T1491.001 T1491.002 T1495 T1496 T1496.001 T1496.002 T1496.003 T1496.004 T1497 T1497.001 "
    "T1497.002 T1497.003 T1498 T1498.001 T1498.002 T1499 T1499.001 T1499.002 T1499.003 T1499.004 T1505 "
    "T1505.001 T1505.002 T1505.003 T1505.004 T1505.005 T1505.006 T1518 T1518.001 T1518.002 T1525 T1526 "
    "T1528 T1529 T1530 T1531 T1534 T1535 T1537 T1538 T1539 T1542 T1542.001 T1542.002 T1542.003 T1542.004 "
    "T1542.005 T1543 T1543.001 T1543.002 T1543.003 T1543.004 T1543.005 T1546 T1546.001 T1546.002 "
    "T1546.003 T1546.004 T1546.005 T1546.006 T1546.007 T1546.008 T1546.009 T1546.010 T1546.011 T1546.012 "
    "T1546.013 T1546.014 T1546.015 T1546.016 T1546.017 T1546.018 T1547 T1547.001 T1547.002 T1547.003 "
    "T1547.004 T1547.005 T1547.006 T1547.007 T1547.008 T1547.009 T1547.010 T1547.012 T1547.013 T1547.014 "
    "T1547.015 T1548 T1548.001 T1548.002 T1548.003 T1548.004 T1548.005 T1548.006 T1550 T1550.001 "
    "T1550.002 T1550.003 T1550.004 T1552 T1552.001 T1552.002 T1552.003 T1552.004 T1552.005 T1552.006 "
    "T1552.007 T1552.008 T1553 T1553.001 T1553.002 T1553.003 T1553.004 T1553.005 T1553.006 T1554 T1555 "
    "T1555.001 T1555.002 T1555.003 T1555.004 T1555.005 T1555.006 T1556 T1556.001 T1556.002 T1556.003 "
    "T1556.004 T1556.005 T1556.006 T1556.007 T1556.008 T1556.009 T1557 T1557.001 T1557.002 T1557.003 "
    "T1557.004 T1558 T1558.001 T1558.002 T1558.003 T1558.004 T1558.005 T1559 T1559.001 T1559.002 "
    "T1559.003 T1560 T1560.001 T1560.002 T1560.003 T1561 T1561.001 T1561.002 T1563 T1563.001 T1563.002 "
    "T1564 T1564.001 T1564.002 T1564.003 T1564.004 T1564.005 T1564.006 T1564.007 T1564.008 T1564.009 "
    "T1564.010 T1564.011 T1564.012 T1564.013 T1564.014 T1565 T1565.001 T1565.002 T1565.003 T1566 "
    "T1566.001 T1566.002 T1566.003 T1566.004 T1567 T1567.001 T1567.002 T1567.003 T1567.004 T1568 "
    "T1568.001 T1568.002 T1568.003 T1569 T1569.001 T1569.002 T1569.003 T1570 T1571 T1572 T1573 T1573.001 "
    "T1573.002 T1574 T1574.001 T1574.004 T1574.005 T1574.006 T1574.007 T1574.008 T1574.009 T1574.010 "
    "T1574.011 T1574.012 T1574.013 T1574.014 T1578 T1578.001 T1578.002 T1578.003 T1578.004 T1578.005 "
    "T1580 T1583 T1583.001 T1583.002 T1583.003 T1583.004 T1583.005 T1583.006 T1583.007 T1583.008 T1584 "
    "T1584.001 T1584.002 T1584.003 T1584.004 T1584.005 T1584.006 T1584.007 T1584.008 T1585 T1585.001 "
    "T1585.002 T1585.003 T1586 T1586.001 T1586.002 T1586.003 T1587 T1587.001 T1587.002 T1587.003 "
    "T1587.004 T1588 T1588.001 T1588.002 T1588.003 T1588.004 T1588.005 T1588.006 T1588.007 T1589 "
    "T1589.001 T1589.002 T1589.003 T1590 T1590.001 T1590.002 T1590.003 T1590.004 T1590.005 T1590.006 "
    "T1591 T1591.001 T1591.002 T1591.003 T1591.004 T1592 T1592.001 T1592.002 T1592.003 T1592.004 T1593 "
    "T1593.001 T1593.002 T1593.003 T1594 T1595 T1595.001 T1595.002 T1595.003 T1596 T1596.001 T1596.002 "
    "T1596.003 T1596.004 T1596.005 T1597 T1597.001 T1597.002 T1598 T1598.001 T1598.002 T1598.003 "
    "T1598.004 T1599 T1599.001 T1600 T1600.001 T1600.002 T1601 T1601.001 T1601.002 T1602 T1602.001 "
    "T1602.002 T1606 T1606.001 T1606.002 T1608 T1608.001 T1608.002 T1608.003 T1608.004 T1608.005 "
    "T1608.006 T1608.007 T1609 T1610 T1611 T1612 T1613 T1614 T1614.001 T1615 T1619 T1620 T1621 T1622 "
    "T1647 T1648 T1649 T1650 T1651 T1652 T1653 T1654 T1657 T1659 T1665 T1666 T1667 T1668 T1669 T1671 "
    "T1673 T1674 T1675 T1677 T1678 T1679 T1680 T1681 T1682 T1683 T1683.001 T1683.002 T1684 T1684.001 "
    "T1684.002 T1685 T1685.001 T1685.002 T1685.003 T1685.004 T1685.005 T1685.006 T1685.007 T1686 "
    "T1686.001 T1686.002 T1686.003 T1687 T1688 T1689 T1690 T1696 T1696.001 T1696.002 T1697 T1698 T1699 "
    "T1700 "
).split())
REVOKED = {
    "T1002": "T1560", "T1004": "T1547.004", "T1009": "T1027.001", "T1013": "T1547.010", "T1015": "T1546.008",
    "T1017": "T1072", "T1019": "T1542.001", "T1022": "T1560", "T1023": "T1547.009", "T1024": "T1573", "T1028":
    "T1021.006", "T1031": "T1543.003", "T1032": "T1573", "T1035": "T1569.002", "T1038": "T1574.001", "T1042":
    "T1546.001", "T1044": "T1574.010", "T1045": "T1027.002", "T1050": "T1543.003", "T1053.001": "T1053.002",
    "T1054": "T1685", "T1058": "T1574.011", "T1060": "T1547.001", "T1063": "T1518.001", "T1065": "T1571",
    "T1066": "T1027.005", "T1067": "T1542.003", "T1070.001": "T1685.005", "T1070.002": "T1685.006", "T1073":
    "T1574.001", "T1075": "T1550.002", "T1076": "T1021.001", "T1077": "T1021.002", "T1079": "T1573", "T1081":
    "T1552.001", "T1084": "T1546.003", "T1085": "T1218.011", "T1086": "T1059.001", "T1088": "T1548.002",
    "T1089": "T1685", "T1093": "T1055.012", "T1094": "T1095", "T1096": "T1564.004", "T1097": "T1550.003",
    "T1099": "T1070.006", "T1100": "T1505.003", "T1101": "T1547.005", "T1103": "T1546.010", "T1107":
    "T1070.004", "T1109": "T1542.002", "T1116": "T1553.002", "T1117": "T1218.010", "T1118": "T1218.004",
    "T1121": "T1218.009", "T1122": "T1546.015", "T1126": "T1070.005", "T1128": "T1546.007", "T1130":
    "T1553.004", "T1131": "T1547.002", "T1138": "T1546.011", "T1139": "T1552.003", "T1141": "T1056.002",
    "T1142": "T1555.001", "T1143": "T1564.003", "T1144": "T1553.001", "T1145": "T1552.004", "T1146":
    "T1070.003", "T1147": "T1564.002", "T1148": "T1690", "T1150": "T1647", "T1151": "T1036.006", "T1152":
    "T1569.001", "T1154": "T1546.005", "T1155": "T1059.002", "T1156": "T1546.004", "T1157": "T1574.004",
    "T1158": "T1564.001", "T1159": "T1543.001", "T1160": "T1543.004", "T1161": "T1546.006", "T1162": "T1647",
    "T1163": "T1037.004", "T1164": "T1547.007", "T1165": "T1037.005", "T1166": "T1548.001", "T1167":
    "T1555.002", "T1168": "T1053", "T1169": "T1548.003", "T1170": "T1218.005", "T1171": "T1557.001", "T1172":
    "T1090.004", "T1173": "T1559.002", "T1174": "T1556.002", "T1177": "T1547.008", "T1178": "T1134.005",
    "T1179": "T1056.004", "T1180": "T1546.002", "T1181": "T1055.011", "T1182": "T1546.009", "T1183":
    "T1546.012", "T1184": "T1563.001", "T1186": "T1055.013", "T1188": "T1090.003", "T1191": "T1218.003",
    "T1192": "T1566.002", "T1193": "T1566.001", "T1194": "T1566.003", "T1196": "T1218.002", "T1198":
    "T1553.003", "T1206": "T1548.003", "T1208": "T1558.003", "T1209": "T1547.003", "T1214": "T1552.002",
    "T1215": "T1547.006", "T1223": "T1218.001", "T1483": "T1568.002", "T1487": "T1561.002", "T1488":
    "T1561.001", "T1492": "T1565.001", "T1493": "T1565.002", "T1494": "T1565.003", "T1500": "T1027.004",
    "T1501": "T1543.002", "T1502": "T1134.004", "T1503": "T1555.003", "T1504": "T1546.013", "T1506":
    "T1550.004", "T1514": "T1548.004", "T1519": "T1546.014", "T1522": "T1552.005", "T1527": "T1550.001",
    "T1536": "T1578.004", "T1547.011": "T1647", "T1562": "T1685", "T1562.001": "T1685", "T1562.002":
    "T1685.001", "T1562.003": "T1690", "T1562.004": "T1686", "T1562.006": "T1685", "T1562.007": "T1686.001",
    "T1562.008": "T1685.002", "T1562.009": "T1688", "T1562.010": "T1689", "T1562.011": "T1685.003", "T1562.012":
    "T1685.004", "T1562.013": "T1686.002", "T1574.002": "T1574.001", "T1656": "T1684.001", "T1672": "T1684.002",
}
DEPRECATED = frozenset(['T1026', 'T1034', 'T1043', 'T1051', 'T1053.004', 'T1061', 'T1062', 'T1064', 'T1108', 'T1149', 'T1153', 'T1175'])


class YamlError(ValueError):
    pass


# ---------------------------------------------------------------- tiny YAML reader

def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(text: str) -> Any:
    t = text.strip()
    if t == "" or t in ("~", "null", "Null", "NULL"):
        return None
    if len(t) >= 2 and t[0] == t[-1] == "'":
        return t[1:-1].replace("''", "'")
    if len(t) >= 2 and t[0] == t[-1] == '"':
        try:
            return json.loads(t)
        except json.JSONDecodeError:
            return t[1:-1]
    if t.startswith("[") and t.endswith("]"):
        return [_scalar(p) for p in _split_flow(t[1:-1])] if t[1:-1].strip() else []
    if t.startswith("{") and t.endswith("}"):
        out = {}
        for p in _split_flow(t[1:-1]):
            k, _, v = p.partition(":")
            out[str(_scalar(k))] = _scalar(v)
        return out
    if t in ("true", "True", "TRUE"):
        return True
    if t in ("false", "False", "FALSE"):
        return False
    if re.fullmatch(r"-?\d+", t):
        return int(t)
    if re.fullmatch(r"-?\d+\.\d+", t):
        return float(t)
    return t


def _split_flow(s: str) -> List[str]:
    parts, buf, depth, quote = [], [], 0, None
    for c in s:
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            continue
        if c in "'\"":
            quote = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append("".join(buf).strip())
            buf = []
            continue
        buf.append(c)
    if "".join(buf).strip():
        parts.append("".join(buf).strip())
    return parts


def _split_key(content: str):
    """Return (key, rest) if the line is `key: value` / `key:`, else None."""
    quote = None
    for i, c in enumerate(content):
        if quote:
            if c == quote:
                quote = None
            continue
        if c in "'\"" and i == 0:
            quote = c
        elif c == ":" and (i + 1 == len(content) or content[i + 1] in " \t"):
            key = content[:i].strip()
            if key[:1] in "'\"" and key[-1:] == key[:1]:
                key = key[1:-1]
            return key, content[i + 1:].strip()
    return None


class _Lines:
    def __init__(self, text: str):
        self.items = []  # (indent, content, raw, lineno)
        for no, raw in enumerate(text.splitlines(), 1):
            if "\t" in raw[:len(raw) - len(raw.lstrip())]:
                raise YamlError(f"line {no}: tabs are not allowed for indentation")
            content = _strip_comment(raw)
            if not content.strip():
                self.items.append((None, "", raw, no))
                continue
            self.items.append((len(content) - len(content.lstrip()), content.strip(), raw, no))
        self.pos = 0

    def skip_blank(self):
        while self.pos < len(self.items) and self.items[self.pos][0] is None:
            self.pos += 1

    def peek(self):
        self.skip_blank()
        return self.items[self.pos] if self.pos < len(self.items) else None


def _parse_block(lines: _Lines, indent: int):
    first = lines.peek()
    if first is None:
        return None
    if first[1] == "-" or first[1].startswith("- "):
        return _parse_list(lines, first[0])
    return _parse_map(lines, first[0])


def _block_scalar(lines: _Lines, parent_indent: int, style: str) -> str:
    collected, block_indent = [], None
    while lines.pos < len(lines.items):
        ind, content, raw, _ = lines.items[lines.pos]
        if raw.strip() == "":
            collected.append("")
            lines.pos += 1
            continue
        raw_ind = len(raw) - len(raw.lstrip())
        if raw_ind <= parent_indent:
            break
        if block_indent is None:
            block_indent = raw_ind
        collected.append(raw[block_indent:])
        lines.pos += 1
    while collected and collected[-1] == "":
        collected.pop()
    if style.startswith(">"):
        return " ".join(c.strip() for c in collected if c.strip())
    return "\n".join(collected)


def _value_after_key(lines: _Lines, indent: int, rest: str):
    if rest in ("|", "|-", "|+", ">", ">-", ">+"):
        return _block_scalar(lines, indent, rest)
    if rest:
        return _scalar(rest)
    nxt = lines.peek()
    if nxt is None:
        return None
    if nxt[0] > indent or (nxt[0] == indent and (nxt[1] == "-" or nxt[1].startswith("- "))):
        return _parse_block(lines, nxt[0])
    return None


def _parse_map(lines: _Lines, indent: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    while True:
        item = lines.peek()
        if item is None or item[0] < indent:
            return out
        ind, content, _, no = item
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        if content == "-" or content.startswith("- "):
            return out  # a sibling list at the same indent ends this map (handled by caller)
        kv = _split_key(content)
        if kv is None:
            raise YamlError(f"line {no}: expected 'key: value', got '{content[:40]}'")
        key, rest = kv
        lines.pos += 1
        if key in out:
            raise YamlError(f"line {no}: duplicate key '{key}'")
        out[key] = _value_after_key(lines, indent, rest)


def _parse_list(lines: _Lines, indent: int) -> List[Any]:
    out: List[Any] = []
    while True:
        item = lines.peek()
        if item is None or item[0] < indent:
            return out
        ind, content, raw, no = item
        if ind > indent:
            raise YamlError(f"line {no}: unexpected indentation")
        if not (content == "-" or content.startswith("- ")):
            return out
        rest = content[1:].lstrip()
        if not rest:
            lines.pos += 1
            nxt = lines.peek()
            out.append(_parse_block(lines, nxt[0]) if nxt and nxt[0] > indent else None)
            continue
        kv = _split_key(rest) if not rest.startswith(("'", '"', "[", "{")) else None
        if kv is None and rest[:1] in "'\"":
            # a quoted key is still a mapping item: - 'a': b
            kv2 = _split_key(rest)
            kv = kv2 if kv2 and not _scalar_like(rest) else None
        if kv is None:
            lines.pos += 1
            out.append(_scalar(rest))
            continue
        # mapping inside a list item: rewrite this line as if the key started a block
        child_indent = indent + (len(content) - len(rest))
        lines.items[lines.pos] = (child_indent, rest, raw, no)
        out.append(_parse_map(lines, child_indent))


def _scalar_like(s: str) -> bool:
    s = s.strip()
    return len(s) >= 2 and s[0] in "'\"" and s[-1] == s[0]


def load_yaml_docs(text: str) -> List[Any]:
    """Parse a YAML stream (documents split by ---) into Python objects."""
    docs, chunk = [], []
    for line in text.splitlines():
        if line.strip() == "---" or line.startswith("--- "):
            if any(l.strip() and not l.strip().startswith("#") for l in chunk):
                docs.append("\n".join(chunk))
            chunk = []
        elif line.strip() == "...":
            continue
        else:
            chunk.append(line)
    if any(l.strip() and not l.strip().startswith("#") for l in chunk):
        docs.append("\n".join(chunk))
    out = []
    for d in docs:
        lines = _Lines(d)
        first = lines.peek()
        val = _parse_block(lines, first[0] if first else 0)
        rest = lines.peek()
        if rest is not None:
            raise YamlError(f"line {rest[3]}: could not parse '{rest[1][:40]}'")
        out.append(val)
    return out


def load_rules(path: str) -> List[Any]:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.lower().endswith(".json") or text.lstrip().startswith(("{", "[")):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    return load_yaml_docs(text)


# ---------------------------------------------------------------- lint

def finding(fid, severity, title, detail, fix, location=None):
    f = {"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix}
    if location:
        f["location"] = location
    return f


def condition_identifiers(condition: str) -> Tuple[List[str], List[str]]:
    """Return (plain identifiers, 'x of pattern' patterns) used in a condition."""
    cond = condition.split("|", 1)[0]
    patterns = re.findall(r"\b(?:\d+|all|any)\s+of\s+([\w*]+)", cond)
    cleaned = re.sub(r"\b(?:\d+|all|any)\s+of\s+[\w*]+", " ", cond)
    names = [t for t in re.findall(r"[\w*]+", cleaned) if t.lower() not in CONDITION_WORDS]
    return names, patterns


def _pattern_re(p: str):
    return re.compile("^" + re.escape(p).replace(r"\*", ".*") + "$")


def lint_rule(rule: Any, where: str = "") -> List[Dict]:
    out = []
    loc = where or None
    if not isinstance(rule, dict):
        return [finding("SIG-000", "high", "Not a Sigma rule", "The document is not a mapping of fields.", "Start from a Sigma rule template.", loc)]
    if rule.get("action") in ("global", "reset", "repeat"):
        return [finding("SIG-099", "info", "Rule collection action document skipped",
                        f"action: {rule.get('action')} documents are merged into the following rules by Sigma tooling and are not linted alone.",
                        "Prefer one rule per file; collections are deprecated in Sigma 2.", loc)]
    kind = "correlation" if "correlation" in rule else "filter" if "filter" in rule and "detection" not in rule else "rule"
    title = rule.get("title")
    if not title:
        out.append(finding("SIG-001", "high", "title missing", "Every Sigma rule needs a title.", "Add `title:` with a short description of what is detected.", loc))
    elif len(str(title)) > 256:
        out.append(finding("SIG-004", "low", "title too long", f"{len(str(title))} characters; Sigma recommends a short title.", "Keep the title under 256 characters and move detail into description.", loc))
    rid = rule.get("id")
    if rid is None and kind == "filter":
        out.append(finding("SIG-002", "info", "filter has no id", "id is optional for filters but helps track changes.", "Add `id:` with a random UUID.", loc))
    elif rid is None:
        out.append(finding("SIG-002", "medium", "id missing", "Without a stable id, rules cannot be tracked across versions or deduplicated.", "Add `id:` with a random UUID (python3 -c 'import uuid; print(uuid.uuid4())').", loc))
    elif not UUID_RE.match(str(rid)):
        out.append(finding("SIG-002", "medium", "id is not a UUID", f"id '{rid}' is not in UUID format.", "Use a random UUID version 4.", loc))
    status = rule.get("status")
    if kind == "filter":
        pass  # filters have no status or level in the spec
    elif status is None:
        out.append(finding("SIG-010", "medium", "status missing", "Consumers use status to decide whether to deploy the rule.", "Add `status:` (experimental, test or stable).", loc))
    elif str(status) not in STATUSES:
        out.append(finding("SIG-010", "medium", "invalid status", f"'{status}' is not one of {', '.join(sorted(STATUSES))}.", "Use a valid status value.", loc))
    level = rule.get("level")
    if kind == "filter":
        pass
    elif level is None:
        out.append(finding("SIG-011", "low", "level missing", "Without a level the SIEM cannot prioritise alerts.", "Add `level:` (informational, low, medium, high, critical).", loc))
    elif str(level) not in LEVELS:
        out.append(finding("SIG-011", "medium", "invalid level", f"'{level}' is not one of {', '.join(sorted(LEVELS))}.", "Use a valid level value.", loc))
    if not rule.get("description"):
        out.append(finding("SIG-012", "info", "description missing", "Analysts triaging the alert need to know what it means.", "Add a one or two sentence `description:`.", loc))

    out += lint_related(rule.get("related"), loc)
    if kind == "correlation":
        out += lint_correlation(rule.get("correlation"), loc)
        if "detection" in rule or "logsource" in rule:
            out.append(finding("SIG-087", "low", "correlation rule also has detection or logsource",
                               "A correlation rule takes its events from the rules it lists; tools ignore detection and logsource here.",
                               "Move the detection into its own rule and list that rule under correlation.rules.", loc))
        out += lint_tags_and_meta(rule, loc)
        return out

    ls = rule.get("logsource")
    if not isinstance(ls, dict):
        out.append(finding("SIG-060", "high", "logsource missing", "Sigma needs logsource to know which logs the rule applies to.", "Add `logsource:` with category/product/service.", loc))
    elif not any(k in ls for k in ("category", "product", "service")):
        out.append(finding("SIG-060", "high", "logsource has no category, product or service", f"logsource keys: {', '.join(ls) or 'none'}.", "Set at least one of category, product, service.", loc))

    if kind == "filter":
        flt = rule.get("filter")
        if not isinstance(flt, dict):
            out.append(finding("SIG-090", "high", "filter block is not a mapping", "filter needs rules, a selection and a condition.", "Write `filter:` with `rules:`, `selection:` and `condition:`.", loc))
            return out
        refs = flt.get("rules")
        if not refs or not isinstance(refs, (list, str)):
            out.append(finding("SIG-090", "high", "filter has no rules to apply to", "filter.rules is mandatory: the ids or names of the rules this filter is added to.", "List the target rule ids under `filter: rules:`.", loc))
        out += lint_detection({k: v for k, v in flt.items() if k != "rules"}, loc)
        for key in ("date", "modified"):
            out += _lint_date(rule, key, loc)
        return out

    det = rule.get("detection")
    if not isinstance(det, dict):
        out.append(finding("SIG-020", "high", "detection missing", "The rule has no detection block.", "Add `detection:` with selections and a condition.", loc))
    else:
        out += lint_detection(det, loc)
    out += lint_tags_and_meta(rule, loc)
    return out


def lint_tags_and_meta(rule: Dict, loc) -> List[Dict]:
    out = []
    tags = rule.get("tags") or []
    if not isinstance(tags, list):
        out.append(finding("SIG-030", "low", "tags is not a list", "tags must be a YAML list.", "Write tags as a list of strings.", loc))
        tags = []
    has_attack = False
    for t in tags:
        t = str(t)
        if t.lower().startswith("attack."):
            has_attack = True
            body = t[len("attack."):]
            ok = (re.fullmatch(r"t\d{4}(\.\d{3})?", body) or re.fullmatch(r"[gs]\d{4}", body) or body in TACTIC_TAGS)
            if body in LEGACY_TACTIC_TAGS:
                out.append(finding("SIG-033", "low", f"legacy ATT&CK tactic tag '{t}'",
                                   "ATT&CK v19 renamed TA0005 Defense Evasion to Stealth and moved the techniques that switch defenses off to TA0112 Defense Impairment. pySigma validates tags against current ATT&CK.",
                                   "Use attack.stealth for hiding techniques (T1027, T1036, T1218, T1070...) or attack.defense-impairment for disabling defenses (T1685, T1686, T1112, T1556...).", loc))
                continue
            if ok and body.startswith("t"):
                out += _lint_technique_tag(t, body.upper(), loc)
                continue
            if not ok:
                hint = "lowercase, e.g. attack.t1059.001" if body.lower() != body else "use attack.tNNNN[.NNN], attack.gNNNN, attack.sNNNN or a tactic name like attack.execution"
                out.append(finding("SIG-030", "low", f"bad ATT&CK tag '{t}'", "Sigma ATT&CK tags are lowercase with dots.", hint, loc))
        elif not re.fullmatch(r"[a-z0-9_-]+\.[a-z0-9._-]+", t):
            out.append(finding("SIG-031", "low", f"tag '{t}' does not follow namespace.value", "Sigma tags look like attack.execution, cve.2021-44228, car.2016-04-005, detection.threat-hunting.", "Lowercase and use a namespace prefix.", loc))
    if not has_attack:
        out.append(finding("SIG-032", "info", "no ATT&CK tags", "Tags let you measure coverage per technique.", "Add attack.<tactic> and attack.tNNNN tags.", loc))

    fps = rule.get("falsepositives")
    if not fps:
        out.append(finding("SIG-040", "low", "falsepositives missing", "Triage is faster when known benign causes are listed.", "Add `falsepositives:` (use 'Unknown' if you truly have none).", loc))

    for key in ("date", "modified"):
        out += _lint_date(rule, key, loc)
    return out


def _lint_date(rule: Dict, key: str, loc) -> List[Dict]:
    v = rule.get(key)
    if v is None:
        if key == "date":
            return [finding("SIG-050", "info", "date missing", "The creation date helps age and review rules.", "Add `date: YYYY-MM-DD`.", loc)]
        return []
    v = str(v)
    if re.fullmatch(r"\d{4}/\d{2}/\d{2}", v):
        return [finding("SIG-050", "low", f"{key} uses the old YYYY/MM/DD format", f"{key}: {v}", "Use ISO 8601 YYYY-MM-DD.", loc)]
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])", v):
        return [finding("SIG-050", "medium", f"{key} is not a valid date", f"{key}: {v}", "Use ISO 8601 YYYY-MM-DD.", loc)]
    return []


def _lint_technique_tag(tag: str, tid: str, loc) -> List[Dict]:
    if tid in REVOKED:
        return [finding("SIG-034", "medium", f"ATT&CK tag '{tag}' names a revoked technique",
                        f"{tid} was revoked in ATT&CK; the current technique is {REVOKED[tid]}. pySigma and coverage tools no longer accept the old ID.",
                        f"Replace it with attack.{REVOKED[tid].lower()} and check the tactic tags still fit.", loc)]
    if tid in DEPRECATED:
        return [finding("SIG-034", "medium", f"ATT&CK tag '{tag}' names a deprecated technique",
                        f"{tid} is deprecated in ATT&CK with no replacement.",
                        "Map the behaviour to a current technique on attack.mitre.org.", loc)]
    if tid not in ATTACK_IDS:
        return [finding("SIG-035", "low", f"ATT&CK tag '{tag}' is not a known technique",
                        f"{tid} is not in ATT&CK Enterprise v{ATTACK_VERSION} (typo, or a newer release than this linter knows).",
                        "Check the ID on attack.mitre.org.", loc)]
    return []


def lint_related(related: Any, loc) -> List[Dict]:
    if related is None:
        return []
    if not isinstance(related, list):
        return [finding("SIG-013", "low", "related is not a list", "related must be a list of {id, type} entries.", "Write related as a list.", loc)]
    out = []
    for item in related:
        if not isinstance(item, dict):
            out.append(finding("SIG-013", "low", "related entry is not a mapping", repr(item)[:80], "Use `- id: <uuid>` and `type: <derived|obsolete|merged|renamed|similar>`.", loc))
            continue
        rtype = item.get("type")
        if str(rtype) not in RELATED_TYPES:
            out.append(finding("SIG-013", "low", f"invalid related type '{rtype}'", f"Allowed: {', '.join(sorted(RELATED_TYPES))}.", "Use one of the allowed relation types.", loc))
        if not item.get("id"):
            out.append(finding("SIG-013", "low", "related entry has no id", repr(item)[:80], "Add the id of the related rule.", loc))
    return out


def lint_correlation(corr: Any, loc) -> List[Dict]:
    """Checks for a Sigma 2 correlation rule (`correlation:` block)."""
    if not isinstance(corr, dict):
        return [finding("SIG-080", "high", "correlation block is not a mapping", "correlation needs type, rules, timespan and usually group-by and condition.", "Write `correlation:` as a mapping.", loc)]
    out = []
    ctype = corr.get("type")
    if ctype is None:
        out.append(finding("SIG-080", "high", "correlation type missing", "Without a type the correlation cannot be converted.", f"Set `type:` to one of {', '.join(sorted(CORRELATION_TYPES))}.", loc))
    elif str(ctype) not in CORRELATION_TYPES:
        out.append(finding("SIG-080", "high", f"invalid correlation type '{ctype}'", f"Allowed: {', '.join(sorted(CORRELATION_TYPES))}.", "Use a type from the Sigma correlation specification.", loc))
    refs = corr.get("rules")
    if isinstance(refs, str):
        refs = [refs]
    if not refs or not isinstance(refs, list):
        out.append(finding("SIG-081", "high", "correlation has no rules", "correlation.rules is mandatory: the ids or names of the rules whose events are correlated.", "List the base rules under `rules:`.", loc))
        refs = []
    elif str(ctype) in ("temporal", "temporal_ordered") and len(refs) < 2:
        out.append(finding("SIG-086", "medium", f"{ctype} correlation with only one rule", "Temporal correlations look for events from several different rules; with one rule it never means more than that rule.", "List two or more rules, or use event_count.", loc))
    span = corr.get("timespan")
    if span is None:
        out.append(finding("SIG-082", "high", "correlation timespan missing", "timespan is mandatory: the window the events must fall in.", "Add `timespan:` like 10m, 1h or 1d.", loc))
    elif not TIMESPAN_RE.match(str(span)):
        out.append(finding("SIG-082", "high", f"invalid timespan '{span}'", "The format is a number plus one lowercase letter: s, m, h or d (90m, not 1h30m or 1H).", "Rewrite it as one number and unit, e.g. 90m.", loc))
    gb = corr.get("group-by")
    if gb is None:
        out.append(finding("SIG-085", "low", "correlation group-by missing", "The specification marks group-by as mandatory; without it every event in the window is counted together (one noisy host hides the rest).", "Add `group-by:` with the fields to count per, e.g. User or ComputerName.", loc))
    elif not isinstance(gb, list):
        out.append(finding("SIG-085", "low", "group-by is not a list", f"group-by: {gb}", "Write group-by as a list of field names.", loc))
    cond = corr.get("condition")
    needs_cond = str(ctype) not in ("temporal", "temporal_ordered")
    if cond is None:
        if needs_cond and ctype is not None:
            out.append(finding("SIG-083", "high", "correlation condition missing", f"A {ctype} correlation needs a threshold such as `gte: 10`.", "Add `condition:` with gt, gte, lt, lte, eq or neq.", loc))
    elif not isinstance(cond, dict):
        out.append(finding("SIG-083", "high", "correlation condition is not a mapping", f"condition: {cond}", "Use a mapping like `condition: {gte: 10}`.", loc))
    else:
        ops = [k for k in cond if k != "field"]
        bad = [k for k in ops if k not in CORRELATION_OPS]
        if bad:
            out.append(finding("SIG-083", "high", f"unknown condition operator(s): {', '.join(map(str, bad))}", f"Allowed: {', '.join(sorted(CORRELATION_OPS))} (plus field).", "Fix the operator name.", loc))
        if not ops:
            out.append(finding("SIG-083", "high", "correlation condition has no operator", f"condition: {cond}", "Add one operator, e.g. `gte: 10` (two for a range: gt and lte).", loc))
        elif len(ops) > 2:
            out.append(finding("SIG-083", "medium", "correlation condition has more than two operators", f"condition: {cond}", "Use one operator, or two for a range; chain correlations for anything more complex.", loc))
        for k in ops:
            v = cond.get(k)
            if k in CORRELATION_OPS and (isinstance(v, bool) or not isinstance(v, (int, float))):
                out.append(finding("SIG-083", "high", f"condition {k} is not a number", f"{k}: {v!r}", "Use a number for the threshold.", loc))
        if str(ctype) in CORRELATION_FIELD_TYPES and not cond.get("field"):
            out.append(finding("SIG-084", "high", f"{ctype} correlation needs condition.field", "value_count, value_sum, value_avg and value_percentile aggregate one field.", "Add `field:` under condition, e.g. `field: TargetUserName`.", loc))
    aliases = corr.get("aliases")
    if aliases is not None and not isinstance(aliases, dict):
        out.append(finding("SIG-085", "low", "aliases is not a mapping", f"aliases: {aliases}", "Write aliases as alias: {rule name: field}.", loc))
    return out


def _iter_field_keys(selection):
    if isinstance(selection, dict):
        yield from selection.keys()
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                yield from item.keys()


def lint_detection(det: Dict, loc) -> List[Dict]:
    out = []
    cond = det.get("condition")
    selections = {k: v for k, v in det.items() if k not in ("condition", "timeframe")}
    if cond is None:
        out.append(finding("SIG-021", "high", "condition missing", "detection has no condition, so nothing ever matches.", "Add `condition:` e.g. `selection and not filter`.", loc))
        return out
    conds = cond if isinstance(cond, list) else [cond]
    if isinstance(cond, list):
        out.append(finding("SIG-026", "low", "condition is a list", "Lists of conditions are deprecated in Sigma 2.", "Combine them with `or` into one condition.", loc))
    if not selections:
        out.append(finding("SIG-022", "high", "no selections", "detection only has a condition.", "Add at least one named selection.", loc))
    used = set()
    for c in conds:
        c = str(c)
        if c.count("(") != c.count(")"):
            out.append(finding("SIG-023", "high", "unbalanced parentheses in condition", c, "Fix the parentheses.", loc))
        if "|" in c:
            out.append(finding("SIG-027", "low", "aggregation in condition", "Pipe aggregations (| count() ...) are deprecated in Sigma 2 and many backends ignore them.", "Use a Sigma correlation rule instead.", loc))
        names, patterns = condition_identifiers(c)
        for n in names:
            if n not in selections:
                out.append(finding("SIG-020", "high", f"condition uses undefined selection '{n}'", f"condition: {c}", f"Define `{n}` under detection or fix the name.", loc))
            used.add(n)
        for p in patterns:
            if p == "them":
                used.update(selections)
                continue
            rx = _pattern_re(p)
            hits = [s for s in selections if rx.match(s)]
            if not hits:
                out.append(finding("SIG-020", "high", f"condition pattern '{p}' matches no selection", f"condition: {c}", "Rename the selections or fix the pattern.", loc))
            used.update(hits)
    for s in selections:
        if s not in used:
            out.append(finding("SIG-024", "low", f"selection '{s}' is never used", "It is defined but the condition does not reference it.", "Use it in the condition or delete it.", loc))
    for name, sel in selections.items():
        if sel is None or sel == {} or sel == []:
            out.append(finding("SIG-025", "medium", f"selection '{name}' is empty", "An empty selection matches nothing or everything depending on the backend.", "Add field conditions or remove it.", loc))
        for key, vals in _iter_field_items(sel):
            parts = str(key).split("|")
            mods = parts[1:]
            for mod in mods:
                if mod not in MODIFIERS:
                    out.append(finding("SIG-070", "medium", f"unknown modifier '{mod}' in '{key}'", f"Known: {', '.join(sorted(MODIFIERS))}.", "Fix the spelling (contains, startswith, endswith, re, all...).", loc))
            values = vals if isinstance(vals, list) else [vals]
            if "re" in mods:
                for v in values:
                    try:
                        re.compile(str(v))
                    except re.error as err:
                        out.append(finding("SIG-071", "high", f"invalid regex in '{key}'", f"{v!r}: {err}", "Fix the regular expression.", loc))
            out += _lint_modifier_values(key, mods, vals, values, loc)
    return out


def _iter_field_items(selection):
    if isinstance(selection, dict):
        yield from selection.items()
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                yield from item.items()


def _is_number(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    return isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v.strip()) is not None


def _lint_modifier_values(key: str, mods: List[str], raw, values: List[Any], loc) -> List[Dict]:
    out = []
    if "all" in mods and not isinstance(raw, list):
        out.append(finding("SIG-072", "medium", f"'all' modifier on a single value in '{key}'",
                           "all means every value in the list must match; with one value it does nothing and the Sigma specification does not allow it.",
                           "Remove |all, or list several values.", loc))
    flags = [m for m in mods if m in REGEX_FLAGS]
    if flags and "re" not in mods:
        out.append(finding("SIG-073", "medium", f"regex flag modifier '{flags[0]}' without 're' in '{key}'",
                           "i, m and s are sub-modifiers of re and mean nothing on their own.",
                           f"Write {key.split('|')[0]}|re|{flags[0]} or drop the flag.", loc))
    num = [m for m in mods if m in NUMERIC_MODIFIERS]
    if num:
        bad = [v for v in values if not _is_number(v)]
        if bad:
            out.append(finding("SIG-074", "medium", f"'{num[0]}' needs numbers in '{key}'", f"non-numeric value(s): {', '.join(repr(b) for b in bad[:3])}",
                               "Compare numbers only; use contains or re for text.", loc))
    for m in mods:
        if m in TIME_MODIFIERS:
            lo, hi = TIME_MODIFIERS[m]
            bad = [v for v in values if not _is_number(v) or not lo <= float(v) <= hi]
            if bad:
                out.append(finding("SIG-074", "medium", f"'{m}' value out of range in '{key}'", f"{m} takes a number from {lo} to {hi}; got {', '.join(repr(b) for b in bad[:3])}.",
                                   f"Use a whole number from {lo} to {hi}.", loc))
    if "cidr" in mods:
        for v in values:
            try:
                ipaddress.ip_network(str(v), strict=False)
            except ValueError:
                out.append(finding("SIG-075", "high", f"invalid CIDR in '{key}'", f"{v!r} is not an IPv4 or IPv6 network.", "Use a network like 10.0.0.0/8 or 2001:db8::/32.", loc))
    if "exists" in mods and not isinstance(raw, bool):
        out.append(finding("SIG-076", "medium", f"'exists' needs true or false in '{key}'", f"got {raw!r}",
                           "Write `Field|exists: true` (or false).", loc))
    if "re" in mods and ({"contains", "startswith", "endswith", "windash", "base64", "base64offset"} & set(mods)):
        out.append(finding("SIG-077", "low", f"'re' combined with a string modifier in '{key}'",
                           "Backends handle re on its own; contains, startswith, endswith, windash and base64 do not apply to a regex.",
                           "Put the anchors or wildcards in the regex itself.", loc))
    return out


def collect_files(paths: List[str]) -> List[str]:
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in sorted(names) if n.lower().endswith((".yml", ".yaml", ".json"))]
        else:
            files.append(p)
    return files


def _check_references(parsed: List[Tuple[str, Any, List[Dict]]]) -> None:
    """SIG-088 (info): correlation or filter rules that point at rules not found in the linted files."""
    known = set()
    for _, rule, _ in parsed:
        if isinstance(rule, dict):
            known.update(str(rule[k]) for k in ("id", "name") if rule.get(k))
    for where, rule, f in parsed:
        if not isinstance(rule, dict):
            continue
        block = rule.get("correlation") if "correlation" in rule else rule.get("filter")
        refs = block.get("rules") if isinstance(block, dict) else None
        refs = [refs] if isinstance(refs, str) else refs if isinstance(refs, list) else []
        missing = [str(r) for r in refs if str(r) not in known]
        if missing:
            f.append(finding("SIG-088", "info", "referenced rule not among the linted files",
                             f"not found by id or name: {', '.join(missing[:5])}",
                             "Lint the base rules together with this one, or check the id or name.", where))


def lint_paths(paths: List[str]) -> Dict:
    results, seen_ids = [], {}
    parsed = []
    for path in collect_files(paths):
        try:
            docs = load_rules(path)
        except (YamlError, json.JSONDecodeError, OSError, UnicodeDecodeError) as err:
            results.append({"file": path, "title": None, "findings": [finding("SIG-000", "high", "File could not be parsed", str(err), "Fix the YAML syntax (indentation, quotes, colons).", path)]})
            continue
        for i, rule in enumerate(docs):
            where = path if len(docs) == 1 else f"{path} (document {i + 1})"
            f = lint_rule(rule, where)
            rid = rule.get("id") if isinstance(rule, dict) else None
            if rid:
                if rid in seen_ids:
                    f.append(finding("SIG-003", "medium", "duplicate id", f"id {rid} is also used in {seen_ids[rid]}.", "Give every rule its own UUID.", where))
                else:
                    seen_ids[rid] = where
            parsed.append((where, rule, f))
            results.append({"file": where, "title": rule.get("title") if isinstance(rule, dict) else None, "findings": f})
    _check_references(parsed)
    for r in results:
        r["findings"].sort(key=lambda x: (-SEVERITY_ORDER.index(x["severity"]), x["id"]))
    return {"rules": results, "summary": {s: sum(1 for r in results for f in r["findings"] if f["severity"] == s) for s in SEVERITY_ORDER}}


def render_text(result: Dict) -> str:
    out = []
    for r in result["rules"]:
        bad = [f for f in r["findings"] if f["severity"] != "info"]
        out.append(f"{'FAIL' if any(f['severity'] in ('high', 'critical') for f in r['findings']) else 'ok  '} {r['file']}"
                   + (f"  ({r['title']})" if r["title"] else ""))
        for f in r["findings"]:
            out.append(f"     [{f['severity'].upper():8}] {f['id']}  {f['title']}")
            if f["severity"] != "info":
                out.append(f"                {f['detail']}")
                out.append(f"                fix: {f['fix']}")
        if not bad and not r["findings"]:
            out.append("     clean")
    s = result["summary"]
    out.append("")
    out.append(f"{len(result['rules'])} rule(s): " + ", ".join(f"{s[k]} {k}" for k in reversed(SEVERITY_ORDER)))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Lint Sigma rules (YAML or JSON).")
    ap.add_argument("paths", nargs="+", help="rule files or folders")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--fail-on", default="high", choices=SEVERITY_ORDER + ["never"],
                    help="exit 1 if any finding is at or above this severity (default: high)")
    args = ap.parse_args(argv)

    files = collect_files(args.paths)
    missing = [p for p in files if not os.path.isfile(p)]
    if missing or not files:
        print(f"error: no rule files found{': ' + ', '.join(missing) if missing else ''}", file=sys.stderr)
        return 2
    result = lint_paths(args.paths)
    print(json.dumps(result, indent=2) if args.json else render_text(result))
    if args.fail_on != "never":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f["severity"]) >= threshold for r in result["rules"] for f in r["findings"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
