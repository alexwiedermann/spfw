# -*- coding: utf-8 -*-
import request
import iptc
import functools

with open("ips.txt", "r") as ips:
    ips = ips.readlines()
    for ip in ips:
        ip = ip.strip()
        rule = iptc.Rule()
        rule.in_interface = "enp4s0"
        rule.src = ip
        rule.protocol = "tcp"
        rule.target = rule.create_target("ACCEPT")
        match = rule.create_match("comment")
        match.comment = "Regra temporaria de INPUT"
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        chain.insert_rule(rule)
