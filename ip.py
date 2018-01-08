# -*- coding: utf-8 -*-
from flask import request
from flask import jsonify
from flask import Flask
import iptc

app = Flask(__name__)
app.config['SECRET_KEY'] = 'batata'


interface = "wlp2s0"

@app.route("/")
def hello():
    return 500

def simple_protect():
    secret = request.args.get('secret')
    if secret == "batata":
        return "OK"
    else:
        exit(0)

@app.route("/get_my_ip", methods=["GET"])
def get_my_ip():
    simple_protect()
    ipcliente = jsonify({'ip': request.remote_addr}), 200
    return ipcliente

@app.route("/flush_ip", methods=["GET"])
def flush_ip():
    simple_protect()
    tb = iptc.Table(iptc.Table.FILTER)
    c = iptc.Chain(tb, 'INPUT')
    c.flush()
    allow_loopback()
    allow_established()
    return jsonify({'status': 'flush'})

def allow_loopback():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "lo"
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target
    chain.insert_rule(rule)

def allow_established():
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), 'INPUT')
    rule = iptc.Rule()
    match = rule.create_match('state')
    match.state = "RELATED,ESTABLISHED"
    rule.target = iptc.Target(rule, 'ACCEPT')
    chain.insert_rule(rule)

def preserve_table():
    flush_ip()
    with open("ips.txt", "r") as ips:
        ips = ips.readlines()
        for ip in ips:
            # Nao tem linhas no arquivo
            if not ip.strip():
                continue
            # Adiciona as linhas existentes
            else:
                ip = ip.strip()
                rule = iptc.Rule()
                rule.in_interface = interface
                rule.src = ip
                rule.protocol = "tcp"
                rule.target = rule.create_target("ACCEPT")
                match = rule.create_match("comment")
                match.comment = "Regra temporaria de INPUT"
                chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
                chain.insert_rule(rule)

@app.route("/add_my_ip", methods=["GET"])
def add_my_ip():
    simple_protect()
    # Mantem ips cadastrados
    preserve_table()
    ipcliente = request.remote_addr, 200
    ipcliente = ipcliente[0]
    if ipcliente in open('ips.txt').read():
        return jsonify({'status': 'ip cadastrado'})
        drop_ssh()
        exit(0)
    save_ip   = open("ips.txt", "a")
    save_ip.write(ipcliente + "\n")
    save_ip.close()
    add_ip(ipcliente)
    drop_ssh()
    return jsonify({'status': 'adicionado', 'ip': ipcliente})

def drop_ssh():
    rule = iptc.Rule()
    rule.in_interface = interface
    rule.src = "0.0.0.0/0"
    rule.protocol = "tcp"
    rule.target = rule.create_target("DROP")
    match = rule.create_match("comment")
    match.comment = "Bloqueia SSH"
    # Comente este match para bloquear qualquer porta
    match = iptc.Match(rule, "tcp")
    match.dport = "22"
    rule.add_match(match)
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.append_rule(rule)

def add_ip(ipcliente):
    rule = iptc.Rule()
    rule.in_interface = interface
    rule.src = ipcliente
    rule.protocol = "tcp"
    rule.target = rule.create_target("ACCEPT")
    match = rule.create_match("comment")
    match.comment = "Regra temporaria de INPUT"
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.insert_rule(rule)

@app.route("/del_ip", methods=["GET"])
def del_ip():
    simple_protect()
    ipcliente = request.remote_addr, 200
    rule = iptc.Rule()
    rule.in_interface = interface
    rule.src = ipcliente[0]
    rule.protocol = "tcp"
    rule.target = rule.create_target("ACCEPT")
    match = rule.create_match("comment")
    match.comment = "Regra temporaria de INPUT"
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    chain.delete_rule(rule)
    return jsonify({'status': 'removido', 'ip': ipcliente[0]})

if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')
