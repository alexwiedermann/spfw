# -*- coding: utf-8 -*-
import spfw_vars
from flask import abort, redirect, url_for,request,jsonify,Flask
from flask_httpauth import HTTPBasicAuth
from flask.ext.script import Manager
import iptc
import threading
app = Flask(__name__)

interface  = "enp2s0"
ports = "22,3306,5432,9947"

# Autenticacao basica
auth = HTTPBasicAuth()

# Pega a senha
@auth.get_password
def get_pw(username):
    if username in spfw_vars.users:
        return spfw_vars.users.get(username)
    return None

@app.route("/")
def hello():
    # I'm a teapot
    abort(418)

@app.route("/get_my_ip", methods=["GET"])
@auth.login_required
def get_my_ip():
    ipcliente = jsonify({'ip': request.remote_addr}), 200
    return ipcliente

@app.route("/flush_all", methods=["GET"])
@auth.login_required
def flush_all():
    tb = iptc.Table(iptc.Table.FILTER)
    c = iptc.Chain(tb, 'INPUT')
    c.flush()
    allow_loopback()
    allow_established()
    clear = open("ips.txt", "w")
    clear.write("127.0.0.1" + "\n")
    clear.close()
    return jsonify({'status': 'flush'})

def flush_ip():
    tb = iptc.Table(iptc.Table.FILTER)
    c = iptc.Chain(tb, 'INPUT')
    c.flush()
    allow_loopback()
    allow_established()
    return jsonify({'status': 'flush'}),200

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
@auth.login_required
def add_my_ip():
    ipcliente = request.remote_addr, 200
    ipcliente = ipcliente[0]
    if ipcliente in open('ips.txt').read():
        return jsonify({'status': 'ip ja cadastrado'}),200
    # Mantem ips cadastrados
    preserve_table()
    save_ip   = open("ips.txt", "a")
    save_ip.write(ipcliente + "\n")
    save_ip.close()
    add_ip(ipcliente)
    drop_ssh()
    return jsonify({'status': 'adicionado', 'ip': ipcliente}),200

def drop_ssh():
    rule = iptc.Rule()
    rule.in_interface = interface
    rule.src = "0.0.0.0/0"
    rule.protocol = "tcp"
    rule.target = rule.create_target("DROP")
    match = rule.create_match("comment")
    match.comment = "Bloqueia porta"
    match = iptc.Match(rule, "tcp")
    rule.add_match(match)
    match = iptc.Match(rule, 'multiport')
    # Comente este match para bloquear qualquer porta
    match.dports = ports
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
def block_all():
    if request.remote_addr == "127.0.0.1":
        flush_all()
        drop_ssh()
        return "OK"
    else:
        return "Wrong Access"


manager = Manager(app)

@manager.command
def runserver():
    app.run(debug=False,host='0.0.0.0')
    # FIXME
    tb = iptc.Table(iptc.Table.FILTER)
    c = iptc.Chain(tb, 'INPUT')
    c.flush()
    allow_loopback()
    allow_established()
    clear = open("ips.txt", "w")
    clear.write("127.0.0.1" + "\n")
    clear.close()
    return jsonify({'status': 'flush'})

if __name__ == "__main__":
    manager.run()
