#!/bin/bash

model=$1
action=$2

echo "vtysh args=$@"

if [ $model = "whitelist" ]; then
    if [ $action = "add" ]; then
        rule=$3
        vtysh -c "configure terminal" -c firewall -c "firewall rule whitelist add $rule"
        echo "增加白名单$rule"
    elif [ $action = "del" ]; then
        vtysh -c "configure terminal" -c firewall -c "firewall rule whitelist del"
        echo "删除白名单"
    fi
elif [ $model = "blacklist" ]; then
    if [ $action = "add" ]; then
        rule=$3
        vtysh -c "configure terminal" -c firewall -c "firewall rule blacklist add $rule"
        echo "增加黑名单$rule"
    elif [ $action = "del" ]; then
        vtysh -c "configure terminal" -c firewall -c "firewall rule blacklist del"
        echo "删除白名单"
    fi
elif [ $model = "suricata" ]; then
    if [ $action = "reload" ]; then
        vtysh -c "configure terminal" -c firewall -c "firewall rule reload"
        echo "规则重载"
    fi
fi
