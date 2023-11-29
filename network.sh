function tc_off() {
    sudo tc qdisc del dev lo root
}

function tc_lan() {
    sudo tc qdisc del dev lo root
    sudo tc qdisc add dev lo root handle 1:0 htb default 10
    sudo tc class add dev lo parent 1:0 classid 1:10 htb rate 1Gbit
    sudo tc qdisc add dev lo parent 1:10 handle 10:0 netem delay 0.5ms 0.03ms 5% distribution normal
}

function tc_wan() {
    sudo tc qdisc del dev lo root
    sudo tc qdisc add dev lo root handle 1:0 htb default 10
    sudo tc class add dev lo parent 1:0 classid 1:10 htb rate 100Mbit
    sudo tc qdisc add dev lo parent 1:10 handle 10:0 netem delay 50ms 3ms 25% distribution normal
}
