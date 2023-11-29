#!/bin/bash
# set -x

dir=~/benchmark_data/asterisk_offline

# rm -rf $dir/*.log $dir/g*.json
mkdir -p $dir

for players in {5,10,25,50,100}
do
    for party in $(seq 1 $players)
    do
        log=$dir/g_$1_d_$2_$party.log
        json=$dir/g_$1_d_$2_$party.json
        if test $party = 1
        then
            ./benchmarks/asterisk_offline -p $party --localhost -g $1 -d $2 -n $players -o $json 2>&1 | cat >> /dev/null &
        else
            ./benchmarks/asterisk_offline -p $party --localhost -g $1 -d $2 -n $players 2>&1 | cat > /dev/null &
        fi
        codes[$party]=$!
    done

    ./benchmarks/asterisk_offline -p 0 --localhost -g $1 -d $2 -n $players -o $dir/g_$1_d_$2_0.json 2>&1 | tee -a /dev/null &
    codes[0]=$!

    for party in $(seq 0 $players)
    do
        wait ${codes[$party]} || return 1
    done
done
