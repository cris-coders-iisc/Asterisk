#!/bin/bash
# set -x

dir=~/benchmark_data/Darkpool_CDA

# rm -rf $dir/*.log $dir/b*.json
mkdir -p $dir

for players in 5
do
    for party in $(seq 1 $players)
    do
        log=$dir/b_$1_s_$2_$party.log
        json=$dir/b_$1_s_$2_$party.json
        if [ $party == 1 ] || [ $party == 5 ] 
        then
            ./benchmarks/Darkpool_CDA -p $party --localhost -b $1 -s $2 -n $players -o $json 2>&1 | cat >> /dev/null &
        else
            ./benchmarks/Darkpool_CDA -p $party --localhost -b $1 -s $2 -n $players 2>&1 | cat > /dev/null &
        fi
        codes[$party]=$!
    done

    ./benchmarks/Darkpool_CDA -p 0 --localhost -b $1 -s $2 -n $players -o $dir/b_$1_s_$2_0.json 2>&1 | tee -a /dev/null &
    codes[0]=$!

    for party in $(seq 0 $players)
    do
        wait ${codes[$party]} || return 1
    done
done

