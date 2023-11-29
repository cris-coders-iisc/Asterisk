#!/bin/bash
# set -x

dir=~/benchmark_data/Darkpool_VM

# rm -rf $dir/*.log $dir/b*.json
mkdir -p $dir

for var in {5,10,25,50,100}
do
    players=$(( $var + $var ))
    for party in $(seq 1 $players)
    do
        log=$dir/b_"$var"_s_"$var"_"$party".log
        json=$dir/b_"$var"_s_"$var"_"$party".json
        if [ $party = 1 ] || [ $party -eq $players ]
        then
            ./benchmarks/Darkpool_VM -p $party --localhost -b $var -s $var -n $players -o $json 2>&1 | cat >> /dev/null &
        else
            ./benchmarks/Darkpool_VM -p $party --localhost -b $var -s $var -n $players 2>&1 | cat > /dev/null &
        fi
        codes[$party]=$!
    done

    ./benchmarks/Darkpool_VM -p 0 --localhost -b $var -s $var -n $players -o $dir/b_"$var"_s_"$var"_0.json 2>&1 | tee -a /dev/null &
    codes[0]=$!

    for party in $(seq 0 $players)
    do
        wait ${codes[$party]} || return 1
    done
done

