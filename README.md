# Asterisk

This directory contains the implementation of the Asterisk fair protocol.
The protocol is implemented in C++17 and [CMake](https://cmake.org/) is used as the build system.

## External Dependencies
The following libraries need to be installed separately and should be available to the build system and compiler.

- [GMP](https://gmplib.org/)
- [NTL](https://www.shoup.net/ntl/) (11.0.0 or later)
- [Boost](https://www.boost.org/) (1.72.0 or later)
- [Nlohmann JSON](https://github.com/nlohmann/json)
- [EMP Tool](https://github.com/emp-toolkit/emp-tool)

### Docker
All required dependencies to compile and run the project are available through the docker image.
To build and run the docker image, execute the following commands from the root directory of the repository:

```sh
# Build the Asterisk Docker image.
#
# Building the Docker image requires at least 4GB RAM. This needs to be set 
# explicitly in case of Windows and MacOS.
docker build -t asterisk .

# Create and run a container.
#
# This should start the shell from within the container.
docker run -it -v $PWD:/code asterisk

# The following command changes the working directory to the one containing the 
# source code and should be run on the shell started using the previous command.
cd /code
```

## Compilation
The project uses [CMake](https://cmake.org/) for building the source code. 
To compile, run the following commands from the root directory of the repository:

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

# The two main targets are 'benchmarks' and 'tests' corresponding to
# binaries used to run benchmarks and unit tests respectively.
make <target>
```

## Usage
A short description of the compiled programs is given below.
All of them provide detailed usage description on using the `--help` option.

- `benchmarks/asterisk_mpc`: Benchmark the performance of the Asterisk protocol (both offline and online phases) by evaluating a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/asterisk_online`: Benchmark the performance of the Asterisk online phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/asterisk_offline`: Benchmark the performance of the Asterisk offline phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/assistedmpc_offline`: Benchmark the performance of the Assisted MPC offline phase for a circuit with a given depth and number of multiplication gates at each depth.
- `benchmarks/Darkpool_CDA`: Benchmark the performance of the Darkpool CDA algorithm for a given buy list and sell list size.
- `benchmarks/Darkpool_VM`: Benchmark the performance of the Darkpool VM algorithm for a given buy list and sell list size. Here, the number of parties = buy list size + sell list size.
- `tests/*`: These programs contain unit tests for various parts of the codebase. 

Execute the following commands from the `build` directory created during compilation to run the programs:
```sh
# Benchmark Asterisk MPC.
#
# The command below should be run on four different terminals with $PID set to
# 0, 1, 2, and 3 i.e., one instance corresponding to each party.
#
# The number of threads can be set using the '-t' option. '-g' denotes the 
# number of gates at each level and '-d' denotes the depth of the circuit.
#
# The program can be run on different machines by replacing the `--localhost`
# option with '--net-config <net_config.json>' where 'net_config.json' is a
# JSON file containing the IPs of the parties. A template is given in the
# repository root.
./benchmarks/asterisk_mpc -p $PID --localhost -g 100 -d 10

# The `asterisk_mpc` script in the repository root can be used to run the programs 
# for all parties from the same terminal.
# For example, the previous benchmark can be run using the script as shown
# below.
./../asterisk_mpc.sh 100 10

# All other benchmark programs have similar options and behaviour. The '-h'
# option can be used for detailed usage information.

# Benchmark online phase for Asterisk MPC.
./../asterisk_online.sh 100 10

# Benchmark offline phase for Asterisk MPC.
./../asterisk_offline.sh 100 10

# Benchmark offline phase for Assisted MPC.
./../assistedmpc_offline.sh 100 10

# Benchmark Darkpool CDA algorithm for buy list size b=10 and sell list size s=20.
./../Darkpool_CDA.sh 10 20

# Benchmark Darkpool VM algorithm for buy list size = sell list size = 5/10/25/50/100.
./../Darkpool_VM.sh
```
