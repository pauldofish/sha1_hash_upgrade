# cd to directory
cd {D:/02 Github/sha1_hash_upgrade}

#clean lib
vmap -del work
vdel -all -lib work

#create & map work lib
vlib work
vmap work work

#compile source files
vlog -reportprogress 300 -work work {D:/02 Github/sha1_hash_upgrade/src/SHA1_hash.v}

#compile TB
vlog -reportprogress 300 -work work {D:/02 Github/sha1_hash_upgrade/tb_src/SHA1_hash_testbench_v6.v}

#run sim
vsim work.SHA1_hash_testbench

log -r sim:/SHA1_hash_testbench/*
run -a