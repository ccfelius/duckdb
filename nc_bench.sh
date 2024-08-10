#!/bin/bash

for i in {1..2}
do
	build/release/benchmark/benchmark_runner "benchmark/micro/compression/alp/alp_read_worst_case.benchmark"
done
