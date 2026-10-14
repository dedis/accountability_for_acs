// Copyright 2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// main() for running both tests and benchmarks in the same
// file.
//
// The behavior is as follows:
//
//   foo_test
//       Run tests but not benchmarks
//
//   foo_test --benchmark_filter=all
//       Run benchmarks but not tests
//
#include <benchmark/benchmark.h>
#include <gtest/gtest.h>
#include <string.h>

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
    
  // Hack: run benchmarks only if --benchmark_filter is
  // specified explicitly.

  // By default, the benchmark filter is set to *, which runs all
  // benchmarks.  We don't want to run benchmarks when testing.  In
  // recent versions of libbenchmark, one can call
  // GetBenchmarkFilter(), but older versions don't support it.
  // Check for anything that starts with --bench.
  bool bench = (argc > 1) && !strncmp(argv[1], "--bench", 7);

  if (bench) {
    // By default run no benchmarks
    benchmark::Initialize(&argc, argv);
    return benchmark::RunSpecifiedBenchmarks();
  }

  return RUN_ALL_TESTS();
}
