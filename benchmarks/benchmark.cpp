#include <benchmark/benchmark.h>
#include "merkle_tree.h"
#include <random>
#include <vector>
#include <thread>

// 生成随机测试数据
static std::vector<std::string> generate_test_data(size_t count) {
    std::vector<std::string> data;
    data.reserve(count);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    
    for (size_t i = 0; i < count; ++i) {
        std::string item(128, '\0'); // 128字节数据
        std::generate_n(item.begin(), 128, [&]() { return dist(gen); });
        data.push_back(std::move(item));
    }
    return data;
}

// 基准测试：单次插入
static void BM_SingleInsert(benchmark::State& state) {
    auto data_items = generate_test_data(state.range(0));
    size_t index = 0;
    
    MerkleTree tree;
    for (auto _ : state) {
        tree.insert(data_items[index % data_items.size()]);
        index++;
    }
    
    // 确保测试结束后所有插入被处理
    state.PauseTiming();
    tree.flush();
    state.ResumeTiming();
    
    // 吞吐量统计
    state.SetItemsProcessed(state.iterations());
}

// 基准测试：批量插入性能
static void BM_BatchInsert(benchmark::State& state) {
    const size_t batch_size = state.range(0);
    auto data_items = generate_test_data(batch_size);
    
    for (auto _ : state) {
        MerkleTree tree;
        tree.batch_insert(data_items);
        
        state.PauseTiming();
        tree.flush();
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * batch_size);
}

// 基准测试：异步模式下多线程并发插入
static void BM_ConcurrentInsert(benchmark::State& state) {
    const int thread_count = state.range(0);
    const int items_per_thread = 100000;
    auto data_items = generate_test_data(items_per_thread * thread_count);
    
    for (auto _ : state) {
        MerkleTree tree;
        std::vector<std::thread> threads;
        
        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&tree, &data_items, t, items_per_thread] {
                for (int i = 0; i < items_per_thread; ++i) {
                    tree.insert(data_items[t * items_per_thread + i]);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        state.PauseTiming();
        tree.flush(); // 确保所有异步插入完成
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * thread_count * items_per_thread);
}

// 基准测试：包含查询操作
static void BM_Contains(benchmark::State& state) {
    const size_t tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    
    MerkleTree tree;
    tree.batch_insert(data_items);
    tree.flush(); // 确保所有插入完成
    
    // 准备测试查询数据
    std::vector<std::string> queries;
    std::sample(data_items.begin(), data_items.end(), std::back_inserter(queries),
                100, std::mt19937{std::random_device{}()});
    
    size_t i = 0;
    for (auto _ : state) {
        bool exists = tree.contains(queries[i % queries.size()]);
        benchmark::DoNotOptimize(exists);
        ++i;
    }
}

// 基准测试：证明生成和验证
static void BM_ProofGenerateVerify(benchmark::State& state) {
    const size_t tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    
    MerkleTree tree;
    tree.batch_insert(data_items);
    tree.flush(); // 确保所有插入完成
    
    const std::string root_hash = tree.root_hash();
    std::string test_item = data_items[0];
    
    for (auto _ : state) {
        auto proof = tree.generate_proof(test_item);
        bool valid = MerkleTree::verify_proof(proof, root_hash);
        benchmark::DoNotOptimize(valid);
    }
}

// 基准测试：混合操作（插入+查询）
static void BM_MixedOperations(benchmark::State& state) {
    const size_t tree_init_size = 5000;
    const size_t ops_count = state.range(0);
    
    auto data_items = generate_test_data(tree_init_size + ops_count);
    
    MerkleTree tree;
    // 初始树
    tree.batch_insert(std::vector<std::string>(data_items.begin(), data_items.begin() + tree_init_size));
    tree.flush();
    
    for (auto _ : state) {
        for (size_t i = 0; i < ops_count; ++i) {
            if (i % 4 == 0) { // 25%的查询，75%的插入
                tree.contains(data_items[i % tree_init_size]);
            } else {
                tree.insert(data_items[tree_init_size + (i % ops_count)]);
            }
        }
        state.PauseTiming();
        tree.flush();
        state.ResumeTiming();
    }
    state.SetItemsProcessed(state.iterations() * ops_count);
}

// BENCHMARK(BM_SingleInsert)
//     ->Arg(10000)
//     ->Arg(100000)
//     ->Arg(1000000)
//     ->Unit(benchmark::kMicrosecond);

// BENCHMARK(BM_BatchInsert)
//     ->Arg(10000)
//     ->Arg(100000)
//     ->Arg(1000000)
//     ->Unit(benchmark::kMillisecond);

BENCHMARK(BM_ConcurrentInsert)
    ->Arg(2)
    ->Arg(4)
    ->Arg(8)
    ->Arg(16)
    ->Unit(benchmark::kMillisecond);

BENCHMARK(BM_Contains)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK(BM_ProofGenerateVerify)
    ->Unit(benchmark::kMicrosecond);

// BENCHMARK(BM_MixedOperations)
//     ->Arg(1000)
//     ->Arg(5000)
//     ->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
