#include <benchmark/benchmark.h>
#include "../include/merkle_tree.h"
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
    auto data_items = generate_test_data(1);
    const std::string& data = data_items[0];
    
    for (auto _ : state) {
        MerkleTree tree;
        tree.insert(data);
    }
}
BENCHMARK(BM_SingleInsert);

// 基准测试：批量插入性能
static void BM_BatchInsert(benchmark::State& state) {
    const size_t item_count = state.range(0);
    auto data_items = generate_test_data(item_count);
    
    for (auto _ : state) {
        state.PauseTiming();
        try {
            MerkleTree tree;
            state.ResumeTiming();
            
            for (const auto& data : data_items) {
                tree.insert(data);
                benchmark::DoNotOptimize(tree);
            }
            
            state.PauseTiming();
        } catch (const std::exception& e) {
            state.SkipWithError(e.what());
        }
        state.ResumeTiming();
    }
}
BENCHMARK(BM_BatchInsert)
    ->Arg(1'000)
    ->Arg(5'000)  // 先测试中等规模
    ->Arg(10'000)
    ->Unit(benchmark::kMillisecond);

// 基准测试：查寻性能
static void BM_Contains(benchmark::State& state) {
    const size_t tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    MerkleTree tree;
    
    // 构建测试树
    for (const auto& data : data_items) {
        tree.insert(data);
    }
    
    // 准备测试查询
    std::vector<std::string> queries;
    std::sample(data_items.begin(), data_items.end(), std::back_inserter(queries),
                50, std::mt19937{std::random_device{}()});
    
    size_t i = 0;
    for (auto _ : state) {
        tree.contains(queries[i % queries.size()]);
        ++i;
    }
}
BENCHMARK(BM_Contains)->Unit(benchmark::kMicrosecond);

// 基准测试：证明生成性能
static void BM_ProofGeneration(benchmark::State& state) {
    const size_t tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    MerkleTree tree;
    
    // 构建测试树
    for (const auto& data : data_items) {
        tree.insert(data);
    }
    
    // 准备测试查询
    std::vector<std::string> queries;
    std::sample(data_items.begin(), data_items.end(), std::back_inserter(queries),
                50, std::mt19937{std::random_device{}()});
    
    size_t i = 0;
    for (auto _ : state) {
        auto proof = tree.generate_proof(queries[i % queries.size()]);
        benchmark::DoNotOptimize(proof);
        ++i;
    }
}
BENCHMARK(BM_ProofGeneration)->Unit(benchmark::kMicrosecond);

// 基准测试：证明验证性能
static void BM_ProofVerification(benchmark::State& state) {
    const size_t tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    MerkleTree tree;
    
    // 构建测试树并生成证明
    for (const auto& data : data_items) {
        tree.insert(data);
    }
    
    std::vector<MerkleTree::Proof> proofs;
    std::vector<std::string> root_hashes;
    for (int i = 0; i < 50; ++i) {
        proofs.push_back(tree.generate_proof(data_items[i]));
        root_hashes.push_back(tree.root_hash());
    }
    
    size_t i = 0;
    for (auto _ : state) {
        bool valid = MerkleTree::verify_proof(proofs[i % proofs.size()], root_hashes[i % root_hashes.size()]);
        benchmark::DoNotOptimize(valid);
        ++i;
    }
}
BENCHMARK(BM_ProofVerification)->Unit(benchmark::kMicrosecond);

// 基准测试：多线程并发插入
static void BM_ConcurrentInsert(benchmark::State& state) {
    const int thread_count = state.range(0);
    const int items_per_thread = 1000;
    auto data_items = generate_test_data(items_per_thread * thread_count);
    
    for (auto _ : state) {
        state.PauseTiming();
        MerkleTree tree;
        std::vector<std::thread> threads;
        
        state.ResumeTiming();
        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&, t] {
                for (int i = 0; i < items_per_thread; ++i) {
                    tree.insert(data_items[t * items_per_thread + i]);
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
    }
}
BENCHMARK(BM_ConcurrentInsert)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMillisecond);

// 基准测试：多线程混合工作负载
static void BM_MixedWorkload(benchmark::State& state) {
    const int thread_count = state.range(0);
    const int tree_size = 10'000;
    auto data_items = generate_test_data(tree_size);
    
    MerkleTree tree;
    // 初始数据集
    for (int i = 0; i < tree_size/2; ++i) {
        tree.insert(data_items[i]);
    }
    
    for (auto _ : state) {
        std::vector<std::thread> threads;
        
        for (int t = 0; t < thread_count; ++t) {
            threads.emplace_back([&, t] {
                // 混合操作：75%插入，25%查询
                for (int i = 0; i < 1000; ++i) {
                    if (i % 4 != 0) {
                        // 插入新项(使用唯一数据)
                        tree.insert(data_items[(t * 1000 + i) % data_items.size()]);
                    } else {
                        // 查询现有项
                        tree.contains(data_items[t % tree_size]);
                    }
                }
            });
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
    }
}
BENCHMARK(BM_MixedWorkload)->Arg(4)->Arg(8)->Arg(16)->Unit(benchmark::kMillisecond);

// 内存使用基准
static void BM_MemoryUsage(benchmark::State& state) {
    const size_t item_count = state.range(0);
    auto data_items = generate_test_data(item_count);
    
    for (auto _ : state) {
        MerkleTree tree;
        
        for (const auto& data : data_items) {
            tree.insert(data);
        }
        
        state.counters["Memory/Leaf"] = 
            benchmark::Counter(
                sizeof(std::shared_ptr<MerkleNode>) * tree.leaf_count(),
                benchmark::Counter::kDefaults
            );
        
        state.counters["Memory/Node"] = 
            benchmark::Counter(
                sizeof(MerkleNode) * tree.node_count(),
                benchmark::Counter::kDefaults
            );
    }
}
BENCHMARK(BM_MemoryUsage)->Arg(1'000)->Arg(10'000)->Unit(benchmark::kMillisecond);

BENCHMARK_MAIN();
