#include <gtest/gtest.h>
#include "../include/merkle_tree.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>

class MerkleTreeTest : public ::testing::Test {
protected:
    MerkleTree tree;
};

TEST_F(MerkleTreeTest, EmptyTree) {
    EXPECT_TRUE(tree.root_hash().empty());
    EXPECT_EQ(tree.node_count(), 0);
    EXPECT_EQ(tree.leaf_count(), 0);
}

TEST_F(MerkleTreeTest, SingleInsert) {
    tree.insert("tx1");
    EXPECT_FALSE(tree.root_hash().empty());
    EXPECT_EQ(tree.node_count(), 1);
    EXPECT_EQ(tree.leaf_count(), 1);
}

TEST_F(MerkleTreeTest, ProofVerification) {
    tree.insert("Data1");
    tree.insert("Data2");
    tree.insert("Data3");
    
    {
        auto valid_proof = tree.generate_proof("Data2");
        EXPECT_TRUE(MerkleTree::verify_proof(valid_proof, tree.root_hash()));
    }
    
    {
        // 测试不存在的节点
        auto invalid_proof = tree.generate_proof("Data99");
        EXPECT_FALSE(MerkleTree::verify_proof(invalid_proof, tree.root_hash()));
        EXPECT_TRUE(invalid_proof.path.empty());
    }
    
    {
        // 测试篡改的证明
        auto tampered_proof = tree.generate_proof("Data1");
        if (!tampered_proof.path.empty()) {
            tampered_proof.path[0].second[0] ^= 0xFF; // 翻转哈希的首字节
            EXPECT_FALSE(MerkleTree::verify_proof(tampered_proof, tree.root_hash()));
        }
    }
}

TEST_F(MerkleTreeTest, Contains) {
    tree.insert("Data1");
    tree.insert("Data2");
    
    EXPECT_TRUE(tree.contains("Data1"));
    EXPECT_TRUE(tree.contains("Data2"));
    EXPECT_FALSE(tree.contains("Data3"));
}

TEST_F(MerkleTreeTest, DuplicatePrevention) {
    tree.insert("Duplicate");
    size_t first_insert_count = tree.node_count();
    
    tree.insert("Duplicate");
    tree.insert("Duplicate");
    
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), first_insert_count);
}

TEST_F(MerkleTreeTest, IncrementalUpdate) {
    // 初始状态
    EXPECT_EQ(tree.node_count(), 0);
    
    // 插入第一个节点
    tree.insert("A");
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), 1); // 只有叶子节点
    
    // 插入第二个节点
    tree.insert("B");
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_EQ(tree.node_count(), 3); // 2叶子 + 1父节点
    
    // 保存根哈希
    std::string root_ab = tree.root_hash();
    
    // 插入第三个节点
    tree.insert("C");
    EXPECT_EQ(tree.leaf_count(), 3);
    EXPECT_EQ(tree.node_count(), 5); // 3叶子 + 2父节点
}

TEST_F(MerkleTreeTest, Concurrency) {
    constexpr int THREAD_COUNT = 8;
    constexpr int PER_THREAD = 1000;
    std::vector<std::thread> threads;
    std::atomic<int> insert_count{0};
    std::mutex cout_mutex;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < THREAD_COUNT; i++) {
        threads.emplace_back([this, i, &insert_count] {
            for (int j = 0; j < PER_THREAD; j++) {
                std::string data = "Thread" + std::to_string(i) + 
                                   "-Item" + std::to_string(j);
                tree.insert(data);
                insert_count++;
            }
        });
    }
    
    for (auto& t : threads) t.join();
    auto end = std::chrono::high_resolution_clock::now();
    
    // 计算耗时
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    // 验证插入数量
    EXPECT_EQ(tree.leaf_count(), THREAD_COUNT * PER_THREAD);
    
    // 验证随机样本
    EXPECT_TRUE(tree.contains("Thread3-Item42"));
    
    // 验证证明系统
    auto proof = tree.generate_proof("Thread5-Item10");
    EXPECT_TRUE(MerkleTree::verify_proof(proof, tree.root_hash()));
    
    // 性能报告
    std::cout << "Concurrent test: Inserted " << insert_count 
              << " items with " << THREAD_COUNT << " threads in "
              << duration << "ms" << std::endl;
}

TEST_F(MerkleTreeTest, Performance) {
    constexpr int NUM_INSERTS = 10000;
    
    // 测试插入性能
    auto insert_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_INSERTS; i++) {
        tree.insert("Data" + std::to_string(i));
    }
    auto insert_end = std::chrono::high_resolution_clock::now();
    auto insert_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        insert_end - insert_start).count();
    
    // 测试查找性能
    auto contains_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; i++) {
        EXPECT_TRUE(tree.contains("Data" + std::to_string(i*10)));
    }
    auto contains_end = std::chrono::high_resolution_clock::now();
    auto contains_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        contains_end - contains_start).count();
    
    // 测试证明生成性能
    auto proof_start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; i++) {
        tree.generate_proof("Data" + std::to_string(i*100));
    }
    auto proof_end = std::chrono::high_resolution_clock::now();
    auto proof_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        proof_end - proof_start).count();
    
    // 输出结果
    std::cout << "Performance results for " << NUM_INSERTS << " items:\n"
              << "  Insert: " << insert_duration << "ms\n"
              << "  Contains (1000 queries): " << contains_duration << "μs\n"
              << "  Proof generation (100 proofs): " << proof_duration << "ms\n";
}

TEST_F(MerkleTreeTest, TreeStructureValidity) {
    // 插入四个节点形成完全二叉树
    tree.insert("A");
    tree.insert("B");
    tree.insert("C");
    tree.insert("D");
    
    // 验证叶子计数
    EXPECT_EQ(tree.leaf_count(), 4);
    
    // 验证证明
    auto proof_a = tree.generate_proof("A");
    auto proof_b = tree.generate_proof("B");
    auto proof_c = tree.generate_proof("C");
    auto proof_d = tree.generate_proof("D");
    
    EXPECT_TRUE(MerkleTree::verify_proof(proof_a, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_b, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_c, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_d, tree.root_hash()));
    
    // 验证证明路径格式
    if (!proof_a.path.empty()) {
        EXPECT_EQ(proof_a.path.size(), 3);
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
