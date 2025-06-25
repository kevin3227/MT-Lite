#include <gtest/gtest.h>
#include "../include/merkle_tree.h"
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>
#include <random>
#include <algorithm>

class MerkleTreeTest : public ::testing::Test {
protected:
    MerkleTree tree;
};

// 基本功能测试
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

// 增量式重建测试
TEST_F(MerkleTreeTest, IncrementalRebuild) {
    // 初始状态
    EXPECT_EQ(tree.node_count(), 0);
    
    // 插入第一个节点
    tree.insert("A");
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), 1); // 只有叶子节点
    std::string root_a = tree.root_hash();
    
    // 插入第二个节点
    tree.insert("B");
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_EQ(tree.node_count(), 3); // 2叶子 + 1父节点
    std::string root_ab = tree.root_hash();
    EXPECT_NE(root_a, root_ab); // 根哈希应该改变
    
    // 插入第三个节点
    tree.insert("C");
    EXPECT_EQ(tree.leaf_count(), 3);
    std::string root_abc = tree.root_hash();
    EXPECT_NE(root_ab, root_abc); // 根哈希应该改变
    
    // 验证所有节点的证明
    auto proof_a = tree.generate_proof("A");
    auto proof_b = tree.generate_proof("B");
    auto proof_c = tree.generate_proof("C");
    
    EXPECT_TRUE(MerkleTree::verify_proof(proof_a, root_abc));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_b, root_abc));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_c, root_abc));
    
    // 验证证明路径长度在合理范围内
    int expected_path_length = std::ceil(std::log2(3));
    EXPECT_LE(proof_a.path.size(), expected_path_length + 1);
    EXPECT_LE(proof_b.path.size(), expected_path_length + 1);
    EXPECT_LE(proof_c.path.size(), expected_path_length + 1);
}

// 测试树结构在增量式重建后的平衡性
TEST_F(MerkleTreeTest, TreeBalanceAfterIncrementalRebuild) {
    // 插入多个节点
    for (int i = 0; i < 10; i++) {
        tree.insert("Item" + std::to_string(i));
    }
    
    // 验证树的高度在合理范围内
    int expected_height = std::ceil(std::log2(10)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
    
    // 验证所有节点的证明路径长度
    for (int i = 0; i < 10; i++) {
        auto proof = tree.generate_proof("Item" + std::to_string(i));
        EXPECT_TRUE(MerkleTree::verify_proof(proof, tree.root_hash()));
        EXPECT_LE(proof.path.size(), expected_height);
    }
    
    std::cout << "Tree with 10 nodes:\n"
              << "  Height: " << tree.height() << "\n"
              << "  Expected max height: " << expected_height + 1 << std::endl;
}

// 测试交替的增量式重建和完全重建
TEST_F(MerkleTreeTest, MixedRebuildStrategies) {
    // 插入足够多的节点触发完全重建
    for (int i = 0; i < 150; i++) {
        tree.insert("BatchItem" + std::to_string(i));
    }
    
    std::string root_after_full_rebuild = tree.root_hash();
    
    // 再插入几个节点，应该使用增量重建
    for (int i = 0; i < 5; i++) {
        tree.insert("IncrementalItem" + std::to_string(i));
    }
    
    std::string root_after_incremental = tree.root_hash();
    EXPECT_NE(root_after_full_rebuild, root_after_incremental);
    
    // 验证所有节点都可以生成有效证明
    auto proof1 = tree.generate_proof("BatchItem42");
    auto proof2 = tree.generate_proof("IncrementalItem3");
    
    EXPECT_TRUE(MerkleTree::verify_proof(proof1, root_after_incremental));
    EXPECT_TRUE(MerkleTree::verify_proof(proof2, root_after_incremental));
    
    // 验证树高度仍在合理范围内
    int expected_height = std::ceil(std::log2(155)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
}

// 高并发测试
TEST_F(MerkleTreeTest, ConcurrentIncrementalRebuild) {
    constexpr int THREAD_COUNT = 8;
    constexpr int PER_THREAD = 100;
    std::vector<std::thread> threads;
    std::atomic<int> insert_count{0};
    
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
    
    // 验证树高度在合理范围内
    int expected_height = std::ceil(std::log2(THREAD_COUNT * PER_THREAD)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
    
    // 性能报告
    std::cout << "Concurrent test with incremental rebuild:\n"
              << "  Inserted " << insert_count << " items with " << THREAD_COUNT << " threads\n"
              << "  Duration: " << duration << "ms\n"
              << "  Tree height: " << tree.height() << "\n"
              << "  Expected max height: " << expected_height + 1 << std::endl;
}

// 随机插入顺序测试
TEST_F(MerkleTreeTest, RandomInsertionOrder) {
    constexpr int ITEM_COUNT = 200;
    
    // 创建随机排序的数据项
    std::vector<std::string> items;
    for (int i = 0; i < ITEM_COUNT; i++) {
        items.push_back("RandomItem" + std::to_string(i));
    }
    
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(items.begin(), items.end(), g);
    
    // 随机顺序插入
    for (const auto& item : items) {
        tree.insert(item);
    }
    
    // 验证所有项都已插入
    for (const auto& item : items) {
        EXPECT_TRUE(tree.contains(item));
    }
    
    // 验证树高度在合理范围内
    int expected_height = std::ceil(std::log2(ITEM_COUNT)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
    
    // 验证随机选择的项的证明
    auto proof = tree.generate_proof(items[ITEM_COUNT/2]);
    EXPECT_TRUE(MerkleTree::verify_proof(proof, tree.root_hash()));
    EXPECT_LE(proof.path.size(), expected_height);
    
    std::cout << "Random insertion order test:\n"
              << "  Tree height: " << tree.height() << "\n"
              << "  Expected max height: " << expected_height + 1 << "\n"
              << "  Proof path length: " << proof.path.size() << std::endl;
}

// 批量插入与增量重建混合测试
TEST_F(MerkleTreeTest, MixedBatchAndIncrementalInsert) {
    // 首先批量插入
    std::vector<std::string> batch_items;
    for (int i = 0; i < 100; i++) {
        batch_items.push_back("BatchItem" + std::to_string(i));
    }
    tree.batch_insert(batch_items);
    
    std::string root_after_batch = tree.root_hash();
    
    // 然后进行增量插入
    for (int i = 0; i < 10; i++) {
        tree.insert("IncrItem" + std::to_string(i));
    }
    
    std::string root_after_incr = tree.root_hash();
    EXPECT_NE(root_after_batch, root_after_incr);
    
    // 验证所有项都可以生成有效证明
    for (int i = 0; i < 10; i++) {
        int batch_idx = i * 10;
        auto batch_proof = tree.generate_proof("BatchItem" + std::to_string(batch_idx));
        auto incr_proof = tree.generate_proof("IncrItem" + std::to_string(i));
        
        EXPECT_TRUE(MerkleTree::verify_proof(batch_proof, root_after_incr));
        EXPECT_TRUE(MerkleTree::verify_proof(incr_proof, root_after_incr));
    }
    
    // 验证树高度在合理范围内
    int expected_height = std::ceil(std::log2(110)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
    
    std::cout << "Mixed batch and incremental insert test:\n"
              << "  Tree height: " << tree.height() << "\n"
              << "  Expected max height: " << expected_height + 1 << std::endl;
}

// 大规模树测试
TEST_F(MerkleTreeTest, LargeTreeWithIncrementalRebuild) {
    // 创建一个较大的树（1000个节点）
    std::vector<std::string> items;
    for (int i = 0; i < 900; i++) {
        items.push_back("LargeItem" + std::to_string(i));
    }
    
    // 批量插入大部分节点
    tree.batch_insert(items);
    
    // 增量插入剩余节点
    for (int i = 900; i < 1000; i++) {
        tree.insert("LargeItem" + std::to_string(i));
    }
    
    // 验证树的基本属性
    EXPECT_EQ(tree.leaf_count(), 1000);
    
    // 计算预期的树高度
    int expected_height = std::ceil(std::log2(1000)) + 1;
    EXPECT_LE(tree.height(), expected_height + 1);
    
    // 验证随机选择的项的证明
    auto batch_proof = tree.generate_proof("LargeItem500");
    auto incr_proof = tree.generate_proof("LargeItem950");
    
    EXPECT_TRUE(MerkleTree::verify_proof(batch_proof, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(incr_proof, tree.root_hash()));
    
    // 验证路径长度在合理范围内
    EXPECT_LE(batch_proof.path.size(), expected_height);
    EXPECT_LE(incr_proof.path.size(), expected_height);
    
    // std::cout << "Large tree with incremental rebuild:\n"
    //           << "  Tree height: " << tree.height() << "\n"
    //           << "  Expected max height: " << expected_height + 1 << "\n"
    //           << "  Batch proof path length: " << batch_proof.path.size() << "\n"
    //           << "  Incremental proof path length: " << incr_proof.path.size() << std::endl;
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
