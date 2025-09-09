#include <gtest/gtest.h>
#include "../include/merkle_tree.h"
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <random>
#include <algorithm>

class MerkleTreeTest : public ::testing::Test {
protected:
    MerkleTree tree;
    
    // 在每个测试用例后刷新缓冲区
    void TearDown() override {
        tree.flush();
    }
};

// 基本功能测试
TEST_F(MerkleTreeTest, EmptyTree) {
    EXPECT_TRUE(tree.root_hash().empty());
    EXPECT_EQ(tree.node_count(), 0);
    EXPECT_EQ(tree.leaf_count(), 0);
}

TEST_F(MerkleTreeTest, SingleInsert) {
    tree.insert("tx1");
    tree.flush(); // 确保异步插入已处理
    
    EXPECT_FALSE(tree.root_hash().empty());
    EXPECT_EQ(tree.node_count(), 1);
    EXPECT_EQ(tree.leaf_count(), 1);
}

TEST_F(MerkleTreeTest, ProofVerification) {
    tree.insert("Data1");
    tree.insert("Data2");
    tree.insert("Data3");
    tree.flush(); // 确保异步插入已处理
    
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
    tree.flush(); // 确保异步插入已处理
    
    EXPECT_TRUE(tree.contains("Data1"));
    EXPECT_TRUE(tree.contains("Data2"));
    EXPECT_FALSE(tree.contains("Data3"));
}

TEST_F(MerkleTreeTest, DuplicatePrevention) {
    tree.insert("Duplicate");
    tree.flush();
    size_t first_insert_count = tree.node_count();
    
    tree.insert("Duplicate");
    tree.insert("Duplicate");
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), first_insert_count);
}

// 增量式重建测试
TEST_F(MerkleTreeTest, IncrementalRebuild) {
    // 初始状态
    EXPECT_EQ(tree.node_count(), 0);
    
    // 插入第一个节点
    tree.insert("A");
    tree.flush();
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), 1); // 只有叶子节点
    std::string root_a = tree.root_hash();
    
    // 插入第二个节点
    tree.insert("B");
    tree.flush();
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_EQ(tree.node_count(), 3); // 2叶子 + 1父节点
    std::string root_ab = tree.root_hash();
    EXPECT_NE(root_a, root_ab); // 根哈希应该改变
    
    // 插入第三个节点
    tree.insert("C");
    tree.flush();
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
}

// 批量插入测试
TEST_F(MerkleTreeTest, BatchInsert) {
    std::vector<std::string> batch1 = {"Item1", "Item2", "Item3"};
    tree.batch_insert(batch1);
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 3);
    EXPECT_TRUE(tree.contains("Item1"));
    EXPECT_TRUE(tree.contains("Item2"));
    EXPECT_TRUE(tree.contains("Item3"));
    
    std::string root1 = tree.root_hash();
    
    // 再插入一批
    std::vector<std::string> batch2 = {"Item4", "Item5"};
    tree.batch_insert(batch2);
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 5);
    EXPECT_TRUE(tree.contains("Item4"));
    EXPECT_TRUE(tree.contains("Item5"));
    
    // 根哈希应该变化
    EXPECT_NE(root1, tree.root_hash());
    
    // 验证证明
    auto proof = tree.generate_proof("Item3");
    EXPECT_TRUE(MerkleTree::verify_proof(proof, tree.root_hash()));
}

// 并发插入测试
TEST_F(MerkleTreeTest, ConcurrentInsert) {
    const int THREAD_COUNT = 4;
    const int PER_THREAD = 50;
    
    std::vector<std::thread> threads;
    
    for (int i = 0; i < THREAD_COUNT; i++) {
        threads.emplace_back([this, i, PER_THREAD] {
            for (int j = 0; j < PER_THREAD; j++) {
                std::string data = "Thread" + std::to_string(i) + 
                                  "-Item" + std::to_string(j);
                tree.insert(data);
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    tree.flush();
    
    // 验证插入数量
    EXPECT_EQ(tree.leaf_count(), THREAD_COUNT * PER_THREAD);
    
    // 验证随机样本存在
    EXPECT_TRUE(tree.contains("Thread0-Item10"));
    EXPECT_TRUE(tree.contains("Thread3-Item40"));
    
    // 验证证明系统
    auto proof = tree.generate_proof("Thread1-Item25");
    EXPECT_TRUE(MerkleTree::verify_proof(proof, tree.root_hash()));
}

// 混合批量和单点插入测试
TEST_F(MerkleTreeTest, MixedBatchAndSingleInsert) {
    // 批量插入
    std::vector<std::string> batch = {"Batch1", "Batch2", "Batch3"};
    tree.batch_insert(batch);
    
    // 单点插入
    tree.insert("Single1");
    tree.insert("Single2");
    
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 5);
    EXPECT_TRUE(tree.contains("Batch1"));
    EXPECT_TRUE(tree.contains("Single1"));
    
    // 验证证明
    auto batch_proof = tree.generate_proof("Batch2");
    auto single_proof = tree.generate_proof("Single2");
    
    EXPECT_TRUE(MerkleTree::verify_proof(batch_proof, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(single_proof, tree.root_hash()));
}

// 测试批量插入中的去重功能
TEST_F(MerkleTreeTest, BatchDuplicateHandling) {
    // 先插入一个项目
    tree.insert("Duplicate");
    tree.flush();
    
    size_t initial_count = tree.leaf_count();
    
    // 批量插入包含重复项
    std::vector<std::string> batch = {"New1", "Duplicate", "New2", "Duplicate", "New1"};
    tree.batch_insert(batch);
    tree.flush();
    
    // 应该只添加了2个新项目
    EXPECT_EQ(tree.leaf_count(), initial_count + 2);
    EXPECT_TRUE(tree.contains("New1"));
    EXPECT_TRUE(tree.contains("New2"));
}

// 测试在没有插入的情况下刷新缓冲区
TEST_F(MerkleTreeTest, FlushWithoutInsert) {
    // 初始状态
    EXPECT_EQ(tree.node_count(), 0);
    
    // 刷新空缓冲区
    tree.flush();
    
    // 应该没有变化
    EXPECT_EQ(tree.node_count(), 0);
    EXPECT_TRUE(tree.root_hash().empty());
}

// 测试批量插入空列表
TEST_F(MerkleTreeTest, BatchInsertEmpty) {
    std::vector<std::string> empty_batch;
    tree.batch_insert(empty_batch);
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 0);
    EXPECT_TRUE(tree.root_hash().empty());
}

// 快照功能测试
TEST_F(MerkleTreeTest, CreateSnapshot) {
    // 创建初始树
    tree.insert("A");
    tree.insert("B");
    tree.insert("C");
    tree.flush();
    
    // 记录初始状态
    std::string original_root = tree.root_hash();
    size_t original_size = tree.leaf_count();
    
    // 创建快照
    auto snapshot = tree.create_snapshot();
    
    // 确认快照正确保存了状态
    EXPECT_EQ(snapshot->root_hash(), original_root);
    EXPECT_EQ(snapshot->size(), original_size);
    EXPECT_TRUE(snapshot->contains("A"));
    EXPECT_TRUE(snapshot->contains("B"));
    EXPECT_TRUE(snapshot->contains("C"));
    
    // 修改原树
    tree.insert("D");
    tree.insert("E");
    tree.flush();
    
    // 确认原树已修改
    EXPECT_NE(tree.root_hash(), original_root);
    EXPECT_EQ(tree.leaf_count(), original_size + 2);
    
    // 确认快照保持不变
    EXPECT_EQ(snapshot->root_hash(), original_root);
    EXPECT_EQ(snapshot->size(), original_size);
    EXPECT_FALSE(snapshot->contains("D"));
}

TEST_F(MerkleTreeTest, GenerateProofFromSnapshot) {
    // 创建初始树
    tree.insert("Data1");
    tree.insert("Data2");
    tree.insert("Data3");
    tree.flush();
    
    // 创建快照
    auto snapshot = tree.create_snapshot();
    
    // 从快照生成证明
    auto proof = snapshot->generate_proof("Data2");
    
    // 验证证明
    EXPECT_TRUE(MerkleTree::verify_proof(proof, snapshot->root_hash()));
    
    // 修改原树后，快照的证明仍然有效
    tree.insert("Data4");
    tree.flush();
    
    EXPECT_TRUE(MerkleTree::verify_proof(proof, snapshot->root_hash()));
}

TEST_F(MerkleTreeTest, ResetToSnapshot) {
    // 创建初始树
    tree.insert("A");
    tree.insert("B");
    tree.flush();
    
    std::string original_root = tree.root_hash();
    
    // 创建快照
    auto snapshot = tree.create_snapshot();
    
    // 修改树
    tree.insert("C");
    tree.insert("D");
    tree.flush();
    
    std::string modified_root = tree.root_hash();
    EXPECT_NE(original_root, modified_root);
    
    // 重置到快照
    tree.reset_to_snapshot(snapshot);
    
    // 验证树已重置
    EXPECT_EQ(tree.root_hash(), original_root);
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_TRUE(tree.contains("A"));
    EXPECT_TRUE(tree.contains("B"));
    EXPECT_FALSE(tree.contains("C"));
    EXPECT_FALSE(tree.contains("D"));
}

TEST_F(MerkleTreeTest, ClearTree) {
    // 填充树
    tree.insert("A");
    tree.insert("B");
    tree.flush();
    
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_FALSE(tree.root_hash().empty());
    
    // 清空树
    tree.clear();
    
    // 验证树已清空
    EXPECT_EQ(tree.leaf_count(), 0);
    EXPECT_TRUE(tree.root_hash().empty());
    EXPECT_FALSE(tree.contains("A"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
