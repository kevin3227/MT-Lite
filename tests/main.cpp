#include <gtest/gtest.h>
#include "../include/merkle_tree.h"
#include <chrono>
#include <iostream>

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
        auto invalid_proof = tree.generate_proof("Data99");
        EXPECT_FALSE(MerkleTree::verify_proof(invalid_proof, tree.root_hash()));
    }
    
    {
        auto tampered_proof = tree.generate_proof("Data1");
        tampered_proof.path[0].second[0] ^= 0xFF; // 修改哈希值
        EXPECT_FALSE(MerkleTree::verify_proof(tampered_proof, tree.root_hash()));
    }
}

TEST_F(MerkleTreeTest, Contains) {
    tree.insert("Data1");
    tree.insert("Data2");
    
    EXPECT_TRUE(tree.contains("Data1"));
    EXPECT_TRUE(tree.contains("Data2"));
    EXPECT_FALSE(tree.contains("Data3"));
}

TEST_F(MerkleTreeTest, IncrementalUpdate) {
    // 初始状态
    EXPECT_EQ(tree.node_count(), 0);
    
    // 插入第一个节点
    tree.insert("A");
    EXPECT_EQ(tree.leaf_count(), 1);
    EXPECT_EQ(tree.node_count(), 1);
    
    // 插入第二个节点
    tree.insert("B");
    EXPECT_EQ(tree.leaf_count(), 2);
    EXPECT_EQ(tree.node_count(), 3); // 2 叶子 + 1 父节点
    
    // 保存根哈希
    std::string root_ab = tree.root_hash();
    
    // 插入第三个节点
    tree.insert("C");
    EXPECT_EQ(tree.leaf_count(), 3);
    EXPECT_EQ(tree.node_count(), 5); // 3 叶子 + 2 父节点
}

TEST_F(MerkleTreeTest, PerformanceComparison) {
    constexpr int NUM_INSERTS = 1000;
    MerkleTree tree;
    
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < NUM_INSERTS; i++) {
        tree.insert("Data" + std::to_string(i));
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "Inserted " << NUM_INSERTS << " items in " << duration << "ms" << std::endl;
    
    // 验证最终树结构
    EXPECT_TRUE(MerkleTree::verify_proof(tree.generate_proof("Data500"), tree.root_hash()));
}

TEST_F(MerkleTreeTest, TreeStructureValidity) {
    // 插入四个节点形成完全二叉树
    MerkleTree tree;
    tree.insert("A");
    tree.insert("B");
    tree.insert("C");
    tree.insert("D");
    
    // 验证证明
    auto proof_a = tree.generate_proof("A");
    auto proof_b = tree.generate_proof("B");
    auto proof_c = tree.generate_proof("C");
    auto proof_d = tree.generate_proof("D");
    
    EXPECT_TRUE(MerkleTree::verify_proof(proof_a, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_b, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_c, tree.root_hash()));
    EXPECT_TRUE(MerkleTree::verify_proof(proof_d, tree.root_hash()));
    
    // 验证叶子计数
    EXPECT_EQ(tree.leaf_count(), 4);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
