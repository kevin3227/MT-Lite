#include <gtest/gtest.h>
#include "../include/merkle_tree.h"

TEST(MerkleTreeTest, EmptyTree) {
    MerkleTree tree;
    EXPECT_TRUE(tree.root_hash().empty());
}

TEST(MerkleTreeTest, SingleInsert) {
    MerkleTree tree;
    tree.insert("tx1");
    EXPECT_FALSE(tree.root_hash().empty());
}

TEST(MerkleTreeTest, ProofVerification) {
    MerkleTree tree;
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

TEST(MerkleTreeTest, Contains) {
    MerkleTree tree;
    tree.insert("Data1");
    tree.insert("Data2");
    
    EXPECT_TRUE(tree.contains("Data1"));
    EXPECT_TRUE(tree.contains("Data2"));
    EXPECT_FALSE(tree.contains("Data3"));
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
