#include "merkle_tree.h"
#include <algorithm>
#include <string.h>
#include <cstring>
#include <openssl/evp.h>

using LockType = std::shared_mutex;
using ReadLock = std::shared_lock<LockType>;
using WriteLock = std::unique_lock<LockType>;

std::string MerkleTree::hash_data(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    uint8_t hash[32];
    unsigned int hash_len;

    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(hash), 32);
}

std::shared_ptr<MerkleNode> MerkleTree::build_parent(
    const std::shared_ptr<MerkleNode>& left,
    const std::shared_ptr<MerkleNode>& right) {
    
    std::string combined_hash = left->hash + (right ? right->hash : "");
    auto parent = std::make_shared<MerkleNode>(hash_data(combined_hash));
    node_counter_++;
    
    parent->left = left;
    parent->right = right;
    left->parent = parent;
    if (right) right->parent = parent;
    
    return parent;
}

void MerkleTree::process_merge_stack() {
    while (merge_stack_.size() >= 2) {
        auto right = merge_stack_.top();
        merge_stack_.pop();
        auto left = merge_stack_.top();
        merge_stack_.pop();
        
        merge_stack_.push(build_parent(left, right));
    }
}

void MerkleTree::insert(const std::string& data) {
    auto leaf_hash = hash_data(data);
    
    // 双重检查避免重复插入
    {
        std::shared_lock read_lock(index_mutex_);
        if (leaf_map_.find(leaf_hash) != leaf_map_.end()) return;
    }
    
    auto leaf = std::make_shared<MerkleNode>(leaf_hash);
    {
        std::unique_lock idx_lock(index_mutex_);
        std::unique_lock struct_lock(structure_mutex_);
        
        if (leaf_map_.count(leaf_hash)) return; // 再次检查
        
        // 更新叶子映射
        leaf_map_.emplace(leaf_hash, leaf);
        merge_stack_.push(leaf);
        node_counter_++;
    }
    
    // 使用较细粒度锁处理合并
    std::unique_lock struct_lock(structure_mutex_);
    process_merge_stack();
    
    if (merge_stack_.size() == 1) {
        root_ = merge_stack_.top();
        version_++; // 树结构变化时更新版本
    }
}

bool MerkleTree::contains(const std::string& data) const {
    const std::string target_hash = hash_data(data);
    
    // 使用读写锁的读锁保护索引访问
    std::shared_lock lock(index_mutex_);
    
    // 直接查找哈希值是否存在
    return leaf_map_.find(target_hash) != leaf_map_.end();
}

MerkleTree::Proof MerkleTree::generate_proof(const std::string& data) const {
    Proof proof;
    const std::string target_hash = hash_data(data);
    std::shared_ptr<MerkleNode> target_leaf;
    
    // 只保护索引访问
    {
        std::shared_lock read_lock(index_mutex_);
        auto leaf_iter = leaf_map_.find(target_hash);
        if (leaf_iter == leaf_map_.end()) return proof;
        target_leaf = leaf_iter->second;
    }
    
    // 无锁路径计算
    uint64_t start_version = version_.load(std::memory_order_acquire);
    proof.leaf = target_leaf->hash;
    auto current_node = target_leaf;
    
    while (auto parent = current_node->parent.lock()) {
        const bool is_right_child = (parent->right == current_node);
        auto sibling = is_right_child ? parent->left : parent->right;
        
        if (sibling) {
            proof.path.emplace_back(is_right_child, sibling->hash);
        }
        current_node = parent;
    }
    
    // 检查并发修改
    if (version_.load(std::memory_order_acquire) != start_version) {
        return {}; // 版本变化，返回空证明
    }
    return proof;
}

bool MerkleTree::verify_proof(const Proof& proof, const std::string& root_hash) {
    if (proof.path.empty() || proof.leaf.empty() || root_hash.size() != 32) 
        return false;

    alignas(16) uint8_t current_hash[32];
    alignas(16) uint8_t temp_buf[64];
    unsigned int hash_len;

    if (proof.leaf.size() != 32) return false;
    std::memcpy(current_hash, proof.leaf.data(), 32);

    for (const auto& [isRight, sibling] : proof.path) {
        if (sibling.size() != 32) return false;
        
        const uint8_t* first = current_hash;
        const uint8_t* second = reinterpret_cast<const uint8_t*>(sibling.data());
        
        if (isRight) {
            std::memcpy(temp_buf, second, 32);
            std::memcpy(temp_buf + 32, first, 32);
        } else {
            std::memcpy(temp_buf, first, 32);
            std::memcpy(temp_buf + 32, second, 32);
        }
        
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
        EVP_DigestUpdate(ctx, temp_buf, 64);
        EVP_DigestFinal_ex(ctx, current_hash, &hash_len);
        EVP_MD_CTX_free(ctx);
    }
    
    return __builtin_memcmp(current_hash, root_hash.data(), 32) == 0;
}
