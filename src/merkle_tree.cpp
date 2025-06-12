#include "merkle_tree.h"
#include "sha3.h"
#include <algorithm>

using LockType = std::shared_mutex;
using ReadLock = std::shared_lock<LockType>;
using WriteLock = std::unique_lock<LockType>;

std::string MerkleTree::hash_data(const std::string& data) {
    sha3_ctx_t ctx;
    uint8_t hash[32];
    
    sha3_init(&ctx, 32);
    sha3_update(&ctx, data.data(), data.size());
    sha3_final(hash, &ctx);
    
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
    WriteLock lock(mutex_); // 写操作独占锁
    
    auto leaf_hash = hash_data(data);
    
    // 关键优化点1：快速检查重复插入
    if (leaf_map_.find(leaf_hash) != leaf_map_.end()) return;
    
    auto leaf = std::make_shared<MerkleNode>(leaf_hash);
    node_counter_++;
    
    // 关键优化点2：更新索引映射
    leaf_map_.emplace(leaf_hash, leaf);
    
    // 增量更新开始
    merge_stack_.push(leaf);
    process_merge_stack();
    
    // 当栈中仅剩一个节点时，就是当前的根
    if (merge_stack_.size() == 1) {
        root_ = merge_stack_.top();
    }
}

bool MerkleTree::contains(const std::string& data) const {
    ReadLock lock(mutex_); // 读操作共享锁
    
    // 关键优化点3：哈希查找O(1)复杂度
    return leaf_map_.find(hash_data(data)) != leaf_map_.end();
}

MerkleTree::Proof MerkleTree::generate_proof(const std::string& data) const {
    Proof proof;
    WriteLock lock(mutex_); // 证明生成需要暂时升级为写锁（保证树结构不变）
    
    const std::string target_hash = hash_data(data);
    
    // 关键优化点4：直接定位叶子节点
    auto leaf_iter = leaf_map_.find(target_hash);
    if (leaf_iter == leaf_map_.end()) return proof;
    
    proof.leaf = target_hash;
    auto current_node = leaf_iter->second;
    
    // 向上遍历到根节点构建路径
    while (auto parent = current_node->parent.lock()) {
        const bool is_right_child = (parent->right && parent->right->hash == current_node->hash);
        auto sibling = is_right_child ? parent->left : parent->right;
        
        if (sibling) {
            proof.path.emplace_back(is_right_child, sibling->hash);
        }
        current_node = parent;
    }
    return proof;
}

bool MerkleTree::verify_proof(const Proof& proof, const std::string& root_hash) {
    // 静态方法，无需锁定
    if (proof.path.empty() || proof.leaf.empty()) return false;
    
    std::string current_hash = proof.leaf;
    
    for (const auto& [isRight, sibling_hash] : proof.path) {
        current_hash = isRight ? 
            hash_data(sibling_hash + current_hash) : 
            hash_data(current_hash + sibling_hash);
    }
    return current_hash == root_hash;
}
