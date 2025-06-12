#include "merkle_tree.h"
#include "sha3.h"
#include <algorithm>

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
    std::lock_guard<std::mutex> lock(insert_mutex_); // 确保线程安全
    auto leaf = std::make_shared<MerkleNode>(hash_data(data));
    node_counter_++;
    leaves_.push_back(leaf);
    
    // 增量更新开始
    merge_stack_.push(leaf);
    process_merge_stack();
    
    // 当栈中仅剩一个节点时，就是当前的根
    if (merge_stack_.size() == 1) {
        root_ = merge_stack_.top();
    }
}

bool MerkleTree::contains(const std::string& data) const {
    std::string target_hash = hash_data(data);
    return std::any_of(leaves_.begin(), leaves_.end(),
                       [&target_hash](const std::shared_ptr<MerkleNode>& leaf) {
                           return leaf->hash == target_hash;
                       });
}

MerkleTree::Proof MerkleTree::generate_proof(const std::string& data) const {
    Proof proof;
    const std::string target_hash = hash_data(data);
    
    auto leaf_iter = std::find_if(leaves_.begin(), leaves_.end(),
        [&target_hash](const auto& node) { return node->hash == target_hash; });
    if (leaf_iter == leaves_.end()) return proof;
    
    proof.leaf = target_hash;
    auto current_node = *leaf_iter;
    
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
    std::string current_hash = proof.leaf;
    
    for (const auto& [isRight, sibling_hash] : proof.path) {
        current_hash = isRight ? 
            hash_data(sibling_hash + current_hash) : 
            hash_data(current_hash + sibling_hash);
    }
    return current_hash == root_hash;
}
