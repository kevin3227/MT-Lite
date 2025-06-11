#include "merkle_tree.h"
#include "sha3.h"
#include <algorithm>

std::string MerkleTree::hash_data(const std::string& data) {
    sha3_ctx_t ctx;  // 使用 sha3_ctx_t 替代 sha3_context
    uint8_t hash[32]; // SHA3-256输出固定32字节
    
    sha3_init(&ctx, 32); // 32字节 = 256位
    sha3_update(&ctx, data.data(), data.size());
    sha3_final(hash, &ctx);
    
    return std::string(reinterpret_cast<char*>(hash), 32);
}

std::shared_ptr<MerkleNode> MerkleTree::build_parent(
    const std::shared_ptr<MerkleNode>& left,
    const std::shared_ptr<MerkleNode>& right) {
    
    std::string combined_hash = left->hash + (right ? right->hash : "");
    auto parent = std::make_shared<MerkleNode>(hash_data(combined_hash));
    
    parent->left = left;
    parent->right = right;
    left->parent = parent;
    if (right) right->parent = parent;
    
    return parent;
}

void MerkleTree::insert(const std::string& data) {
    auto leaf = std::make_shared<MerkleNode>(hash_data(data));
    leaves_.push_back(leaf);
    
    // 重建树（简化版，后续可优化为增量更新）
    std::vector<std::shared_ptr<MerkleNode>> nodes = leaves_;
    while (nodes.size() > 1) {
        std::vector<std::shared_ptr<MerkleNode>> parents;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            auto left = nodes[i];
            auto right = (i + 1 < nodes.size()) ? nodes[i + 1] : nullptr;
            parents.push_back(build_parent(left, right));
        }
        nodes = std::move(parents);
    }
    root_ = nodes.empty() ? nullptr : nodes[0];
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
    
    // 1. 计算目标叶子哈希
    const std::string target_hash = hash_data(data);
    
    // 2. 查找叶子节点
    auto leaf_iter = std::find_if(leaves_.begin(), leaves_.end(),
        [&target_hash](const auto& node) {
            return node->hash == target_hash;
        });
    
    if (leaf_iter == leaves_.end()) {
        return proof; // 未找到返回空证明
    }
    
    // 3. 保存叶子哈希
    proof.leaf = target_hash;
    
    // 4. 向上追溯路径
    auto current_node = *leaf_iter;
    while (auto parent = current_node->parent.lock()) {
        // 判断当前节点是左子节点还是右子节点
        const bool is_right_child = (parent->right && parent->right->hash == current_node->hash);
        
        // 获取兄弟节点
        auto sibling = is_right_child ? parent->left : parent->right;
        
        if (sibling) {
            // 记录兄弟节点的哈希和方向
            proof.path.emplace_back(is_right_child, sibling->hash);
        }
        
        current_node = parent;
    }
    
    return proof;
}

bool MerkleTree::verify_proof(const Proof& proof, const std::string& root_hash) {
    std::string current_hash = proof.leaf;
    
    for (const auto& [isRight, sibling_hash] : proof.path) {
        if (isRight) {
            current_hash = hash_data(sibling_hash + current_hash);
        } else {
            current_hash = hash_data(current_hash + sibling_hash);
        }
    }
    
    return current_hash == root_hash;
}

// 其他方法实现...
