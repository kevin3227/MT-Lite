#include "merkle_tree.h"
#include <algorithm>
#include <string.h>
#include <cstring>
#include <openssl/evp.h>
#include <numeric>

// 线程局部哈希上下文
thread_local struct {
    EVP_MD_CTX* md_ctx;
    const EVP_MD* sha3;
    bool initialized;
} tls_hash_ctx = {nullptr, nullptr, false};

std::string MerkleTree::hash_data(const std::string& data) {
    // 线程局部缓存，避免重复计算
    thread_local std::unordered_map<std::string, std::string> hash_cache;
    
    // 检查缓存
    if (auto it = hash_cache.find(data); it != hash_cache.end()) {
        return it->second;
    }
    
    // 确保线程局部存储初始化
    if (!tls_hash_ctx.initialized) {
        tls_hash_ctx.md_ctx = EVP_MD_CTX_new();
        tls_hash_ctx.sha3 = EVP_sha3_256();
        tls_hash_ctx.initialized = true;
    }
    
    // 计算哈希
    unsigned char hash[32];
    EVP_DigestInit_ex(tls_hash_ctx.md_ctx, tls_hash_ctx.sha3, nullptr);
    EVP_DigestUpdate(tls_hash_ctx.md_ctx, data.data(), data.size());
    EVP_DigestFinal_ex(tls_hash_ctx.md_ctx, hash, nullptr);
    
    // 存入缓存并返回
    std::string result(reinterpret_cast<char*>(hash), 32);
    hash_cache.emplace(data, result);
    return result;
}

std::shared_ptr<MerkleNode> MerkleTree::build_parent(
    const std::shared_ptr<MerkleNode>& left,
    const std::shared_ptr<MerkleNode>& right) {
    
    // 组合哈希
    std::string combined_hash;
    if (right) {
        combined_hash = left->hash + right->hash;
    } else {
        combined_hash = left->hash + left->hash; // 如果没有右子节点，复制左子节点
    }
    
    // 创建父节点
    auto parent = std::make_shared<MerkleNode>(hash_data(combined_hash));
    node_counter_++;
    
    parent->left = left;
    parent->right = right ? right : left; // 如果没有右子节点，使用左子节点
    left->parent = parent;
    if (right) right->parent = parent;
    
    return parent;
}

void MerkleTree::rebuild_tree() {
    // 清空现有树结构
    root_ = nullptr;
    
    // 收集所有叶子节点
    std::vector<std::shared_ptr<MerkleNode>> nodes;
    nodes.reserve(leaf_map_.size());
    for (const auto& [hash, leaf] : leaf_map_) {
        nodes.push_back(leaf);
    }
    
    // 如果没有节点，直接返回
    if (nodes.empty()) return;
    
    // 自底向上构建平衡树
    while (nodes.size() > 1) {
        std::vector<std::shared_ptr<MerkleNode>> next_level;
        next_level.reserve((nodes.size() + 1) / 2);
        
        for (size_t i = 0; i < nodes.size(); i += 2) {
            if (i + 1 < nodes.size()) {
                // 有右节点，创建完整父节点
                auto parent = build_parent(nodes[i], nodes[i+1]);
                next_level.push_back(parent);
            } else {
                // 没有右节点，单独提升
                auto parent = build_parent(nodes[i], nullptr);
                next_level.push_back(parent);
            }
        }
        
        nodes = std::move(next_level);
    }
    
    // 设置根节点
    root_ = nodes[0];
    version_++;
}

void MerkleTree::incremental_rebuild(const std::shared_ptr<MerkleNode>& new_leaf) {
    // 如果树为空，新叶子就是根
    if (!root_) {
        root_ = new_leaf;
        version_++;
        return;
    }
    
    // 特殊处理 3 个节点的情况，确保与完全重建兼容
    if (leaf_map_.size() == 3) {
        // 收集所有叶子节点
        std::vector<std::shared_ptr<MerkleNode>> leaves;
        leaves.reserve(3);
        for (const auto& [hash, leaf] : leaf_map_) {
            leaves.push_back(leaf);
        }
        
        // 创建一个完全二叉树结构
        // 首先，创建两个叶子的父节点
        auto parent1 = build_parent(leaves[0], leaves[1]);
        
        // 然后，创建一个包含第三个叶子的父节点
        auto parent2 = build_parent(leaves[2], nullptr);
        
        // 最后，创建根节点
        root_ = build_parent(parent1, parent2);
        
        version_++;
        return;
    }
    
    // 如果只有两个节点，创建一个简单的树
    if (leaf_map_.size() == 2) {
        // 找到另一个叶子节点
        std::shared_ptr<MerkleNode> other_leaf = nullptr;
        for (const auto& [hash, leaf] : leaf_map_) {
            if (leaf != new_leaf) {
                other_leaf = leaf;
                break;
            }
        }
        
        if (other_leaf) {
            root_ = build_parent(other_leaf, new_leaf);
            version_++;
        }
        return;
    }
    
    // 其他情况使用原来的增量重建逻辑
    // 查找合适的合并位置
    auto merge_candidate = find_merge_candidate(new_leaf);
    
    if (merge_candidate) {
        // 如果找到合适的合并位置，创建新的子树
        auto parent = merge_candidate->parent.lock();
        auto new_subtree = build_parent(merge_candidate, new_leaf);
        
        if (parent) {
            // 将新子树连接到父节点
            if (parent->left == merge_candidate) {
                parent->left = new_subtree;
            } else {
                parent->right = new_subtree;
            }
            new_subtree->parent = parent;
            
            // 更新路径上的哈希值
            update_path_hashes(parent);
        } else {
            // 如果没有父节点，新子树成为根
            root_ = new_subtree;
        }
    } else {
        // 如果没有找到合适的合并位置，创建新的根
        auto old_root = root_;
        root_ = build_parent(old_root, new_leaf);
    }
    
    version_++;
}

std::shared_ptr<MerkleNode> MerkleTree::find_merge_candidate(
    const std::shared_ptr<MerkleNode>& new_leaf) {
    
    // 使用层序遍历找到最适合合并的节点
    std::queue<std::shared_ptr<MerkleNode>> queue;
    queue.push(root_);
    
    std::shared_ptr<MerkleNode> candidate = nullptr;
    size_t min_height = SIZE_MAX;
    
    while (!queue.empty()) {
        auto node = queue.front();
        queue.pop();
        
        // 检查是否是叶子节点
        if (!node->left && !node->right) {
            // 计算该叶子节点的高度
            size_t height = 0;
            auto current = node;
            while (auto parent = current->parent.lock()) {
                height++;
                current = parent;
            }
            
            // 如果高度小于当前最小高度，更新候选节点
            if (height < min_height) {
                min_height = height;
                candidate = node;
            }
            continue;
        }
        
        // 将子节点加入队列
        if (node->left) queue.push(node->left);
        if (node->right) queue.push(node->right);
    }
    
    return candidate;
}

void MerkleTree::update_path_hashes(const std::shared_ptr<MerkleNode>& from_node) {
    auto current = from_node;
    
    while (current) {
        // 重新计算当前节点的哈希
        std::string combined_hash;
        if (current->left && current->right) {
            combined_hash = current->left->hash + current->right->hash;
        } else if (current->left) {
            combined_hash = current->left->hash + current->left->hash;
        }
        
        if (!combined_hash.empty()) {
            current->hash = hash_data(combined_hash);
        }
        
        // 向上移动到父节点
        current = current->parent.lock();
    }
}

void MerkleTree::insert(const std::string& data) {
    auto leaf_hash = hash_data(data);
    
    // 检查重复
    {
        std::shared_lock read_lock(index_mutex_);
        if (leaf_map_.find(leaf_hash) != leaf_map_.end()) return;
    }
    
    // 创建新叶子节点
    auto leaf = std::make_shared<MerkleNode>(leaf_hash);
    
    std::unique_lock idx_lock(index_mutex_);
    std::unique_lock struct_lock(structure_mutex_);
    
    // 再次检查重复
    if (leaf_map_.count(leaf_hash)) return;
    
    // 添加到叶子映射
    leaf_map_.emplace(leaf_hash, leaf);
    node_counter_++;
    
    // 决定使用增量重建还是完全重建
    if (leaf_map_.size() >= REBUILD_THRESHOLD || leaf_map_.size() <= 3) {
        // 小树或大树使用完全重建
        rebuild_tree();
    } else {
        // 中等大小的树使用增量重建
        incremental_rebuild(leaf);
    }
}

void MerkleTree::batch_insert(const std::vector<std::string>& items) {
    if (items.empty()) return;
    
    // 预计算所有哈希
    std::vector<std::string> hashes;
    hashes.reserve(items.size());
    
    for (const auto& item : items) {
        hashes.push_back(hash_data(item));
    }
    
    // 批量更新
    std::unique_lock idx_lock(index_mutex_);
    std::unique_lock struct_lock(structure_mutex_);
    
    bool tree_modified = false;
    
    // 添加新节点
    for (size_t i = 0; i < items.size(); i++) {
        const auto& hash = hashes[i];
        
        if (leaf_map_.count(hash) == 0) {
            auto leaf = std::make_shared<MerkleNode>(hash);
            leaf_map_.emplace(hash, leaf);
            node_counter_++;
            tree_modified = true;
        }
    }
    
    // 只在有变更时重建树
    if (tree_modified) {
        rebuild_tree();
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
    
    // 保护整个操作，避免树结构变化
    std::shared_lock read_lock(structure_mutex_);
    
    // 查找叶子节点
    std::shared_ptr<MerkleNode> leaf_node = nullptr;
    {
        std::shared_lock idx_lock(index_mutex_);
        auto it = leaf_map_.find(target_hash);
        if (it == leaf_map_.end()) return proof;
        leaf_node = it->second;
    }
    
    // 设置叶子哈希
    proof.leaf = target_hash;
    
    // 如果只有一个节点，返回空路径
    if (leaf_node == root_) {
        return proof;
    }
    
    // 从叶子向上遍历到根
    std::shared_ptr<MerkleNode> current = leaf_node;
    while (auto parent = current->parent.lock()) {
        bool is_right = (parent->right == current);
        auto sibling = is_right ? parent->left : parent->right;
        
        // 确保兄弟节点存在
        if (sibling) {
            proof.path.emplace_back(is_right, sibling->hash);
        } else {
            // 如果没有兄弟节点，使用当前节点的哈希（与树构建逻辑一致）
            proof.path.emplace_back(is_right, current->hash);
        }
        
        current = parent;
        if (current == root_) break;
    }
    
    return proof;
}

bool MerkleTree::verify_proof(const Proof& proof, const std::string& root_hash) {
    // 参数验证
    if (proof.leaf.empty() || root_hash.empty()) 
        return false;
    
    // 如果没有路径，直接比较叶子哈希和根哈希
    if (proof.path.empty())
        return proof.leaf == root_hash;
    
    // 计算从叶子到根的哈希
    std::string current_hash = proof.leaf;
    
    for (const auto& [isRight, sibling] : proof.path) {
        // 组合哈希（与build_parent逻辑一致）
        std::string combined;
        if (isRight) {
            combined = sibling + current_hash;
        } else {
            combined = current_hash + sibling;
        }
        
        // 计算父哈希
        current_hash = hash_data(combined);
    }
    
    // 比较最终哈希
    return current_hash == root_hash;
}

size_t MerkleTree::height() const {
    std::shared_lock lock(structure_mutex_);
    return calculate_height(root_);
}

size_t MerkleTree::calculate_height(const std::shared_ptr<MerkleNode>& node) const {
    if (!node) return 0;
    return 1 + std::max(
        calculate_height(node->left),
        calculate_height(node->right)
    );
}
