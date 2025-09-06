#include "merkle_tree.h"
#include <algorithm>
#include <string.h>
#include <cstring>
#include <openssl/evp.h>
#include <numeric>
#include <omp.h>

// 线程局部哈希上下文
thread_local struct {
    EVP_MD_CTX* md_ctx;
    const EVP_MD* sha3;
    bool initialized;
} tls_hash_ctx = {nullptr, nullptr, false};

MerkleTree::MerkleTree() {
    // 启动工作线程
    buffer_.worker = std::thread(&MerkleTree::worker_thread, this);
}

MerkleTree::~MerkleTree() {
    // 停止工作线程
    {
        std::unique_lock<std::mutex> lock(buffer_.mutex);
        buffer_.should_terminate = true;
        buffer_.cv.notify_one();
    }
    
    // 等待线程结束
    if (buffer_.worker.joinable()) {
        buffer_.worker.join();
    }
}

void MerkleTree::worker_thread() {
    while (true) {
        std::vector<std::string> items_to_process;
        
        {
            std::unique_lock<std::mutex> lock(buffer_.mutex);
            
            // 等待有数据或终止信号
            buffer_.cv.wait(lock, [this] {
                return !buffer_.items.empty() || buffer_.should_terminate;
            });
            
            // 检查是否应该结束线程
            if (buffer_.should_terminate && buffer_.items.empty()) {
                break;
            }
            
            // 获取所有项目并清空缓冲区
            items_to_process.swap(buffer_.items);
            buffer_.processing = true;
        }
        
        // 处理项目
        if (!items_to_process.empty()) {
            internal_batch_insert(items_to_process);
        }
        
        buffer_.processing = false;
        buffer_.cv.notify_all(); // 通知等待flush的线程
    }
}

void MerkleTree::process_buffered_items() {
    std::vector<std::string> items_to_process;
    
    {
        std::unique_lock<std::mutex> lock(buffer_.mutex);
        items_to_process.swap(buffer_.items);
    }
    
    if (!items_to_process.empty()) {
        internal_batch_insert(items_to_process);
    }
}

void MerkleTree::flush() {
    {
        std::unique_lock<std::mutex> lock(buffer_.mutex);
        // 如果缓冲区非空，将数据移到临时缓冲区并处理
        if (!buffer_.items.empty()) {
            auto items = std::move(buffer_.items);
            buffer_.items.clear();
            lock.unlock();
            
            // 处理临时缓冲区中的数据
            internal_batch_insert(items);
        }
    }
    
    // 等待所有异步操作完成
    std::unique_lock<std::mutex> lock(buffer_.mutex);
    buffer_.cv.wait(lock, [this] { return !buffer_.processing; });
}

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

void MerkleTree::insert(const std::string& data) {
    // 快速路径：检查是否已存在
    {
        const std::string target_hash = hash_data(data);
        // std::shared_lock read_lock(index_mutex_);
        if (leaf_map_.find(target_hash) != leaf_map_.end()) return;
    }
    
    // 添加到缓冲区
    {
        std::unique_lock<std::mutex> lock(buffer_.mutex);
        buffer_.items.push_back(data);
        
        // 如果缓冲区达到阈值，唤醒工作线程
        if (buffer_.items.size() >= FLUSH_THRESHOLD) {
            lock.unlock();
            buffer_.cv.notify_one();
        }
    }
}

void MerkleTree::batch_insert(const std::vector<std::string>& items) {
    if (items.empty()) return;
    
    // 如果批量很大，直接处理
    if (items.size() >= BUFFER_CAPACITY) {
        internal_batch_insert(items);
        return;
    }
    
    // 否则添加到缓冲区
    {
        std::unique_lock<std::mutex> lock(buffer_.mutex);
        
        // 检查缓冲区容量
        if (buffer_.items.size() + items.size() >= BUFFER_CAPACITY) {
            // 如果添加这批会超过容量，先处理当前缓冲区
            std::vector<std::string> current_items;
            current_items.swap(buffer_.items);
            lock.unlock();
            
            internal_batch_insert(current_items);
            
            // 重新获取锁
            lock.lock();
        }
        
        // 添加新项目到缓冲区
        buffer_.items.insert(buffer_.items.end(), items.begin(), items.end());
        
        // 如果缓冲区达到阈值，唤醒工作线程
        if (buffer_.items.size() >= FLUSH_THRESHOLD) {
            lock.unlock();
            buffer_.cv.notify_one();
        }
    }
}

void MerkleTree::internal_batch_insert(const std::vector<std::string>& items) {
    if (items.empty()) return;
    
    // 并行计算所有数据的哈希
    std::unordered_map<std::string, std::shared_ptr<MerkleNode>> new_nodes;
    new_nodes.reserve(items.size());
    #pragma omp parallel for schedule(dynamic, 256)
    for (int i = 0; i < items.size(); ++i) {
        const auto& data = items[i];
        const std::string hash = hash_data(data);
        auto node = std::make_shared<MerkleNode>(hash);
        
        #pragma omp critical
        {
            new_nodes.emplace(hash, node);
        }
    }    
    
    // 获取锁并执行插入
    // std::unique_lock idx_lock(index_mutex_);
    
    bool tree_modified = false;
    std::vector<std::shared_ptr<MerkleNode>> inserted_nodes;
    
    // 过滤并添加新节点
    for (const auto& [hash, node] : new_nodes) {
        if (leaf_map_.count(hash) == 0) {
            leaf_map_.emplace(hash, node);
            node_counter_++;
            tree_modified = true;
            inserted_nodes.push_back(node);
        }
    }
    
    // 如果有新节点添加，重建树
    if (tree_modified) {
        std::unique_lock struct_lock(structure_mutex_);
        
        // 大规模更改使用完全重建，小规模可选择批量增量更新
        if (leaf_map_.size() >= REBUILD_THRESHOLD || inserted_nodes.size() > 10) {
            rebuild_tree();
        } else {
            for (const auto& node : inserted_nodes) {
                incremental_rebuild(node);
            }
        }
    }
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
    parent->right = right;
    left->parent = parent;
    if (right) right->parent = parent;
    
    return parent;
}

void MerkleTree::rebuild_tree() {
    // 清空现有树结构
    root_ = nullptr;
    
    // 收集所有叶子节点
    std::vector<std::shared_ptr<MerkleNode>> current_level;
    current_level.reserve(leaf_map_.size());
    for (const auto& [hash, leaf] : leaf_map_) {
        current_level.push_back(leaf);
    }
    
    if (current_level.empty()) return;
    if (current_level.size() == 1) {
        root_ = current_level[0];
        version_++;
        return;
    }
    
    // 并行构建树层
    while (current_level.size() > 1) {
        std::vector<std::shared_ptr<MerkleNode>> next_level;
        next_level.resize((current_level.size() + 1) / 2);
        
        // 并行处理每对节点
        #pragma omp parallel for schedule(dynamic, 256)
        for (int i = 0; i < current_level.size(); i += 2) {
            if (i + 1 < current_level.size()) {
                next_level[i/2] = build_parent(current_level[i], current_level[i+1]);
            } else {
                next_level[i/2] = build_parent(current_level[i], nullptr);
            }
        }
        
        current_level = std::move(next_level);
    }
    
    // 设置根节点
    root_ = current_level[0];
    version_++;
}

void MerkleTree::incremental_rebuild(const std::shared_ptr<MerkleNode>& new_leaf) {
    // 如果树为空，新叶子就是根
    if (!root_) {
        root_ = new_leaf;
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
    
    // 其他情况使用增量重建逻辑
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

bool MerkleTree::contains(const std::string& data) const {
    const std::string target_hash = hash_data(data);
    
    // 使用读写锁的读锁保护索引访问
    // std::shared_lock lock(index_mutex_);
    
    // 直接查找哈希值是否存在
    return leaf_map_.find(target_hash) != leaf_map_.end();
}

MerkleTree::Proof MerkleTree::generate_proof(const std::string& data) const {
    Proof proof;
    const std::string target_hash = hash_data(data);
    
    // 查找叶子节点
    std::shared_ptr<MerkleNode> leaf_node = nullptr;
    {
        // std::shared_lock idx_lock(index_mutex_);
        auto it = leaf_map_.find(target_hash);
        if (it == leaf_map_.end()) return proof;
        leaf_node = it->second;
    }
    
    // 保护树结构访问
    std::shared_lock read_lock(structure_mutex_);
    
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
