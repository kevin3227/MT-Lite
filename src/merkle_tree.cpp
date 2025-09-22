#include "merkle_tree.h"
#include <algorithm>
#include <string.h>
#include <cstring>
#include <openssl/evp.h>
#include <numeric>
#include <omp.h>
#include <iostream>

// 线程局部哈希上下文
thread_local struct {
    EVP_MD_CTX* md_ctx;
    const EVP_MD* sha3;
    bool initialized;
} tls_hash_ctx = {nullptr, nullptr, false};

MerkleTree::MerkleTree() {
    // 启动工作线程
    buffer_.worker = std::thread(&MerkleTree::worker_thread, this);
    
    // // 打印锁地址
    // std::cout << "buffer mutex address: " << &buffer_.mutex << std::endl;
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
        
        // 如果根节点共享，创建一个新的根节点
        if (root_ && is_node_shared(root_)) {
            root_ = get_writable_node(root_);
        }
        
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
    // 收集所有叶子节点
    std::vector<std::shared_ptr<MerkleNode>> current_level;
    current_level.reserve(leaf_map_.size());
    
    // 检查所有叶子节点，需要时创建副本
    for (const auto& [hash, leaf] : leaf_map_) {
        if (is_node_shared(leaf)) {
            auto writable_leaf = get_writable_node(leaf);
            leaf_map_[hash] = writable_leaf; // 更新叶子映射
            current_level.push_back(writable_leaf);
        } else {
            current_level.push_back(leaf);
        }
    }
    
    if (current_level.empty()) {
        root_ = nullptr;
        version_++;
        return;
    }
    
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
            // 检查other_leaf是否共享
            if (is_node_shared(other_leaf)) {
                other_leaf = get_writable_node(other_leaf);
            }
            
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
        
        // 检查叶子节点是否共享
        for (int i = 0; i < leaves.size(); i++) {
            if (is_node_shared(leaves[i])) {
                leaves[i] = get_writable_node(leaves[i]);
            }
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
        // 如果找到合适的合并位置，检查是否需要复制
        if (is_node_shared(merge_candidate)) {
            merge_candidate = get_writable_node(merge_candidate);
        }
        
        // 获取父节点
        auto parent = merge_candidate->parent.lock();
        
        // 检查是否需要克隆父节点路径
        if (parent && is_node_shared(parent)) {
            // 克隆整个路径到根
            auto new_parent = clone_path_to_root(parent);
            
            // 更新父子关系
            if (parent->left == merge_candidate) {
                new_parent->left = merge_candidate;
            } else if (parent->right == merge_candidate) {
                new_parent->right = merge_candidate;
            }
            merge_candidate->parent = new_parent;
            
            // 如果原始父节点是根，更新根节点
            if (parent == root_) {
                root_ = new_parent;
            }
            
            // 使用新的父节点
            parent = new_parent;
        }
        
        // 创建新的子树
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
        // 如果没有找到合适的合并位置
        // 检查根节点是否共享
        auto old_root = root_;
        if (is_node_shared(old_root)) {
            old_root = get_writable_node(old_root);
        }
        
        // 创建新的根
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
        // 确保当前节点可写
        if (is_node_shared(current)) {
            auto writable_current = get_writable_node(current);
            
            // 更新父子关系
            auto parent = current->parent.lock();
            if (parent) {
                if (parent->left == current) {
                    parent->left = writable_current;
                } else if (parent->right == current) {
                    parent->right = writable_current;
                }
            }
            
            // 更新左右子节点的父指针
            if (writable_current->left) {
                writable_current->left->parent = writable_current;
            }
            if (writable_current->right) {
                writable_current->right->parent = writable_current;
            }
            
            // 如果是根节点，更新根指针
            if (current == root_) {
                root_ = writable_current;
            }
            
            current = writable_current;
        }
        
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
        
        // 获取父节点，确保它也是可写的
        auto parent = current->parent.lock();
        if (parent && is_node_shared(parent)) {
            auto writable_parent = get_writable_node(parent);
            
            // 更新父子关系
            if (parent->left == current) {
                writable_parent->left = current;
            } else if (parent->right == current) {
                writable_parent->right = current;
            }
            current->parent = writable_parent;
            
            // 如果父节点是根节点，更新根
            if (parent == root_) {
                root_ = writable_parent;
            }
            
            // 更新父节点的其他子节点的父指针
            if (writable_parent->left && writable_parent->left != current) {
                writable_parent->left->parent = writable_parent;
            }
            if (writable_parent->right && writable_parent->right != current) {
                writable_parent->right->parent = writable_parent;
            }
            
            // 更新父节点引用
            parent = writable_parent;
        }
        
        current = parent;
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

// 快照相关实现
MerkleTree::Snapshot::Snapshot(
    uint64_t version, 
    std::shared_ptr<MerkleNode> root,
    const tbb::concurrent_unordered_map<std::string, std::shared_ptr<MerkleNode>>& leaf_map)
    : version_(version), root_(root), leaf_map_(leaf_map) {
}

MerkleTree::Snapshot::~Snapshot() {
    if (root_) {
        // 递归减少所有引用节点的引用计数
        decrement_ref_counts(root_);
    }
}

bool MerkleTree::Snapshot::contains(const std::string& data) const {
    const std::string target_hash = MerkleTree::hash_data(data);
    return leaf_map_.find(target_hash) != leaf_map_.end();
}

MerkleTree::Proof MerkleTree::Snapshot::generate_proof(const std::string& data) const {
    Proof proof;
    const std::string target_hash = MerkleTree::hash_data(data);
    
    // 查找叶子节点
    auto it = leaf_map_.find(target_hash);
    if (it == leaf_map_.end()) return proof;
    
    std::shared_ptr<MerkleNode> leaf_node = it->second;
    
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
            // 如果没有兄弟节点，使用当前节点的哈希
            proof.path.emplace_back(is_right, current->hash);
        }
        
        current = parent;
        if (current == root_) break;
    }
    
    return proof;
}

void MerkleTree::Snapshot::increment_ref_counts(const std::shared_ptr<MerkleNode>& node) {
    if (!node) return;
    
    // 如果节点已在集合中，不再处理
    if (referenced_nodes_.find(node) != referenced_nodes_.end()) {
        return;
    }
    
    // 增加引用计数并记录节点
    node->ref_count++;
    referenced_nodes_.insert(node);
    
    // 递归处理子节点
    if (node->left) increment_ref_counts(node->left);
    if (node->right) increment_ref_counts(node->right);
}

void MerkleTree::Snapshot::decrement_ref_counts(const std::shared_ptr<MerkleNode>& node) {
    if (!node) return;
    
    // 如果节点不在集合中，不处理
    if (referenced_nodes_.find(node) == referenced_nodes_.end()) {
        return;
    }
    
    // 减少引用计数并从集合移除
    node->ref_count--;
    referenced_nodes_.erase(node);
    
    // 递归处理子节点
    if (node->left) decrement_ref_counts(node->left);
    if (node->right) decrement_ref_counts(node->right);
}

// 检查节点是否共享
bool MerkleTree::is_node_shared(const std::shared_ptr<MerkleNode>& node) const {
    return node && node->ref_count > 1;
}

// 获取可写节点
std::shared_ptr<MerkleNode> MerkleTree::get_writable_node(
    const std::shared_ptr<MerkleNode>& node) {
    
    if (!node || node->ref_count == 1) {
        // 如果节点为空或引用计数为1，无需复制
        return node;
    }
    
    // 创建节点副本
    auto copy = std::make_shared<MerkleNode>(node->hash);
    node_counter_++;
    
    // 复制子节点引用（但不复制子节点本身）
    copy->left = node->left;
    copy->right = node->right;
    
    // 更新子节点的parent指针
    if (copy->left) copy->left->parent = copy;
    if (copy->right) copy->right->parent = copy;
    
    return copy;
}

// 从节点到根的路径克隆
std::shared_ptr<MerkleNode> MerkleTree::clone_path_to_root(
    const std::shared_ptr<MerkleNode>& from_node) {
    
    if (!from_node) return nullptr;
    
    // 如果节点不共享，无需克隆
    if (!is_node_shared(from_node)) {
        return from_node;
    }
    
    // 创建节点副本
    auto node_copy = get_writable_node(from_node);
    
    // 处理父节点路径
    auto parent = from_node->parent.lock();
    if (parent) {
        // 递归克隆父节点路径
        auto parent_copy = clone_path_to_root(parent);
        
        // 更新父节点的子节点引用
        if (parent->left == from_node) {
            parent_copy->left = node_copy;
        } else {
            parent_copy->right = node_copy;
        }
        
        // 更新子节点的父节点引用
        node_copy->parent = parent_copy;
    }
    
    return node_copy;
}

// 创建快照
std::shared_ptr<MerkleTree::Snapshot> MerkleTree::create_snapshot() {
    // 确保所有异步操作完成
    flush();
    
    // 锁定树结构
    std::shared_lock lock(structure_mutex_);
    
    // 创建快照对象，直接使用当前树的引用
    auto snapshot = std::make_shared<Snapshot>(
        version_, root_, leaf_map_);
    
    // 注册快照并增加节点引用计数
    if (root_) {
        snapshot->increment_ref_counts(root_);
    }
    
    // 注册到活跃快照列表
    {
        std::lock_guard<std::mutex> snap_lock(snapshots_mutex_);
        active_snapshots_.push_back(snapshot);
    }
    
    return snapshot;
}

// 重置树为快照状态
void MerkleTree::reset_to_snapshot(const std::shared_ptr<Snapshot>& snapshot) {
    if (!snapshot) return;
    
    flush();
    std::unique_lock lock(structure_mutex_);
    
    // 减少当前树根的引用计数(如果被快照引用)
    if (root_ && root_->ref_count > 1) {
        root_->ref_count--;
    }
    
    // 增加快照根的引用计数
    if (snapshot->root_) {
        snapshot->root_->ref_count++;
    }
    
    // 直接使用快照的状态
    root_ = snapshot->root_;
    leaf_map_ = snapshot->leaf_map_;
    version_ = snapshot->version_;
    
    // 更新节点计数
    node_counter_ = leaf_map_.size();
}

// 清理
void MerkleTree::clear() {
    // 确保所有异步操作完成
    flush();
    
    // 锁定树结构
    std::unique_lock lock(structure_mutex_);
    
    // 检查是否有快照引用
    std::lock_guard<std::mutex> snap_lock(snapshots_mutex_);
    bool has_snapshots = !active_snapshots_.empty();
    
    if (has_snapshots && root_) {
        // 如果有快照并且树不为空，递减引用计数
        if (root_->ref_count > 1) {
            root_->ref_count--;
        }
    }
    
    // 清空树
    root_ = nullptr;
    leaf_map_.clear();
    node_counter_ = 0;
    version_++;
}