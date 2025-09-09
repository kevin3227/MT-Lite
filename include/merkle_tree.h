#pragma once
#include <vector>
#include <memory>
#include <string>
#include <stack>
#include <mutex>
#include <shared_mutex>
#include <tbb/concurrent_unordered_map.h>
#include <atomic>
#include <cmath>
#include <queue>
#include <condition_variable>
#include <thread>
#include <functional>

struct MerkleNode {
    std::string hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;
    std::weak_ptr<MerkleNode> parent;

    explicit MerkleNode(std::string hash) 
        : hash(std::move(hash)), left(nullptr), right(nullptr) {}
};

class MerkleTree {
public:
    MerkleTree();
    ~MerkleTree();
    
    // 使用缓冲区的异步插入
    void insert(const std::string& data);
    void batch_insert(const std::vector<std::string>& items);
    
    // 等待所有异步操作完成
    void flush();
    
    bool contains(const std::string& data) const;
    std::string root_hash() const { 
        std::shared_lock lock(structure_mutex_);
        return root_ ? root_->hash : ""; 
    }
    
    struct Proof {
        std::vector<std::pair<bool, std::string>> path; // <isRight, hash>
        std::string leaf;
    };
    
    static std::string hash_data(const std::string& data);
    Proof generate_proof(const std::string& data) const;
    static bool verify_proof(const Proof& proof, const std::string& root_hash);
    
    // 性能分析接口
    size_t node_count() const { return node_counter_; }
    size_t leaf_count() const { return leaf_map_.size(); }
    size_t height() const;

    // 快照相关类型和方法
    class Snapshot {
    public:
        friend class MerkleTree;
        
        Snapshot(uint64_t version, 
                 std::shared_ptr<MerkleNode> root,
                 const tbb::concurrent_unordered_map<std::string, std::shared_ptr<MerkleNode>>& leaf_map);

        // 从快照生成证明
        Proof generate_proof(const std::string& data) const;
        
        // 获取快照的根哈希
        std::string root_hash() const {
            return root_ ? root_->hash : "";
        }
        
        // 检查快照中是否包含某数据
        bool contains(const std::string& data) const;
        
        // 获取快照的版本号
        uint64_t version() const { return version_; }
        
        // 快照的大小
        size_t size() const { return leaf_map_.size(); }

    private:
        uint64_t version_;
        std::shared_ptr<MerkleNode> root_;
        tbb::concurrent_unordered_map<std::string, std::shared_ptr<MerkleNode>> leaf_map_;
    };
    
    // 创建当前树的快照
    std::shared_ptr<Snapshot> create_snapshot();
    
    // 重置树为快照状态
    void reset_to_snapshot(const std::shared_ptr<Snapshot>& snapshot);
    
    // 清空树
    void clear();

private:
    std::shared_ptr<MerkleNode> root_;
    std::atomic<size_t> node_counter_{0};
    mutable std::shared_mutex structure_mutex_;
    std::atomic<uint64_t> version_{0};
    
    // 存储结构：叶子节点哈希映射
    tbb::concurrent_unordered_map<std::string, std::shared_ptr<MerkleNode>> leaf_map_;
    
    // 增量重建相关
    static constexpr size_t REBUILD_THRESHOLD = 5000; // 完全重建阈值
    static constexpr size_t BUFFER_CAPACITY = 1000;   // 插入缓冲区大小
    static constexpr size_t FLUSH_THRESHOLD = 500;    // 触发刷新的阈值
    
    // 异步插入缓冲区
    struct {
        std::mutex mutex;
        std::condition_variable cv;
        std::vector<std::string> items;
        bool should_terminate = false;
        std::atomic<bool> processing = false;
        std::thread worker;
    } buffer_;
    
    // 异步工作线程函数
    void worker_thread();
    
    // 刷新缓冲区，执行批量插入
    void process_buffered_items();
    
    // 内部批量插入实现
    void internal_batch_insert(const std::vector<std::string>& items);
    
    std::shared_ptr<MerkleNode> build_parent(
        const std::shared_ptr<MerkleNode>& left,
        const std::shared_ptr<MerkleNode>& right);
    
    // 完全重建树
    void rebuild_tree();
    
    // 增量重建树
    void incremental_rebuild(const std::shared_ptr<MerkleNode>& new_leaf);
    
    // 查找最佳合并位置
    std::shared_ptr<MerkleNode> find_merge_candidate(
        const std::shared_ptr<MerkleNode>& new_leaf);
    
    // 更新路径上的哈希值
    void update_path_hashes(const std::shared_ptr<MerkleNode>& from_node);
    
    size_t calculate_height(const std::shared_ptr<MerkleNode>& node) const;
    
    // 创建一个节点的深拷贝，用于快照
    std::shared_ptr<MerkleNode> deep_copy_node(
        const std::shared_ptr<MerkleNode>& node,
        std::unordered_map<std::shared_ptr<MerkleNode>, std::shared_ptr<MerkleNode>>& node_map);
};
