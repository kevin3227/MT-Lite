#pragma once
#include <vector>
#include <memory>
#include <string>
#include <stack>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <atomic>

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
    MerkleTree() = default;
    
    void insert(const std::string& data);
    bool contains(const std::string& data) const;
    std::string root_hash() const { return root_ ? root_->hash : ""; }
    
    struct Proof {
        std::vector<std::pair<bool, std::string>> path; // <isRight, hash>
        std::string leaf;
    };
    
    Proof generate_proof(const std::string& data) const;
    static bool verify_proof(const Proof& proof, const std::string& root_hash);

    // 性能分析接口
    size_t node_count() const { return node_counter_; }
    size_t leaf_count() const { return leaf_map_.size(); }

private:
    std::shared_ptr<MerkleNode> root_;
    size_t node_counter_ = 0;
    std::stack<std::shared_ptr<MerkleNode>> merge_stack_;
    mutable std::shared_mutex index_mutex_;
    mutable std::mutex structure_mutex_;
    std::atomic<uint64_t> version_{0};
    
    // 存储结构优化关键点：叶子节点哈希映射
    std::unordered_map<std::string, std::shared_ptr<MerkleNode>> leaf_map_;

    static std::string hash_data(const std::string& data);
    std::shared_ptr<MerkleNode> build_parent(
        const std::shared_ptr<MerkleNode>& left,
        const std::shared_ptr<MerkleNode>& right);
    
    void process_merge_stack();
};
