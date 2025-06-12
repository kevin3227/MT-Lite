#pragma once
#include <vector>
#include <memory>
#include <string>
#include <stack>
#include <mutex> // 添加互斥锁头文件

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
    size_t leaf_count() const { return leaves_.size(); } // 新增叶子计数

private:
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;
    size_t node_counter_ = 0;
    std::stack<std::shared_ptr<MerkleNode>> merge_stack_;
    std::mutex insert_mutex_; // 互斥锁确保线程安全

    static std::string hash_data(const std::string& data);
    std::shared_ptr<MerkleNode> build_parent(
        const std::shared_ptr<MerkleNode>& left,
        const std::shared_ptr<MerkleNode>& right);
    
    void process_merge_stack();
};
