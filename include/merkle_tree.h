#pragma once
#include <vector>
#include <memory>
#include <string>

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

private:
    std::vector<std::shared_ptr<MerkleNode>> leaves_;
    std::shared_ptr<MerkleNode> root_;

    static std::string hash_data(const std::string& data);
    std::shared_ptr<MerkleNode> build_parent(
        const std::shared_ptr<MerkleNode>& left,
        const std::shared_ptr<MerkleNode>& right);
};
