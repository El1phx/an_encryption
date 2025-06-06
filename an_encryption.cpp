#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cassert>
using namespace std;

const size_t BLOCK_BITS = 1024;
const size_t BLOCK_BYTES = BLOCK_BITS / 8;

// 自逆S盒
const unsigned char SBOX[256] = {
    0x00, 0x01, 0x8d, 0xf6, 0xcb, 0x52, 0x7b, 0xd1, 0xe8, 0x4f, 0x29, 0xc0, 0xb0, 0xe1, 0xe5, 0xc7,
    0x74, 0xb4, 0xaa, 0x4b, 0x99, 0x2b, 0x60, 0x5f, 0x58, 0x3f, 0xfd, 0xcc, 0xff, 0x40, 0xee, 0xb2,
    0x3a, 0x6e, 0x5a, 0xf1, 0x55, 0x4d, 0xa8, 0xc9, 0xc1, 0x0a, 0x98, 0x15, 0x30, 0x44, 0xa2, 0xc2,
    0x2c, 0x45, 0x92, 0x6c, 0xf3, 0x39, 0x66, 0x42, 0xf2, 0x35, 0x20, 0x6f, 0x77, 0xbb, 0x59, 0x19,
    0x1d, 0xfe, 0x37, 0x67, 0x2d, 0x31, 0xf5, 0x69, 0xa7, 0x64, 0xab, 0x13, 0x54, 0x25, 0xe9, 0x09,
    0xed, 0x5c, 0x05, 0xca, 0x4c, 0x24, 0x87, 0xbf, 0x18, 0x3e, 0x22, 0xf0, 0x51, 0xec, 0x61, 0x17,
    0x16, 0x5e, 0xaf, 0xd3, 0x49, 0xa6, 0x36, 0x43, 0xf4, 0x47, 0x91, 0xdf, 0x33, 0x93, 0x21, 0x3b,
    0x79, 0xb7, 0x97, 0x85, 0x10, 0xb5, 0xba, 0x3c, 0xb6, 0x70, 0xd0, 0x06, 0xa1, 0xfa, 0x81, 0x82,
    0x83, 0x7e, 0x7f, 0x80, 0x96, 0x73, 0xbe, 0x56, 0x9b, 0x9e, 0x95, 0xd9, 0xf7, 0x02, 0xb9, 0xa4,
    0xde, 0x6a, 0x32, 0x6d, 0xd8, 0x8a, 0x84, 0x72, 0x2a, 0x14, 0x9f, 0x88, 0xf9, 0xdc, 0x89, 0x9a,
    0xfb, 0x7c, 0x2e, 0xc3, 0x8f, 0xb8, 0x65, 0x48, 0x26, 0xc8, 0x12, 0x4a, 0xce, 0xe7, 0xd2, 0x62,
    0x0c, 0xe0, 0x1f, 0xef, 0x11, 0x75, 0x78, 0x71, 0xa5, 0x8e, 0x76, 0x3d, 0xbd, 0xbc, 0x86, 0x57,
    0x0b, 0x28, 0x2f, 0xa3, 0xda, 0xd4, 0xe4, 0x0f, 0xa9, 0x27, 0x53, 0x04, 0x1b, 0xfc, 0xac, 0xe6,
    0x7a, 0x07, 0xae, 0x63, 0xc5, 0xdb, 0xe2, 0xea, 0x94, 0x8b, 0xc4, 0xd5, 0x9d, 0xf8, 0x90, 0x6b,
    0xb1, 0x0d, 0xd6, 0xeb, 0xc6, 0x0e, 0xcf, 0xad, 0x08, 0x4e, 0xd7, 0xe3, 0x5d, 0x50, 0x1e, 0xb3,
    0x5b, 0x23, 0x38, 0x34, 0x68, 0x46, 0x03, 0x8c, 0xdd, 0x9c, 0x7d, 0xa0, 0xcd, 0x1a, 0x41, 0x1c
};

// 自逆矩阵置换表（用于列混合）
const unsigned char MIX_MATRIX[8][8] = {
     {0x02, 0x03, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00},
     {0x01, 0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00},
     {0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00},
     {0x03, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00},
     {0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x01, 0x01},
     {0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x01},
     {0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x03},
     {0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x02}
};
const unsigned char Rcon[18] = {
    0x00, // 索引0，未使用
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E
};

// 从文件读取密钥
vector<unsigned char> read_key(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Unable to open key file");
    }

    file.seekg(0, ios::end);
    size_t size = file.tellg();
    file.seekg(0, ios::beg);

    if (size != BLOCK_BYTES) {
        throw runtime_error("The key must be 128 bytes (1024 bits)");
    }

    vector<unsigned char> key(BLOCK_BYTES);
    if (!file.read(reinterpret_cast<char*>(key.data()), BLOCK_BYTES)) {
        throw runtime_error("Failed to read key");
    }

    return key;
}

// 密钥扩展算法 
vector<vector<unsigned char>> expand_key(const vector<unsigned char>& master_key) {
    const int rounds = 16;  // 直接生成16个轮密钥
    const int key_size = 128;
    vector<vector<unsigned char>> round_keys;
    vector<unsigned char> current_key = master_key;

    for (int round = 0; round < rounds; ++round) {
        // 1. 字节替换
        for (int i = 0; i < key_size; ++i) {
            current_key[i] = SBOX[current_key[i]];
        }

        // 2. 循环移位
        rotate(current_key.begin(), current_key.begin() + (round % 8) + 1, current_key.end());

        // 3. 添加轮常数
        for (int i = 0; i < key_size; i += 16) {
            current_key[i] ^= Rcon[round + 1];
        }

        // 4. 矩阵变换
        for (int i = 0; i < key_size; i += 8) {
            vector<unsigned char> temp(8, 0);
            for (int row = 0; row < 8; ++row) {
                for (int col = 0; col < 8; ++col) {
                    unsigned char a = current_key[i + col];
                    unsigned char b = MIX_MATRIX[row][col];
                    unsigned char p = 0;
                    for (int counter = 0; counter < 8; counter++) {
                        if (b & 1) p ^= a;
                        bool hi_bit_set = (a & 0x80);
                        a <<= 1;
                        if (hi_bit_set) a ^= 0x1B;
                        b >>= 1;
                    }
                    temp[row] ^= p;
                }
            }
            copy(temp.begin(), temp.end(), current_key.begin() + i);
        }

        // 保存当前轮密钥
        round_keys.push_back(current_key);
    }
    return round_keys;
}

// 单轮Feistel变换
void feistel_round(vector<unsigned char>& left, vector<unsigned char>& right,
    const vector<unsigned char>& round_key)
{
    const int block_size = 64;
    vector<unsigned char> original_right = right;

    // 1. 轮密钥加
    for (int i = 0; i < block_size; ++i) {
        right[i] ^= round_key[i % round_key.size()];
    }

    // 2. 字节替换
    for (int i = 0; i < block_size; ++i) {
        right[i] = SBOX[right[i]];
    }

    // 3. 行移位
    for (int i = 0; i < 8; ++i) {
        int shift = (i % 4) + 1;
        rotate(right.begin() + i * 8,
        right.begin() + i * 8 + shift,
        right.begin() + (i + 1) * 8);
    }

    // 4. 列混合
    for (int col = 0; col < 8; ++col) {
        vector<unsigned char> column(8);
        for (int row = 0; row < 8; ++row) {
            column[row] = right[col + row * 8];
        }

        for (int row = 0; row < 8; ++row) {
            unsigned char val = 0;
            for (int k = 0; k < 8; ++k) {
                unsigned char a = column[k];
                unsigned char b = MIX_MATRIX[row][k];
                unsigned char p = 0;
                for (int counter = 0; counter < 8; counter++) {
                    if (b & 1) p ^= a;
                    bool hi_bit_set = (a & 0x80);
                    a <<= 1;
                    if (hi_bit_set) a ^= 0x1B;
                    b >>= 1;
                }
                val ^= p;
            }
            right[col + row * 8] = val;
        }
    }

    // 5. 更新左块和右块
    vector<unsigned char> new_right(block_size);
    for (int i = 0; i < block_size; ++i) {
        new_right[i] = left[i] ^ right[i];
    }
    left = original_right;
    right = new_right;
}

// 块处理函数 
void process_block(vector<unsigned char>& block,
    const vector<vector<unsigned char>>& round_keys,
    bool is_encrypt) {
    const int block_size = block.size();
    if (block_size != 128) {
        throw invalid_argument("The block size must be 128 bytes (1024 bits)");
    }

    vector<unsigned char> left(block.begin(), block.begin() + 64);
    vector<unsigned char> right(block.begin() + 64, block.end());

    // 初始变换 (加密用第一个密钥，解密用最后一个密钥)
    int init_key_idx = is_encrypt ? 0 : 15;
    for (int i = 0; i < 64; ++i) {
        left[i] ^= round_keys[init_key_idx][i];
        right[i] ^= round_keys[init_key_idx][i + 64];
    }

    // Feistel 轮处理
    if (is_encrypt) {
        for (int round = 0; round < 16; ++round) {
            feistel_round(left, right, round_keys[round]);
        }
    }
    else {
        for (int round = 15; round >= 0; --round) {
            feistel_round(left, right, round_keys[round]);
        }
    }

    // 最终变换 (加密用最后一个密钥，解密用第一个密钥)
    int final_key_idx = is_encrypt ? 15 : 0;
    for (int i = 0; i < 64; ++i) {
        left[i] ^= round_keys[final_key_idx][i];
        right[i] ^= round_keys[final_key_idx][i + 64];
    }

    // 合并结果
    copy(left.begin(), left.end(), block.begin());
    copy(right.begin(), right.end(), block.begin() + 64);
}

// 处理所有块
void process_blocks(vector<vector<unsigned char>>& blocks,
    const vector<vector<unsigned char>>& round_keys,
    bool is_encrypt) {
    for (auto& block : blocks) {
        process_block(block, round_keys,is_encrypt);
    }
}

// 生成随机字节的函数
unsigned char generateRandomByte() {
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dis(0, 255);
    return static_cast<unsigned char>(dis(gen));
}

// 读取文件并分块存储
vector<vector<unsigned char>> readFileToBlocks(const string& filename, size_t& original_size) {
    ifstream infile(filename, ios::binary | ios::ate);
    if (!infile) {
        cerr << "Unable to open file: " << filename << endl;
        exit(1);
    }

    // 获取文件大小
    original_size = infile.tellg();
    infile.seekg(0, ios::beg);

    cout << "File size: " << original_size << " bytes\n";
    cout << "Block size: " << BLOCK_BYTES << " bytes (" << BLOCK_BITS << " bits)\n";

    // 计算所需块数
    size_t total_blocks = original_size / BLOCK_BYTES;
    if (original_size % BLOCK_BYTES != 0) {
        total_blocks++;
    }
    cout << "Total blocks: " << total_blocks << "\n\n";

    // 存储所有块的容器
    vector<vector<unsigned char>> blocks;

    for (size_t i = 0; i < total_blocks; ++i) {
        vector<unsigned char> block(BLOCK_BYTES, 0); // 初始化为0

        // 计算当前块的实际数据大小
        size_t data_bytes = BLOCK_BYTES;
        if (i == total_blocks - 1 && original_size % BLOCK_BYTES != 0) {
            data_bytes = original_size % BLOCK_BYTES;
        }

        // 读取数据
        infile.read(reinterpret_cast<char*>(block.data()), data_bytes);

        // 处理最后一个块（需要填充）
        if (i == total_blocks - 1 && data_bytes < BLOCK_BYTES) {
            // 计算填充字节数（包括长度字节）
            size_t padding_bytes = BLOCK_BYTES - data_bytes;

            // 用随机数据填充剩余部分
            for (size_t j = data_bytes; j < BLOCK_BYTES - 1; ++j) {
                block[j] = generateRandomByte();
            }

            // 最后一个字节存储填充长度
            block[BLOCK_BYTES - 1] = static_cast<unsigned char>(padding_bytes);

            cout << "Block " << i + 1 << " (padded): "
                << data_bytes << " bytes data, "
                << padding_bytes - 1 << " bytes random, "
                << "1 byte length (" << static_cast<int>(padding_bytes) << ")\n";
        }
        else {
            cout << "Block " << i + 1 << ": " << data_bytes << " bytes data\n";
        }

        blocks.push_back(block);
    }

    infile.close();
    return blocks;
}

// 将块重新组合为原始数据
void reassembleBlocksToFile(const vector<vector<unsigned char>>& blocks,
    const string& output_filename,
    size_t original_size) {
    ofstream outfile(output_filename, ios::binary);
    if (!outfile) {
        cerr << "Unable to create output file: " << output_filename << endl;
        exit(1);
    }

    size_t total_bytes_written = 0;
    const size_t total_blocks = blocks.size();

    // 处理所有块
    for (size_t i = 0; i < total_blocks; i++) {
        // 计算当前块应写入的字节数
        size_t bytes_to_write = BLOCK_BYTES;

        // 如果是最后一个块且原始大小不是块大小的整数倍
        if (i == total_blocks - 1 && original_size % BLOCK_BYTES != 0) {
            bytes_to_write = original_size % BLOCK_BYTES;
        }

        // 写入数据
        outfile.write(reinterpret_cast<const char*>(blocks[i].data()), bytes_to_write);
        total_bytes_written += bytes_to_write;
    }

    outfile.close();

    // 最终大小验证
    cout << "\nReassembly complete!\n";
    cout << "Original size: " << original_size << " bytes\n";
    cout << "Output size: " << total_bytes_written << " bytes\n";

    if (total_bytes_written == original_size) {
        cout << "Success: Output file size matches original\n";
    }
    else {
        cerr << "Error: Output file size does not match original!\n";
        exit(2);
    }
}

int main() {
    // 文件名
    const string input_filename = "in.bin";
    const string output_filename = "out.bin";
    const string key_filename = "key.bin";

    // 创建示例二进制文件
    {
        ofstream outfile(input_filename, ios::binary);
        string data = "This is a test binary file for demonstrating reading 1024-bit blocks. "
            "It contains sample data to test the padding and reassembly functionality. "
            "The quick brown fox jumps over the lazy dog. 1234567890!@#$%^&*()";
        outfile.write(data.data(), data.size());
        cout << "Created input file: " << input_filename << " (" << data.size() << " bytes)\n";
    }

    // 创建密钥文件（如果不存在）
    {
        ifstream test_key(key_filename);
        if (!test_key) {
            ofstream key_file(key_filename, ios::binary);
            vector<unsigned char> key(BLOCK_BYTES);
            generate(key.begin(), key.end(), generateRandomByte);
            key_file.write(reinterpret_cast<const char*>(key.data()), BLOCK_BYTES);
            cout << "Created key file: " << key_filename << " (" << BLOCK_BYTES << " bytes)\n";
        }
    }

    // 步骤1: 读取文件并分块存储
    size_t original_size;
    cout << "\n===== Reading and Block Processing =====\n";
    vector<vector<unsigned char>> blocks = readFileToBlocks(input_filename, original_size);

    // 步骤2: 加解密
    try {
        // 1. 读取密钥
        auto master_key = read_key(key_filename);

        // 2. 密钥扩展
        auto round_keys = expand_key(master_key);

        // 3. 加密块
        process_blocks(blocks, round_keys,true);
        cout << "Encryption completed successfully.\n";

        // 4. 解密块
        process_blocks(blocks, round_keys,false);
        cout << "Decryption completed successfully.\n";
    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }

    // 步骤3: 将块重新组合为文件
    cout << "\n===== Reassembling Blocks to File =====\n";
    reassembleBlocksToFile(blocks, output_filename, original_size);

    return 0;
}
