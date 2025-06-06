#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cassert>
#include <stdexcept>
using namespace std;

const size_t BLOCK_BITS = 1024;
const size_t BLOCK_BYTES = BLOCK_BITS / 8;

// 自逆S盒
const unsigned char SBOX[256] = {
    0xd4,0x01,0x3b,0x75,0x58,0xf8,0x9f,0x2c,0x74,0xd0,0x88,0xe4,0xb9,0x28,0xe5,0x69,
    0x4b,0x18,0xab,0xc3,0x8d,0xbe,0xd7,0x1f,0x11,0xaa,0x1a,0x37,0x1c,0xb7,0x1e,0x17,
    0xf0,0x3c,0x57,0x27,0x85,0xce,0x87,0x23,0x0d,0xa4,0x6b,0x93,0x07,0xeb,0x2e,0xc5,
    0xa9,0x67,0xac,0x33,0x82,0xcd,0x36,0x1b,0xba,0x39,0x44,0x02,0x21,0x3d,0x3e,0x94,
    0x5d,0xdc,0xfd,0xa7,0x3a,0x50,0x46,0x47,0x59,0xbc,0x9e,0x10,0x53,0xe0,0x62,0x4f,
    0x45,0xad,0x89,0x4c,0xc1,0x60,0x5a,0x22,0x04,0x48,0x56,0x70,0xec,0x40,0xd1,0xfc,
    0x55,0x8e,0x4e,0xfb,0x64,0x65,0x71,0x31,0xea,0x0f,0x6a,0x2a,0x81,0xe6,0x96,0xe8,
    0x5b,0x66,0xa3,0x73,0x08,0x03,0x76,0x77,0x78,0xe2,0x7a,0x9d,0x99,0x7d,0x9c,0x7f,
    0xb4,0x6c,0x34,0xdf,0xda,0x24,0x86,0x26,0x0a,0x52,0xf9,0x8b,0x8c,0x14,0x61,0x8f,
    0x90,0x91,0x92,0x2b,0x3f,0x95,0x6e,0x97,0x98,0x7c,0xb5,0xc4,0x7e,0x7b,0x4a,0x06,
    0xa0,0xa1,0xa2,0x72,0x29,0xb0,0xa6,0x43,0xc6,0x30,0x19,0x12,0x32,0x51,0xae,0xaf,
    0xa5,0xb1,0xb2,0xc9,0x80,0x9a,0xd6,0x1d,0xb8,0x0c,0x38,0xbb,0x49,0xbd,0x15,0xbf,
    0xc0,0x54,0xf5,0x13,0x9b,0x2f,0xa8,0xc7,0xc8,0xb3,0xca,0xf6,0xcc,0x35,0x25,0xcf,
    0x09,0x5e,0xd9,0xd3,0x00,0xf2,0xb6,0x16,0xf3,0xd2,0x84,0xdb,0x41,0xdd,0xde,0x83,
    0x4d,0xe1,0x79,0xe3,0x0b,0x0e,0x6d,0xe7,0x6f,0xe9,0x68,0x2d,0x5c,0xed,0xee,0xef,
    0x20,0xf1,0xd5,0xd8,0xf4,0xc2,0xcb,0xff,0x05,0x8a,0xfa,0x63,0x5f,0x42,0xfe,0xf7
};


void transformBlock(std::vector<unsigned char>& block, const std::vector<unsigned char>& roundKey) {
    const int blockSize = BLOCK_BYTES; // 128字节

    // 轮密钥加
    for (int i = 0; i < blockSize; ++i) {
        block[i] ^= roundKey[i];
    }
    for (int j = 0; j < 16; j++) {
        // S盒替换 (SubBytes)
        for (int i = 0; i < blockSize; ++i) {
            block[i] = SBOX[block[i]];
        }
        //块内字节反转
        reverse(block.begin(), block.end());

        // 轮密钥加
        for (int i = 0; i < blockSize; ++i) {
            block[i] ^= roundKey[i];
        }
    }

    // 扩散层：行内循环移位（自逆操作）
    for (int row = 0; row < 16; ++row) { // 128字节视为16行x8列
        int rowStart = row * 8;
        // 循环移位，偶数行左移，奇数行右移（移位量取模以避免无效移位）
        if (row % 2 == 0) {
            rotate(block.begin() + rowStart,
                block.begin() + rowStart,
                block.begin() + rowStart + 8);
        }
        else {
            rotate(block.begin() + rowStart,
                block.begin() + rowStart + 8 ,
                block.begin() + rowStart + 8);
        }
    }
}

// 主加密/解密函数
void selfInverseCipher(vector<vector<unsigned char>>& blocks,
    const vector<unsigned char>& masterKey) {
 
    // 处理每个块
    for (auto& block : blocks) {
        transformBlock(block, masterKey);
    }
}

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

// 将块重新组合为原始数据大小
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
    string input_filename;
    string output_filename;
    string key_filename;
    cout << "Input Source File:\n";
    cin >> input_filename;
    cout << "Enter destination file:\n";
    cin >> output_filename;
    cout << "Enter key file:(if it does not exist, randomly generate the key and perform encryption)：\n";
    cin >> key_filename;

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
        // 2. 加解密
        selfInverseCipher(blocks, master_key);
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
