#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <iomanip>
#include <cctype>

int main() {
    const int SIZE = 256;
    std::vector<int> sbox(SIZE);

    // 初始化S盒为顺序映射
    for (int i = 0; i < SIZE; ++i) {
        sbox[i] = i;
    }

    // 设置随机数引擎
    std::random_device rd;
    std::mt19937 gen(rd());

    // 随机打乱S盒（Fisher-Yates算法）
    for (int i = SIZE - 1; i > 0; --i) {
        std::uniform_int_distribution<> dis(0, i);
        int j = dis(gen);
        std::swap(sbox[i], sbox[j]);
    }

    // 构建自逆S盒
    std::vector<int> inv(SIZE, -1);
    for (int i = 0; i < SIZE; ++i) {
        if (inv[i] == -1) {
            int j = sbox[i];
            if (i == j) {  // 自反点
                inv[i] = i;
            }
            else {
                if (inv[j] == -1) {
                    inv[i] = j;
                    inv[j] = i;
                }
                else {  // 处理冲突
                    for (int k = 0; k < SIZE; ++k) {
                        if (inv[k] == -1) {
                            inv[i] = k;
                            inv[k] = i;
                            break;
                        }
                    }
                }
            }
        }
    }

    // 验证自逆属性
    for (int i = 0; i < SIZE; ++i) {
        if (inv[inv[i]] != i) {
            std::cerr << "Error: S-box is not self-inverse at position " << i << std::endl;
            return 1;
        }
    }

    // 格式化输出
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < SIZE; ++i) {
        std::cout << "0x" << std::setw(2) << inv[i];

        if (i < SIZE - 1) {
            std::cout << ",";
        }

        // 每16个元素换行
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }

    return 0;
}