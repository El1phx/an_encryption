#include <iostream>
#include <vector>
#include <algorithm>
#include <random>
#include <iomanip>
#include <cctype>

int main() {
    const int SIZE = 256;
    std::vector<int> sbox(SIZE);

    // ��ʼ��S��Ϊ˳��ӳ��
    for (int i = 0; i < SIZE; ++i) {
        sbox[i] = i;
    }

    // �������������
    std::random_device rd;
    std::mt19937 gen(rd());

    // �������S�У�Fisher-Yates�㷨��
    for (int i = SIZE - 1; i > 0; --i) {
        std::uniform_int_distribution<> dis(0, i);
        int j = dis(gen);
        std::swap(sbox[i], sbox[j]);
    }

    // ��������S��
    std::vector<int> inv(SIZE, -1);
    for (int i = 0; i < SIZE; ++i) {
        if (inv[i] == -1) {
            int j = sbox[i];
            if (i == j) {  // �Է���
                inv[i] = i;
            }
            else {
                if (inv[j] == -1) {
                    inv[i] = j;
                    inv[j] = i;
                }
                else {  // �����ͻ
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

    // ��֤��������
    for (int i = 0; i < SIZE; ++i) {
        if (inv[inv[i]] != i) {
            std::cerr << "Error: S-box is not self-inverse at position " << i << std::endl;
            return 1;
        }
    }

    // ��ʽ�����
    std::cout << std::hex << std::setfill('0');
    for (int i = 0; i < SIZE; ++i) {
        std::cout << "0x" << std::setw(2) << inv[i];

        if (i < SIZE - 1) {
            std::cout << ",";
        }

        // ÿ16��Ԫ�ػ���
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }

    return 0;
}