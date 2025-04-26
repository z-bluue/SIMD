#include "md5.h"
#include <iomanip>
#include <assert.h>
#include <chrono>

using namespace std;
using namespace chrono;

/**
 * StringProcess: 将单个输入字符串转换成MD5计算所需的消息数组
 * @param input 输入
 * @param[out] n_byte 用于给调用者传递额外的返回值，即最终Byte数组的长度
 * @return Byte消息数组
 */
Byte *StringProcess(string input, int *n_byte)
{
	// 将输入的字符串转换为Byte为单位的数组
	Byte *blocks = (Byte *)input.c_str();
	int length = input.length();

	// 计算原始消息长度（以比特为单位）
	int bitLength = length * 8;

	// paddingBits: 原始消息需要的padding长度（以bit为单位）
	// 对于给定的消息，将其补齐至length%512==448为止
	// 需要注意的是，即便给定的消息满足length%512==448，也需要再pad 512bits
	int paddingBits = bitLength % 512;
	if (paddingBits > 448)
	{
		paddingBits = 512 - (paddingBits - 448);
	}
	else if (paddingBits < 448)
	{
		paddingBits = 448 - paddingBits;
	}
	else if (paddingBits == 448)
	{
		paddingBits = 512;
	}

	// 原始消息需要的padding长度（以Byte为单位）
	int paddingBytes = paddingBits / 8;
	// 创建最终的字节数组
	// length + paddingBytes + 8:
	// 1. length为原始消息的长度（bits）
	// 2. paddingBytes为原始消息需要的padding长度（Bytes）
	// 3. 在pad到length%512==448之后，需要额外附加64bits的原始消息长度，即8个bytes
	int paddedLength = length + paddingBytes + 8;
	Byte *paddedMessage = new Byte[paddedLength];

	// 复制原始消息
	memcpy(paddedMessage, blocks, length);

	// 添加填充字节。填充时，第一位为1，后面的所有位均为0。
	// 所以第一个byte是0x80
	paddedMessage[length] = 0x80;							 // 添加一个0x80字节
	memset(paddedMessage + length + 1, 0, paddingBytes - 1); // 填充0字节

	// 添加消息长度（64比特，小端格式）
	for (int i = 0; i < 8; ++i)
	{
		// 特别注意此处应当将bitLength转换为uint64_t
		// 这里的length是原始消息的长度
		paddedMessage[length + paddingBytes + i] = ((uint64_t)length * 8 >> (i * 8)) & 0xFF;
	}

	// 验证长度是否满足要求。此时长度应当是512bit的倍数
	int residual = 8 * paddedLength % 512;
	// assert(residual == 0);

	// 在填充+添加长度之后，消息被分为n_blocks个512bit的部分
	*n_byte = paddedLength;
	return paddedMessage;
}


/**
 * MD5Hash: 将单个输入字符串转换成MD5
 * @param input 输入
 * @param[out] state 用于给调用者传递额外的返回值，即最终的缓冲区，也就是MD5的结果
 * @return Byte消息数组
 */
 void MD5Hash_NEON(const std::string inputs[4], bit32 states[16], int count) {
    // 初始化MD5状态向量 (4个并行)
    vbit32 a = vdupq_n_u32(0x67452301);
    vbit32 b = vdupq_n_u32(0xefcdab89);
    vbit32 c = vdupq_n_u32(0x98badcfe);
    vbit32 d = vdupq_n_u32(0x10325476);

    // 预处理所有输入消息
    Byte* paddedMessages[4] = {nullptr};
    int messageLengths[4] = {0};
    
    for (int i = 0; i < count; i++) {
        paddedMessages[i] = StringProcess(inputs[i], &messageLengths[i]);
    }

    // 确定块数(以第一个消息的长度为准)
    int n_blocks = messageLengths[0] / 64;

    // 处理每个512-bit块
    for (int block = 0; block < n_blocks; block++) {
        // 加载消息块到16个NEON寄存器中
        vbit32 x[16];
        for (int i = 0; i < 16; i++) {
            uint32_t words[4] = {0};
            for (int j = 0; j < count; j++) {
                words[j] = (paddedMessages[j][4*i + 0 + block*64]) |
                          (paddedMessages[j][4*i + 1 + block*64] << 8) |
                          (paddedMessages[j][4*i + 2 + block*64] << 16) |
                          (paddedMessages[j][4*i + 3 + block*64] << 24);
            }
            x[i] = vld1q_u32(words);
        }

        vbit32 aa = a, bb = b, cc = c, dd = d;

        /* Round 1 */

        NEON_FF(a, b, c, d, x[0], s11, 0xd76aa478); 
        NEON_FF(d, a, b, c, x[1], s12, 0xe8c7b756); 
        NEON_FF(c, d, a, b, x[2], s13, 0x242070db); 
        NEON_FF(b, c, d, a, x[3], s14, 0xc1bdceee); 
        NEON_FF(a, b, c, d, x[4], s11, 0xf57c0faf); 
        NEON_FF(d, a, b, c, x[5], s12, 0x4787c62a); 
        NEON_FF(c, d, a, b, x[6], s13, 0xa8304613); 
        NEON_FF(b, c, d, a, x[7], s14, 0xfd469501); 
        NEON_FF(a, b, c, d, x[8], s11, 0x698098d8); 
        NEON_FF(d, a, b, c, x[9], s12, 0x8b44f7af); 
        NEON_FF(c, d, a, b, x[10], s13, 0xffff5bb1); 
        NEON_FF(b, c, d, a, x[11], s14, 0x895cd7be); 
        NEON_FF(a, b, c, d, x[12], s11, 0x6b901122); 
        NEON_FF(d, a, b, c, x[13], s12, 0xfd987193); 
        NEON_FF(c, d, a, b, x[14], s13, 0xa679438e); 
        NEON_FF(b, c, d, a, x[15], s14, 0x49b40821); 

        /* Round 2 */

        NEON_GG(a, b, c, d, x[1], s21, 0xf61e2562); 
        NEON_GG(d, a, b, c, x[6], s22, 0xc040b340); 
        NEON_GG(c, d, a, b, x[11], s23, 0x265e5a51); 
        NEON_GG(b, c, d, a, x[0], s24, 0xe9b6c7aa); 
        NEON_GG(a, b, c, d, x[5], s21, 0xd62f105d); 
        NEON_GG(d, a, b, c, x[10], s22, 0x02441453); 
        NEON_GG(c, d, a, b, x[15], s23, 0xd8a1e681); 
        NEON_GG(b, c, d, a, x[4], s24, 0xe7d3fbc8); 
        NEON_GG(a, b, c, d, x[9], s21, 0x21e1cde6); 
        NEON_GG(d, a, b, c, x[14], s22, 0xc33707d6); 
        NEON_GG(c, d, a, b, x[3], s23, 0xf4d50d87); 
        NEON_GG(b, c, d, a, x[8], s24, 0x455a14ed); 
        NEON_GG(a, b, c, d, x[13], s21, 0xa9e3e905); 
        NEON_GG(d, a, b, c, x[2], s22, 0xfcefa3f8); 
        NEON_GG(c, d, a, b, x[7], s23, 0x676f02d9); 
        NEON_GG(b, c, d, a, x[12], s24, 0x8d2a4c8a); 

        /* Round 3 */

        NEON_HH(a, b, c, d, x[5], s31, 0xfffa3942); 
        NEON_HH(d, a, b, c, x[8], s32, 0x8771f681); 
        NEON_HH(c, d, a, b, x[11], s33, 0x6d9d6122); 
        NEON_HH(b, c, d, a, x[14], s34, 0xfde5380c); 
        NEON_HH(a, b, c, d, x[1], s31, 0xa4beea44); 
        NEON_HH(d, a, b, c, x[4], s32, 0x4bdecfa9); 
        NEON_HH(c, d, a, b, x[7], s33, 0xf6bb4b60); 
        NEON_HH(b, c, d, a, x[10], s34, 0xbebfbc70); 
        NEON_HH(a, b, c, d, x[13], s31, 0x289b7ec6); 
        NEON_HH(d, a, b, c, x[0], s32, 0xeaa127fa); 
        NEON_HH(c, d, a, b, x[3], s33, 0xd4ef3085); 
        NEON_HH(b, c, d, a, x[6], s34, 0x04881d05); 
        NEON_HH(a, b, c, d, x[9], s31, 0xd9d4d039); 
        NEON_HH(d, a, b, c, x[12], s32, 0xe6db99e5); 
        NEON_HH(c, d, a, b, x[15], s33, 0x1fa27cf8); 
        NEON_HH(b, c, d, a, x[2], s34, 0xc4ac5665); 

        /* Round 4 */

        NEON_II(a, b, c, d, x[0], s41, 0xf4292244); 
        NEON_II(d, a, b, c, x[7], s42, 0x432aff97); 
        NEON_II(c, d, a, b, x[14], s43, 0xab9423a7); 
        NEON_II(b, c, d, a, x[5], s44, 0xfc93a039); 
        NEON_II(a, b, c, d, x[12], s41, 0x655b59c3); 
        NEON_II(d, a, b, c, x[3], s42, 0x8f0ccc92); 
        NEON_II(c, d, a, b, x[10], s43, 0xffeff47d); 
        NEON_II(b, c, d, a, x[1], s44, 0x85845dd1); 
        NEON_II(a, b, c, d, x[8], s41, 0x6fa87e4f); 
        NEON_II(d, a, b, c, x[15], s42, 0xfe2ce6e0); 
        NEON_II(c, d, a, b, x[6], s43, 0xa3014314); 
        NEON_II(b, c, d, a, x[13], s44, 0x4e0811a1); 
        NEON_II(a, b, c, d, x[4], s41, 0xf7537e82); 
        NEON_II(d, a, b, c, x[11], s42, 0xbd3af235); 
        NEON_II(c, d, a, b, x[2], s43, 0x2ad7d2bb); 
        NEON_II(b, c, d, a, x[9], s44, 0xeb86d391); 

        a = vaddq_u32(a, aa);
        b = vaddq_u32(b, bb);
        c = vaddq_u32(c, cc);
        d = vaddq_u32(d, dd);
    }

    // 存储结果，处理字节序
    uint32_t results[4][4];
    vst1q_u32(results[0], a);
    vst1q_u32(results[1], b);
    vst1q_u32(results[2], c);
    vst1q_u32(results[3], d);

// 修正后的字节序处理部分
for (int i = 0; i < count; i++) {
    states[i*4 + 0] = ((results[0][i] << 24) | 
                       ((results[0][i] & 0xff00) << 8) |
                       ((results[0][i] >> 8) & 0xff00) | 
                       (results[0][i] >> 24));
    states[i*4 + 1] = ((results[1][i] << 24) | 
                       ((results[1][i] & 0xff00) << 8) |
                       ((results[1][i] >> 8) & 0xff00) | 
                       (results[1][i] >> 24));
    states[i*4 + 2] = ((results[2][i] << 24) | 
                       ((results[2][i] & 0xff00) << 8) |
                       ((results[2][i] >> 8) & 0xff00) | 
                       (results[2][i] >> 24));
    states[i*4 + 3] = ((results[3][i] << 24) | 
                       ((results[3][i] & 0xff00) << 8) |
                       ((results[3][i] >> 8) & 0xff00) | 
                       (results[3][i] >> 24));
}

    // 释放内存
    for (int i = 0; i < count; i++) {
        delete[] paddedMessages[i];
    }
}
