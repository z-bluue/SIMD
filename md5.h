#include <iostream>
#include <string>
#include <cstring>
#include <arm_neon.h>
using namespace std;

// 定义了Byte，便于使用
typedef unsigned char Byte;
// 定义了32比特
typedef unsigned int bit32;

// MD5的一系列参数。参数是固定的，其实你不需要看懂这些
#define s11 7
#define s12 12
#define s13 17
#define s14 22
#define s21 5
#define s22 9
#define s23 14
#define s24 20
#define s31 4
#define s32 11
#define s33 16
#define s34 23
#define s41 6
#define s42 10
#define s43 15
#define s44 21

/**
 * @Basic MD5 functions.
 *
 * @param there bit32.
 *
 * @return one bit32.
 */
// 定义了一系列MD5中的具体函数
// 这四个计算函数是需要你进行SIMD并行化的
// 可以看到，FGHI四个函数都涉及一系列位运算，在数据上是对齐的，非常容易实现SIMD的并行化

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/**
 * @Rotate Left.
 *
 * @param {num} the raw number.
 *
 * @param {n} rotate left n.
 *
 * @return the number after rotated left.
 */
// 定义了一系列MD5中的具体函数
// 这五个计算函数（ROTATELEFT/FF/GG/HH/II）和之前的FGHI一样，都是需要你进行SIMD并行化的
// 但是你需要注意的是#define的功能及其效果，可以发现这里的FGHI是没有返回值的，为什么呢？你可以查询#define的含义和用法
// NEON版本的MD5核心函数
#define NEON_ROTATELEFT(vec, n) vorrq_u32(vshlq_n_u32(vec, n), vshrq_n_u32(vec, 32-(n)))

#define NEON_FF(a, b, c, d, x, s, ac) { \
  vbit32 f = vorrq_u32(vandq_u32(b, c), vandq_u32(vmvnq_u32(a), d)); \
  a = vaddq_u32(a, f); \
  a = vaddq_u32(a, x); \
  a = vaddq_u32(a, vdupq_n_u32(ac)); \
  a = NEON_ROTATELEFT(a, s); \
  a = vaddq_u32(a, b); \
}

#define NEON_GG(a, b, c, d, x, s, ac) { \
  vbit32 g = vorrq_u32(vandq_u32(b, d), vandq_u32(c, vmvnq_u32(d))); \
  a = vaddq_u32(a, g); \
  a = vaddq_u32(a, x); \
  a = vaddq_u32(a, vdupq_n_u32(ac)); \
  a = NEON_ROTATELEFT(a, s); \
  a = vaddq_u32(a, b); \
}

#define NEON_HH(a, b, c, d, x, s, ac) { \
  vbit32 h = veorq_u32(veorq_u32(b, c), d); \
  a = vaddq_u32(a, h); \
  a = vaddq_u32(a, x); \
  a = vaddq_u32(a, vdupq_n_u32(ac)); \
  a = NEON_ROTATELEFT(a, s); \
  a = vaddq_u32(a, b); \
}

#define NEON_II(a, b, c, d, x, s, ac) { \
  vbit32 i = veorq_u32(b, vorrq_u32(a, vmvnq_u32(d))); \
  a = vaddq_u32(a, i); \
  a = vaddq_u32(a, x); \
  a = vaddq_u32(a, vdupq_n_u32(ac)); \
  a = NEON_ROTATELEFT(a, s); \
  a = vaddq_u32(a, b); \
}

// NEON向量类型定义
typedef uint32x4_t vbit32;

void MD5Hash_NEON(const string* inputs, bit32* states, int count);
