#include "PCFG.h"
#include <chrono>
#include <fstream>
#include "md5.h"
#include <iomanip>
#include <vector>
#include <algorithm>

using namespace std;
using namespace chrono;

// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main -O1
// g++ main.cpp train.cpp guessing.cpp md5.cpp -o main -O2

int main() {
    // 计时变量
    double time_hash = 0;   // MD5哈希时间
    double time_guess = 0;  // 猜测生成时间
    double time_train = 0;  // 模型训练时间
    
    PriorityQueue q;
    
    // 训练模型
    auto start_train = system_clock::now();
    q.m.train("/guessdata/Rockyou-singleLined-full.txt");
    q.m.order();
    auto end_train = system_clock::now();
    auto duration_train = duration_cast<microseconds>(end_train - start_train);
    time_train = double(duration_train.count()) * microseconds::period::num / microseconds::period::den;
    
    // 初始化优先队列
    q.init();
    cout << "Initialization complete. Starting password generation..." << endl;
    
    int curr_num = 0;
    auto start = system_clock::now();
    int history = 0;  // 记录已生成的猜测总数
    
    // 用于批量处理的缓冲区
    const int BATCH_SIZE = 4;
    string batch[BATCH_SIZE];
    bit32 batch_states[BATCH_SIZE * 4];
    int batch_count = 0;
    
    // 主循环：生成密码猜测
    while (!q.priority.empty()) {
        q.PopNext();
        q.total_guesses = q.guesses.size();
        
        // 每生成100,000个猜测输出进度
        if (q.total_guesses - curr_num >= 100000) {
            cout << "Guesses generated: " << history + q.total_guesses << endl;
            curr_num = q.total_guesses;
            
            // 设置生成的猜测上限
            int generate_n = 10000000;
            if (history + q.total_guesses > generate_n) {
                auto end = system_clock::now();
                auto duration = duration_cast<microseconds>(end - start);
                time_guess = double(duration.count()) * microseconds::period::num / microseconds::period::den;
                
                cout << "Guess time: " << time_guess - time_hash << " seconds" << endl;
                cout << "Hash time: " << time_hash << " seconds" << endl;
                cout << "Train time: " << time_train << " seconds" << endl;
                break;
            }
        }
        
        // 当生成的猜测达到一定数量时，进行批量哈希处理
        if (curr_num > 1000000) {
            auto start_hash = system_clock::now();
            
            // 使用NEON批量处理密码哈希
            for (string pw : q.guesses) {
                batch[batch_count] = pw;
                batch_count++;
                
                // 当收集到足够数量的密码时，调用NEON MD5函数
                if (batch_count == BATCH_SIZE) {
                    MD5Hash_NEON(batch, batch_states, batch_count);
                    
                    // 处理哈希结果
                    for (int i = 0; i < batch_count; i++) {
                        // 可以在这里将哈希结果写入文件或进行其他操作
                        /*
                        cout << batch[i] << "\t";
                        for (int j = 0; j < 4; j++) {
                            cout << hex << setw(8) << setfill('0') << batch_states[i*4 + j];
                        }
                        cout << endl;
                        */
                    }
                    
                    batch_count = 0;
                }
            }
            
            // 处理剩余的不足一个批次的密码
            if (batch_count > 0) {
                MD5Hash_NEON(batch, batch_states, batch_count);
                
                // 处理哈希结果
                for (int i = 0; i < batch_count; i++) {
                    // 可以在这里将哈希结果写入文件或进行其他操作
                    /*
                    cout << batch[i] << "\t";
                    for (int j = 0; j < 4; j++) {
                        cout << hex << setw(8) << setfill('0') << batch_states[i*4 + j];
                    }
                    cout << endl;
                    */
                }
                
                batch_count = 0;
            }
            
            // 计算哈希时间
            auto end_hash = system_clock::now();
            auto duration = duration_cast<microseconds>(end_hash - start_hash);
            time_hash += double(duration.count()) * microseconds::period::num / microseconds::period::den;
            
            // 更新已生成的口令总数并清空缓冲区
            history += curr_num;
            curr_num = 0;
            q.guesses.clear();
        }
    }
    
    // 处理最后剩余的猜测（如果有）
    if (!q.guesses.empty()) {
        auto start_hash = system_clock::now();
        
        // 使用NEON批量处理剩余的密码
        for (string pw : q.guesses) {
            batch[batch_count] = pw;
            batch_count++;
            
            if (batch_count == BATCH_SIZE) {
                MD5Hash_NEON(batch, batch_states, batch_count);
                batch_count = 0;
            }
        }
        
        if (batch_count > 0) {
            MD5Hash_NEON(batch, batch_states, batch_count);
        }
        
        auto end_hash = system_clock::now();
        auto duration = duration_cast<microseconds>(end_hash - start_hash);
        time_hash += double(duration.count()) * microseconds::period::num / microseconds::period::den;
        
        history += q.guesses.size();
        q.guesses.clear();
    }
    
    // 输出最终统计信息
    cout << "\nFinal Statistics:" << endl;
    cout << "Total guesses generated: " << history << endl;
    cout << "Total training time: " << time_train << " seconds" << endl;
    cout << "Total guessing time: " << time_guess << " seconds" << endl;
    cout << "Total hashing time: " << time_hash << " seconds" << endl;
    cout << "Total execution time: " << time_train + time_guess + time_hash << " seconds" << endl;
    
    return 0;
}
