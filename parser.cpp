#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstdio>
#include <cstring>
#include <regex.h>

// 定義 struct Buffer
struct Buffer {
    std::string type;       // 儲存資料類型
    unsigned int address;   // 儲存地址
    unsigned int size;      // 區段大小
    char* data;             // 指向資料的動態分配區
    unsigned int iova;        // 設備虛擬地址
    unsigned int data_count; // 用來追蹤目前填入的數據數量

    Buffer(const std::string& t, unsigned int addr, unsigned int sz)
        : type(strdup(t)), address(addr), size(sz), data_count(0) {
        if  (type != "L1") {
            data = nullptr; // L1 不分配記憶體
        } else {
            data = new unsigned int[size / 4];    // 分配記憶體但不初始化
        }
    }

    ~Buffer() {
        if (data != nullptr) {
            delete[] data; // 只有當 data 不為 nullptr 時才釋放
        }
    }

    // 修改 addData 方法來接受單一 char 值
    void addData(char value) { 
        if (data_count < size) { 
            data[data_count++] = value; // 添加數據
        } else {
            std::cerr << "Warning: Buffer overflow when adding data to " << type << "\n";
        }
    }
};

// 定義 class Pattern 來管理不同類型的 buffer
class Pattern {
private:
    std::vector<std::shared_ptr<Buffer>> code_buffers;    // 儲存 Code buffer
    std::vector<std::shared_ptr<Buffer>> data_buffers;    // 儲存合併後的 Data buffer
    std::vector<std::pair<unsigned int, unsigned int>> bindings; // 儲存 offset 和 address
    Buffer* current_buffer; // 當前 buffer
        // 存儲 Golden 和 Golden_Mask buffer 的成對列表
    std::vector<std::pair<std::shared_ptr<Buffer>, std::shared_ptr<Buffer>>> golden_buffers; 

    // 獲取設備 TCM 地址的假設方法
    unsigned int getDeviceTcmAddress() {
        // 返回 TCM 地址
        return 0 /* TCM address */;
    }

    // 申請設備地址的方法，根據具體情況實現
    unsigned int allocateDeviceAddress(unsigned int size) {
        // 這裡應該包含分配設備地址的邏輯
        return 0 /* allocated address */;
    }

public:
    Pattern() : current_buffer(nullptr) {}

    void addBuffer(const std::string& type, unsigned int address, unsigned int size) {
        std::shared_ptr<Buffer> buffer = std::make_shared<Buffer>(type, address, size);
        current_buffer = buffer.get(); // 設定當前 buffer 為新增加的 buffer
        
        if (type == "Code") {
            code_buffers.push_back(buffer);
        } else {
            data_buffers.push_back(buffer); // 直接加入 data_buffers
        }
        std::cout << "Added buffer: Type = " << type << ", Address = " << std::hex << address << ", Size = " << size << " bytes\n";
    }

    void addBinding(unsigned int offset, unsigned int address) {
        bindings.emplace_back(offset, address);
        std::cout << "Added binding: Offset = " << offset << ", Address = " << std::hex << address << "\n";
    }

    Buffer* getCurrentBuffer() {
        return current_buffer; // 返回當前 buffer
    }

    void addGoldenBuffers(unsigned int address, unsigned int size) {
        std::shared_ptr<Buffer> golden_buffer = std::make_shared<Buffer>("Golden", address, size);
        std::shared_ptr<Buffer> golden_mask_buffer = std::make_shared<Buffer>("Golden_Mask", address, size);
        
        golden_buffers.emplace_back(golden_buffer, golden_mask_buffer); // 同時儲存 Golden 和 Golden_Mask buffer
        std::cout << "Added golden buffers: Address = " << std::hex << address << ", Size = " << size << " bytes\n";
    }

    std::vector<std::shared_ptr<Buffer>> getCodeBuffers() const {
        std::vector<std::shared_ptr<Buffer>> codeBuffers;
        for (const auto& buffer : data_buffers) {  // 假設 data_buffers 是一個成員變數
            if (buffer->type == "Code") {
                codeBuffers.push_back(buffer);
            }
        }
        return codeBuffers;
    }

    // API：根據 Output buffers 抓取 Golden 和 Golden_Mask buffers
    void getGoldenBuffersFromOutputs() {
        for (const auto& outputBuffer : output_buffers) {
            unsigned int address = outputBuffer->address;

            // 查找 Golden 和 Golden_Mask buffer
            for (const auto& pair : golden_buffers) {
                if (pair.first->address == address) {
                    // 找到匹配的 Golden 和 Golden_Mask buffers
                    std::cout << "找到 Output: " << outputBuffer->type 
                              << ", Golden: " << pair.first->type 
                              << ", Golden_Mask: " << pair.second->type 
                              << "，地址: " << std::hex << address << std::dec << std::endl;
                    // 可以在這裡進一步處理這些 buffers，例如填充數據
                }
            }
        }
    }

    std::pair<std::shared_ptr<Buffer>, std::shared_ptr<Buffer>> getGoldenBuffersByAddress(unsigned int address) {
        for (const auto& buffers : golden_buffers) {
            if (buffers.first->address == address) {
                return buffers; // 返回 Golden 和 Golden_Mask buffer
            }
        }
        return {nullptr, nullptr}; // 如果找不到則返回 nullptr
    }

    std::shared_ptr<Buffer> getDataBufferByAddress(unsigned int address) {
        for (const auto& buffer : data_buffers) {
            if (buffer->address == address) {
                return buffer; // 找到匹配的 buffer，返回
            }
        }
        return nullptr; // 如果找不到則返回 nullptr
    }

    void listAllBuffers() const {
        std::cout << "Code Buffers:\n";
        for (const auto& buf : code_buffers) {
            std::cout << "Type: " << buf->type << ", Address: " << std::hex << buf->address << ", Size: " << buf->size << " bytes\n";
        }

        std::cout << "Data Buffers:\n";
        for (const auto& buf : data_buffers) {
            std::cout << "Type: " << buf->type << ", Address: " << std::hex << buf->address << ", Size: " << buf->size << " bytes\n";
        }

        std::cout << "Golden Buffers:\n";
        for (const auto& buffers : golden_buffers) {
            std::cout << "Golden Type: " << buffers.first->type << ", Address: " << std::hex << buffers.first->address << ", Size: " << buffers.first->size << " bytes\n";
            std::cout << "Golden Mask Type: " << buffers.second->type << ", Address: " << std::hex << buffers.second->address << ", Size: " << buffers.second->size << " bytes\n";
        }
    }

    void listBindings() const {
        for (const auto& binding : bindings) {
            std::cout << "Binding: Offset = " << binding.first << ", Address = " << std::hex << binding.second << "\n";
        }
    }

    std::shared_ptr<Buffer> getNCodeBufferData(unsigned int index) {
        if (index < code_buffers.size()) {
            unsigned int binding_address = bindings[index].second; // 獲取第 N 個 binding 的地址
            return getDataBufferByAddress(binding_address); // 查找對應的 data buffer
        }
        return nullptr; // 如果 index 超出範圍則返回 nullptr
    }

    void patchingAllCodeBuffers() {
        for (size_t n = 0; n < code_buffers.size(); ++n) {
            auto& codeBuffer = code_buffers[n];

            if (n >= bindings.size()) {
                std::cerr << "Error: No binding available for index " << n << ". Skipping.\n";
                continue; // 若沒有對應的 binding，則跳過
            }

            unsigned int bindingOffset = bindings[n].first;
            unsigned int bindingAddress = bindings[n].second;

            std::shared_ptr<Buffer> matchedBuffer = nullptr;
            unsigned int closestDiff = std::numeric_limits<unsigned int>::max();

            for (const auto& buffer : data_buffers) {
                unsigned int bufferEnd = buffer->address + buffer->size;
                unsigned int diff = bindingAddress - buffer->address;

                // 檢查 buffer 的地址是否在範圍內
                if (buffer->address <= bindingAddress && bindingAddress < bufferEnd) {
                    matchedBuffer = buffer;
                    break; // 找到精確匹配，直接返回
                }

                // 更新最近的匹配 buffer
                if (diff < closestDiff && bindingAddress < bufferEnd) {
                    closestDiff = diff;
                    matchedBuffer = buffer;
                }
            }

            if (!matchedBuffer) {
                std::cerr << "No matching buffer found for binding address " << std::hex << bindingAddress << std::dec 
                        << " for Code buffer at index " << n << ". Skipping.\n";
                continue; // 找不到匹配的 buffer，直接跳過
            }

            // 使用 matched buffer 的 iova 更新 codeBuffer 的 data
            if (bindingOffset / 4 < codeBuffer->size) {
                codeBuffer->data[bindingOffset / 4] = static_cast<char>(matchedBuffer->iova);
                std::cout << "Patched Code buffer at index " << n << " at offset " << bindingOffset / 4 
                        << " with iova " << matchedBuffer->iova << std::endl;
            } else {
                std::cerr << "Error: Offset " << bindingOffset << " is out of bounds for Code buffer at index " << n << ".\n";
            }
        }
    }
     // 獲取所有 data buffers，並根據類型填入設備地址
    void allocateDeviceAddresses() {
        for (const auto& buffer : data_buffers) {
            unsigned int deviceAddress = 0;

            if (buffer->type == "L1") {
                deviceAddress = getDeviceTcmAddress(); // 獲取設備 TCM 地址
                buffer->iova = deviceAddress; // 將地址填入 iova
                std::cout << "Assigned TCM address: " << std::hex << deviceAddress 
                          << " for L1 buffer." << std::dec << std::endl;
            } 
            else if (buffer->type == "Temporary") {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress; // 填入設備地址
                    // 初始化為0
                    memset(buffer->iova, 0, buffer->size);
                    std::cout << "Allocated Temporary buffer address: " << std::hex << deviceAddress 
                              << " and initialized to 0." << std::dec << std::endl;
                }
            } 
            else if (buffer->type == "Output") {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress; // 填入設備地址
                    // 初始化為0xa5
                    memset(buffer->iova, 0xa5, buffer->size);
                    std::cout << "Allocated Output buffer address: " << std::hex << deviceAddress 
                              << " and initialized to 0xa5." << std::dec << std::endl;
                }
            } 
            else { // 其他類型
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress; // 填入設備地址
                    // 將 buffer data 複製到設備地址
                    memcpy((void*)buffer->iova , buffer->data, buffer->size);
                    std::cout << "Allocated Other buffer address: " << std::hex << deviceAddress 
                              << " and copied data." << std::dec << std::endl;
                }
            }
        }
    }
};

// 解析檔案並填充 Pattern
void parseFile(const std::string& filename, Pattern& pattern) {
    FILE* file = fopen(filename.c_str(), "r");
    if (file == nullptr) {
        std::cerr << "無法開啟檔案: " << filename << std::endl;
        return;
    }

    char line[256];
    regex_t header_regex;
    regcomp(&header_regex, "^// ([A-Za-z]+)@([0-9a-fA-F]+) \\{([0-9]+)\\}", REG_EXTENDED);
    
    regex_t binding_regex;
    regcomp(&binding_regex, "^// (\\d+)@(0[xX]?[0-9a-fA-F]+)$", REG_EXTENDED);
    
    regex_t data_regex;
    regcomp(&data_regex, "^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$", REG_EXTENDED);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // 移除換行符號

        // 匹配形如 `// Code@40001000 {32}`
        if (regexec(&header_regex, line, 0, nullptr, 0) == 0) {
            std::string type(32, '\0'); // 使用預設大小來避免訪問空指針
            unsigned int address, size;
            sscanf(line, "// %[^@]@%x {%u", &type[0], &address, &size); // 解析類型、地址和大小
            pattern.addBuffer(type, address, size);
        }
        // 處理 Binding 格式
        else if (regexec(&binding_regex, line, 0, nullptr, 0) == 0) {
            unsigned int offset;
            unsigned int address;
            sscanf(line, "// %u@%x", &offset, &address); // 解析大小和地址
            pattern.addBinding(offset, address); // 儲存 offset 和地址
        }
        // 處理數據行
        else if (regexec(&data_regex, line, 0, nullptr, 0) == 0) {
            char data[16]; // 儲存每行的 16 個資料
            sscanf(line, "%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x", 
                   &data[0], &data[1], &data[2], &data[3], 
                   &data[4], &data[5], &data[6], &data[7], 
                   &data[8], &data[9], &data[10], &data[11], 
                   &data[12], &data[13], &data[14], &data[15]);

            // 將數據添加到對應的 buffer
            Buffer* current_buffer = pattern.getCurrentBuffer(); // 獲取當前 buffer
            if (current_buffer) {
                for (int i = 0; i < sizeof(data); ++i) {
                    current_buffer->addData(data[i]); // 將數據逐個添加到 buffer
                }
            }
        }
    }

    regfree(&data_regex);
    regfree(&binding_regex);
    regfree(&header_regex);
    fclose(file); // 關閉檔案
}

// 專門用於解析 Golden data 檔案
void parseGoldenFile(const std::string& filename, Pattern& pattern) {
    FILE* file = fopen(filename.c_str(), "r");
    if (file == nullptr) {
        std::cerr << "無法開啟檔案: " << filename << std::endl;
        return;
    }

    char line[256];
    regex_t header_regex;
    regcomp(&header_regex, "^// Output@([0-9a-fA-F]+) \\{([0-9]+)\\}", REG_EXTENDED);
    regex_t data_regex;
    regcomp(&data_regex, "^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$", REG_EXTENDED);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0; // 移除換行符號

        // 匹配形如 `// Output@50006000 {32}`
        if (regexec(&header_regex, line, 0, nullptr, 0) == 0) {
            unsigned int address, size;
            sscanf(line, "// Output@%x {%u", &address, &size); // 解析地址和大小
            
            // 創建 Golden 和 Golden_Mask buffer
            pattern.addGoldenBuffers(address, size);
        }
        // 處理數據行
        else if (regexec(&data_regex, line, 0, nullptr, 0) == 0) {
    
            char data[16]; // 儲存每行的 16 個資料

            #if 0 // 使用舊方式get data
            sscanf(line, "%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x", 
                   &data[0], &data[1], &data[2], &data[3], 
                   &data[4], &data[5], &data[6], &data[7], 
                   &data[8], &data[9], &data[10], &data[11], 
                   &data[12], &data[13], &data[14], &data[15]);
            #endif

            // 將數據同時添加到 Golden 和 Golden_Mask buffer
            auto [golden, golden_mask] = pattern.getGoldenBuffersByAddress(address); // 獲取 Golden 和 Golden_Mask buffer
            if (golden) {
                for (int i = 0; i < 16; ++i) {
                    golden->addData(data[i]); // 將數據添加到 Golden buffer
                }
            }
            if (golden_mask) {
                for (int i = 0; i < 16; ++i) {
                    golden_mask->addData(data[i]); // 將數據添加到 Golden_Mask buffer
                }
            }
        }
    }

    regfree(&data_regex);
    regfree(&header_regex);
    fclose(file); // 關閉檔案
}

//-------------------------------------------------------------------------------
// 以上為Pattern.h
//#include "Pattern.h"
//-------------------------------------------------------------------------------
void showBuffersAndBindings(const Pattern& pattern) {
    // 顯示所有的 buffers
    std::cout << "Buffers:" << std::endl;
    for (const auto& buffer : pattern.getDataBuffers()) {
        std::cout << "Type: " << buffer->type 
                  << ", Address: " << std::hex << buffer->address 
                  << ", Size: " << std::dec << buffer->size 
                  << std::endl;
    }

    // 顯示所有的 bindings
    std::cout << "\nBindings:" << std::endl;
    for (const auto& binding : pattern.getBindings()) {
        std::cout << "Offset: " << std::hex << binding.offset 
                  << ", Address: " << binding.address << std::dec 
                  << std::endl;
    }

    // 顯示 golden 信息
    std::cout << "\nGolden Buffers:" << std::endl;
    auto goldenBuffers = pattern.getGoldenBuffers();
    for (const auto& pair : goldenBuffers) {
        std::cout << "Golden: " << pair.first->type 
                  << ", iova: " << std::hex << pair.first->iova 
                  << std::dec << ", Size: " << pair.first->size 
                  << std::endl;
    }
}

int main() {
    Pattern pattern;

    // 解析第一個文件
    pattern.parseFile("input.txt"); // 假設第一個文件名為 input.txt

    // 解析第二個文件
    pattern.parseGoldenFile("golden.txt"); // 假設第二個文件名為 golden.txt

    // 顯示 buffers, bindings 和 golden 信息
    showBuffersAndBindings(pattern);

    // 分配設備地址
    pattern.allocateDeviceAddresses();

    // 補丁所有的 Code buffers
    pattern.patchingAllCodeBuffers();

    // 顯示所有 Code buffers 的 iova 和大小
    std::cout << "\nCode Buffers:" << std::endl;
    for (const auto& buffer : pattern.getCodeBuffers()) {
        std::cout << "Type: " << buffer->type 
                  << ", iova: " << std::hex << buffer->iova 
                  << ", Size: " << std::dec << buffer->size 
                  << std::endl;
    }

    return 0;
}
