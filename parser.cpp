#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstdio>
#include <cstring>
#include <regex.h>

// 定義 struct Buffer
struct Buffer {
    std::string type;
    unsigned int address;
    unsigned int size;
    std::unique_ptr<char[]> data; // 使用 unique_ptr 來自動管理記憶體
    unsigned int iova;
    unsigned int data_count;

    Buffer(const std::string& t, unsigned int addr, unsigned int sz)
        : type(t), address(addr), size(sz), data_count(0) {
        if (type == "L1") {
            data = nullptr; // L1 不分配記憶體
        } else {
            data = std::make_unique<char[]>(size); // 使用 unique_ptr 來管理動態分配的記憶體
        }
    }

    void addData(char value) { 
        if (data_count < size) { 
            data[data_count++] = value; 
        } else {
            std::cerr << "Warning: Buffer overflow when adding data to " << type << "\n";
        }
    }
};

// 定義 class Pattern 來管理不同類型的 buffer
class Pattern {
private:
    std::vector<std::shared_ptr<Buffer>> code_buffers;
    std::vector<std::shared_ptr<Buffer>> data_buffers;
    std::vector<std::pair<unsigned int, unsigned int>> bindings;
    std::vector<std::pair<std::shared_ptr<Buffer>, std::shared_ptr<Buffer>>> golden_buffers;
    Buffer* current_buffer;

    unsigned int getDeviceTcmAddress() {
        return 0; // 假設的 TCM 地址
    }

    unsigned int allocateDeviceAddress(unsigned int size) {
        return 0; // 假設的設備地址分配邏輯
    }

public:
    Pattern() : current_buffer(nullptr) {}

    void addBuffer(const std::string& type, unsigned int address, unsigned int size) {
        auto buffer = std::make_shared<Buffer>(type, address, size);
        current_buffer = buffer.get(); 

        if (type == "Code") {
            code_buffers.push_back(buffer);
        } else {
            data_buffers.push_back(buffer);
        }
        std::cout << "Added buffer: Type = " << type << ", Address = " << std::hex << address << ", Size = " << size << " bytes\n";
    }

    void addBinding(unsigned int offset, unsigned int address) {
        bindings.emplace_back(offset, address);
        std::cout << "Added binding: Offset = " << offset << ", Address = " << std::hex << address << "\n";
    }

    Buffer* getCurrentBuffer() {
        return current_buffer;
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
        auto listBufferType = [](const std::string& label, const auto& buffers) {
            std::cout << label << ":\n";
            for (const auto& buf : buffers) {
                std::cout << "Type: " << buf->type << ", Address: " << std::hex << buf->address << ", Size: " << std::dec << buf->size << " bytes\n";
            }
        };

        listBufferType("Code Buffers", code_buffers);
        listBufferType("Data Buffers", data_buffers);
        listBufferType("Golden Buffers", golden_buffers);
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
