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
    unsigned int data_count; // 用來追蹤目前填入的數據數量

    Buffer(const std::string& t, unsigned int addr, unsigned int sz)
        : type(t), address(addr), size(sz), data_count(0) {
        if ((type == "Temporary") || (type == "Output")) {
            data = new unsigned int[size / 4]();  // 初始化為 0
        } else if ((type == "Golden") || (type == "Golden_Mask")) {
            data = new unsigned int[size / 4];    // 分配記憶體但不初始化
        } else if (type != "L1") {
            data = new unsigned int[size / 4];    // 一般類型分配記憶體
        } else {
            data = nullptr; // L1 不分配記憶體
        }
    }

    ~Buffer() {
        delete[] data;
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
            pattern.addGoldenBuffer("Golden", address, size);
            pattern.addGoldenBuffer("Golden_Mask", address, size);
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
    regfree(&header_regex);
    fclose(file); // 關閉檔案
}

int main() {
    // 創建 Pattern 類別實例
    Pattern pattern;

    // 從檔案解析並填充 Pattern
    parseFile("input.txt", pattern);

    // 解析第二個檔案以創建 Golden 和 Golden_Mask buffer
    parseGoldenFile("second_file.txt", pattern);

    // 列出所有 buffer 資訊
    pattern.listAllBuffers();
    pattern.listBindings();

    return 0;
}
