#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cstdio>
#include <cstring>
#include <regex.h>

struct Buffer {
    std::string type;
    unsigned int address;
    unsigned int size;
    std::unique_ptr<char[]> data;
    unsigned int iova;
    unsigned int data_count;

    Buffer(const std::string& t, unsigned int addr, unsigned int sz)
        : type(t), address(addr), size(sz), data_count(0) {
        if (type != "L1")
            data = std::make_unique<char[]>(size);
    }

    void addData(char value) {
        if (data_count < size)
            data[data_count++] = value;
        else
            std::cerr << "Warning: Buffer overflow when adding data to " << type << "\n";
    }
};

class Pattern {
private:
    std::vector<std::shared_ptr<Buffer>> code_buffers;
    std::vector<std::shared_ptr<Buffer>> data_buffers;
    std::vector<std::pair<unsigned int, unsigned int>> bindings;
    std::vector<std::pair<std::shared_ptr<Buffer>, std::shared_ptr<Buffer>>> golden_buffers;
    Buffer* current_buffer;

    unsigned int getDeviceTcmAddress() { return 0; }
    unsigned int allocateDeviceAddress(unsigned int size) { return 0; }

public:
    Pattern() : current_buffer(nullptr) {}

    void addBuffer(const std::string& type, unsigned int address, unsigned int size) {
        auto buffer = std::make_shared<Buffer>(type, address, size);
        current_buffer = buffer.get(); 

        if (type == "Code")
            code_buffers.push_back(buffer);
        else
            data_buffers.push_back(buffer);
        std::cout << "Added buffer: Type = " << type << ", Address = " << std::hex << address << ", Size = " << size << " bytes\n";
    }

    void addBinding(unsigned int offset, unsigned int address) {
        bindings.emplace_back(offset, address);
        std::cout << "Added binding: Offset = " << offset << ", Address = " << std::hex << address << "\n";
    }

    Buffer* getCurrentBuffer() { return current_buffer; }

    void addGoldenBuffers(unsigned int address, unsigned int size) {
        auto golden_buffer = std::make_shared<Buffer>("Golden", address, size);
        auto golden_mask_buffer = std::make_shared<Buffer>("Golden_Mask", address, size);
        
        golden_buffers.emplace_back(golden_buffer, golden_mask_buffer);
        std::cout << "Added golden buffers: Address = " << std::hex << address << ", Size = " << size << " bytes\n" << std::dec;
    }

    std::pair<std::shared_ptr<Buffer>, std::shared_ptr<Buffer>> getGoldenBuffersByAddress(unsigned int address) {
        for (const auto& buffers : golden_buffers) {
            if (buffers.first->address == address)
                return buffers; 
        }
        return {nullptr, nullptr};
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
        for (const auto& binding : bindings)
            std::cout << "Binding: Offset = " << binding.first << ", Address = " << std::hex << binding.second << "\n";
    }

    /* class Command */
    void allocateDeviceAddresses() {
        for (const auto& buffer : data_buffers) {
            unsigned int deviceAddress = 0;

            if (buffer->type == "L1") {
                deviceAddress = getDeviceTcmAddress();
                buffer->iova = deviceAddress;
                std::cout << "Assigned TCM address: " << std::hex << deviceAddress 
                          << " for L1 buffer." << std::dec << std::endl;
            } else if (buffer->type == "Temporary") {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress;
                    memset(buffer->iova, 0, buffer->size);
                    std::cout << "Allocated Temporary buffer address: " << std::hex << deviceAddress 
                              << " and initialized to 0." << std::dec << std::endl;
                }
            } else if (buffer->type == "Output") {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress;
                    memset(buffer->iova, 0xa5, buffer->size);
                    std::cout << "Allocated Output buffer address: " << std::hex << deviceAddress 
                              << " and initialized to 0xa5." << std::dec << std::endl;
                }
            } else {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress;
                    memcpy((void*)buffer->iova , buffer->data, buffer->size);
                    std::cout << "Allocated Other buffer address: " << std::hex << deviceAddress 
                              << " and copied data." << std::dec << std::endl;
                }
            }
        }
    }

    void patchingAllCodeBuffers() {
        for (size_t n = 0; n < code_buffers.size(); ++n) {
            auto& codeBuffer = code_buffers[n];

            if (n >= bindings.size()) {
                std::cerr << "Error: No binding available for index " << n << ". Skipping.\n";
                continue;
            }

            unsigned int bindingOffset = bindings[n].first;
            unsigned int bindingAddress = bindings[n].second;

            std::shared_ptr<Buffer> matchedBuffer = nullptr;
            unsigned int closestDiff = std::numeric_limits<unsigned int>::max();

            for (const auto& buffer : data_buffers) {
                unsigned int bufferEnd = buffer->address + buffer->size;
                unsigned int diff = bindingAddress - buffer->address;

                if (buffer->address <= bindingAddress && bindingAddress < bufferEnd) {
                    matchedBuffer = buffer;
                    break;
                }

                if (diff < closestDiff && bindingAddress < bufferEnd) {
                    closestDiff = diff;
                    matchedBuffer = buffer;
                }
            }

            if (!matchedBuffer) {
                std::cerr << "No matching buffer found for binding address " << std::hex << bindingAddress << std::dec 
                        << " for Code buffer at index " << n << ". Skipping.\n";
                continue;
            }

            if (bindingOffset < codeBuffer->size) {
                codeBuffer->data[bindingOffset / 4] = static_cast<char>(matchedBuffer->iova);
                std::cout << "Patched Code buffer at index " << n << " at offset " << bindingOffset / 4 
                        << " with iova " << matchedBuffer->iova << std::endl;
            } else {
                std::cerr << "Error: Offset " << bindingOffset << " is out of bounds for Code buffer at index " << n << ".\n";
            }
        }
    }

    std::vector<std::shared_ptr<Buffer>> getCodeBuffers() const {
        std::vector<std::shared_ptr<Buffer>> codeBuffers;
        for (const auto& buffer : data_buffers) {
            if (buffer->type == "Code")
                codeBuffers.push_back(buffer);
        }
        return codeBuffers;
    }

    void getGoldenBuffersFromOutputs() {
        for (const auto& outputBuffer : data_buffers) {  // Assuming output_buffers is the same as data_buffers for simplification
            unsigned int address = outputBuffer->address;

            for (const auto& pair : golden_buffers) {
                if (pair.first->address == address) {
                    std::cout << "Found Output: " << outputBuffer->type 
                              << ", Golden: " << pair.first->type 
                              << ", Golden_Mask: " << pair.second->type 
                              << ", Address: " << std::hex << address << std::dec << std::endl;
                    // Compare result
                }
            }
        }
    }
};

void parseFile(const std::string& filename, Pattern& pattern) {
    FILE* file = fopen(filename.c_str(), "r");
    if (file == nullptr) {
        std::cerr << "無法開啟檔案: " << filename << std::endl;
        return;
    }

    char line[256];
    // "// Code@40001000 {32}"
    regex_t header_regex;
    regcomp(&header_regex, "^// ([A-Za-z]+)@([0-9a-fA-F]+) \\{([0-9]+)\\}", REG_EXTENDED);
    // "// Binding"
    regex_t binding_regex;
    regcomp(&binding_regex, "^// (\\d+)@(0[xX]?[0-9a-fA-F]+)$", REG_EXTENDED);
    // "12345678_9abcdef0_aaaaaaaa_00000000"
    regex_t data_regex;
    regcomp(&data_regex, "^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$", REG_EXTENDED);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        if (regexec(&header_regex, line, 0, nullptr, 0) == 0) {
            std::string type(32, '\0');
            unsigned int address, size;
            sscanf(line, "// %[^@]@%x {%u", &type[0], &address, &size);
            pattern.addBuffer(type, address, size);
        } else if (regexec(&binding_regex, line, 0, nullptr, 0) == 0) {
            unsigned int offset;
            unsigned int address;
            sscanf(line, "// %u@%x", &offset, &address);
            pattern.addBinding(offset, address);
        }else if (regexec(&data_regex, line, 0, nullptr, 0) == 0) {
            char data[16];
            sscanf(line, "%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x", 
                   &data[0], &data[1], &data[2], &data[3], 
                   &data[4], &data[5], &data[6], &data[7], 
                   &data[8], &data[9], &data[10], &data[11], 
                   &data[12], &data[13], &data[14], &data[15]);

            Buffer* current_buffer = pattern.getCurrentBuffer();
            if (current_buffer) {
                for (int i = 0; i < sizeof(data); ++i)
                    current_buffer->addData(data[i]);
            }
        }
    }

    regfree(&data_regex);
    regfree(&binding_regex);
    regfree(&header_regex);
    fclose(file);
}


void parseGoldenFile(const std::string& filename, Pattern& pattern) {
    FILE* file = fopen(filename.c_str(), "r");
    if (file == nullptr) {
        std::cerr << "無法開啟檔案: " << filename << std::endl;
        return;
    }

    char line[256];
    // "// Output@50006000 {32}"
    regex_t header_regex;
    regcomp(&header_regex, "^// Output@([0-9a-fA-F]+) \\{([0-9]+)\\}", REG_EXTENDED);
    // "xxxxxxxx_xxxxdef0_aaaaaaaa_00000000"
    regex_t data_regex;
    regcomp(&data_regex, "^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$", REG_EXTENDED);

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\n")] = 0;

        if (regexec(&header_regex, line, 0, nullptr, 0) == 0) {
            unsigned int address, size;
            sscanf(line, "// Output@%x {%u", &address, &size);
            pattern.addGoldenBuffers(address, size);
        } else if (regexec(&data_regex, line, 0, nullptr, 0) == 0) {
    
            char data[16];

            #if 0 // Use legacy operaions
            sscanf(line, "%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x_%02x%02x%02x%02x", 
                   &data[0], &data[1], &data[2], &data[3], 
                   &data[4], &data[5], &data[6], &data[7], 
                   &data[8], &data[9], &data[10], &data[11], 
                   &data[12], &data[13], &data[14], &data[15]);
            #endif

            auto [golden, golden_mask] = pattern.getGoldenBuffersByAddress(address);
            if (golden) {
                for (int i = 0; i < 16; ++i)
                    golden->addData(data[i]);
            }
            if (golden_mask) {
                for (int i = 0; i < 16; ++i) {
                    golden_mask->addData(data[i]);
            }
        }
    }

    regfree(&data_regex);
    regfree(&header_regex);
    fclose(file);
}

//-------------------------------------------------------------------------------
// 以上為Pattern.h
//#include "Pattern.h"
//-------------------------------------------------------------------------------

int main() {

    // 1. Create pattern
    Pattern pattern;

    pattern.parseFile("0.hex");
    pattern.parseGoldenFile("cmodel_output.hex");
    pattern.listAllBuffers();

    // 2. Create APU command
    //    2-1. Set APU command paremeters
 
    //    2-2. Prepare MDLA command
    pattern.allocateDeviceAddresses();
    pattern.patchingAllCodeBuffers();
    std::cout << "\nCode Buffers:" << std::endl;
    for (const auto& buffer : pattern.getCodeBuffers()) {
        std::cout << "Type: " << buffer->type 
                  << ", iova: " << std::hex << buffer->iova 
                  << ", Size: " << std::dec << buffer->size 
                  << std::endl;
    }

    // 3. Run Command

    // 4. Command done
    //    4-1. Compare output data
    //    4-2. Show result

    // 5. Relese APU Command

    return 0;
}
