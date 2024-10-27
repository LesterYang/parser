#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <regex>
#include <fstream>
#include <sstream>
#include <iomanip>

struct Buffer {
    std::string type;
    unsigned int address;
    unsigned int size;
    std::vector<char> data;
    unsigned int iova;
    unsigned int data_count;

    Buffer(const std::string& t, unsigned int addr, unsigned int sz)
        : type(t), address(addr), size(sz), data(sz), data_count(0) {}

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

    unsigned int getDeviceTcmAddress() { return 0x1000; } // Example implementation
    unsigned int allocateDeviceAddress(unsigned int size) { return 0x2000; } // Example implementation

    void allocateDeviceAddresses() {
        for (const auto& buffer : data_buffers) {
            unsigned int deviceAddress = 0;

            if (buffer->type == "L1") {
                deviceAddress = getDeviceTcmAddress();
                buffer->iova = deviceAddress;
                std::cout << "Assigned TCM address: " << std::hex << deviceAddress 
                          << " for L1 buffer." << std::dec << std::endl;
            } else {
                deviceAddress = allocateDeviceAddress(buffer->size);
                if (deviceAddress != 0) {
                    buffer->iova = deviceAddress;
                    if (buffer->type == "Temporary") {
                        std::fill(buffer->data.begin(), buffer->data.end(), 0);
                        std::cout << "Allocated Temporary buffer address: " << std::hex << deviceAddress 
                                  << " and initialized to 0." << std::dec << std::endl;
                    } else if (buffer->type == "Output") {
                        std::fill(buffer->data.begin(), buffer->data.end(), 0xa5);
                        std::cout << "Allocated Output buffer address: " << std::hex << deviceAddress 
                                  << " and initialized to 0xa5." << std::dec << std::endl;
                    } else {
                        std::copy(buffer->data.begin(), buffer->data.end(), reinterpret_cast<char*>(buffer->iova));
                        std::cout << "Allocated Other buffer address: " << std::hex << deviceAddress 
                                  << " and copied data." << std::dec << std::endl;
                    }
                }
            }
        }
    }

    int patchingAllCodeBuffers() {
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

                if (buffer->address == bindingAddress) {
                    matchedBuffer = buffer;
                    break;
                }

                if (bindingAddress > buffer->address && bindingAddress < bufferEnd) {
                    unsigned int diff = bindingAddress - buffer->address;
                    if (diff < closestDiff) {
                        closestDiff = diff;
                        matchedBuffer = buffer;
                    }
                }
            }

            if (!matchedBuffer) {
                std::cerr << "No matching buffer found for binding address " << std::hex << bindingAddress << std::dec 
                        << " for Code buffer at index " << n << ". Skipping.\n";
                return -1;
            }

            if (bindingOffset < codeBuffer->size) {
                codeBuffer->data[bindingOffset / 4] = static_cast<char>(matchedBuffer->iova);
                std::cout << "Patched Code buffer at index " << n << " at offset " << bindingOffset / 4 
                        << " with iova " << matchedBuffer->iova << std::endl;
            } else {
                std::cerr << "Error: Offset " << bindingOffset << " is out of bounds for Code buffer at index " << n << ".\n";
                return -1;
            }
        }
        return 0;
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

class Command {
public:
    struct SubCmd {
        unsigned int iova;
    };

    std::vector<SubCmd> subcmds;

    Command(const Pattern& pattern) {
        auto codeBuffers = pattern.getCodeBuffers();
        for (const auto& buffer : codeBuffers) {
            SubCmd cmd;
            cmd.iova = buffer->iova;
            subcmds.push_back(cmd);
        }
    }

    void listSubCmds() const {
        for (const auto& cmd : subcmds) {
            std::cout << "SubCmd iova: " << std::hex << cmd.iova << std::dec << std::endl;
        }
    }
};

void parseFile(const std::string& filename, Pattern& pattern) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return;
    }

    std::string line;
    std::regex header_regex(R"(^// ([A-Za-z]+)@([0-9a-fA-F]+) \\{([0-9]+)\\})");
    std::regex binding_regex(R"(^// (\d+)@(0[xX]?[0-9a-fA-F]+)$)");
    std::regex data_regex(R"(^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$)");

    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_match(line, match, header_regex)) {
            std::string type = match[1];
            unsigned int address = std::stoul(match[2], nullptr, 16);
            unsigned int size = std::stoul(match[3]);
            pattern.addBuffer(type, address, size);
        } else if (std::regex_match(line, match, binding_regex)) {
            unsigned int offset = std::stoul(match[1]);
            unsigned int address = std::stoul(match[2], nullptr, 16);
            pattern.addBinding(offset, address);
        } else if (std::regex_match(line, match, data_regex)) {
            std::vector<char> data(16);
            for (int i = 0; i < 4; ++i) {
                unsigned int value = std::stoul(match[i + 1], nullptr, 16);
                std::memcpy(&data[i * 4], &value, 4);
            }

            Buffer* current_buffer = pattern.getCurrentBuffer();
            if (current_buffer) {
                for (char value : data)
                    current_buffer->addData(value);
            }
        }
    }
}

void parseGoldenFile(const std::string& filename, Pattern& pattern) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << std::endl;
        return;
    }

    std::string line;
    std::regex header_regex(R"(^// Output@([0-9a-fA-F]+) \\{([0-9]+)\\})");
    std::regex data_regex(R"(^([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})_([0-9a-fA-F]{8})$)");

    unsigned int current_address = 0;

    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_match(line, match, header_regex)) {
            current_address = std::stoul(match[1], nullptr, 16);
            unsigned int size = std::stoul(match[2]);
            pattern.addGoldenBuffers(current_address, size);
        } else if (std::regex_match(line, match, data_regex)) {
            std::vector<char> data(16);
            for (int i = 0; i < 4; ++i) {
                unsigned int value = std::stoul(match[i + 1], nullptr, 16);
                std::memcpy(&data[i * 4], &value, 4);
            }

            auto [golden, golden_mask] = pattern.getGoldenBuffersByAddress(current_address);
            if (golden) {
                for (char value : data)
                    golden->addData(value);
            }
            if (golden_mask) {
                for (char value : data)
                    golden_mask->addData(value);
            }
        }
    }
}

int main() {
    Pattern pattern;

    parseFile("0.hex", pattern);
    parseGoldenFile("cmodel_output.hex", pattern);
    pattern.listAllBuffers();

    pattern.allocateDeviceAddresses();
    pattern.patchingAllCodeBuffers();
    std::cout << "\nCode Buffers:" << std::endl;
    for (const auto& buffer : pattern.getCodeBuffers()) {
        std::cout << "Type: " << buffer->type 
                  << ", iova: " << std::hex << buffer->iova 
                  << ", Size: " << std::dec << buffer->size 
                  << std::endl;
    }

    Command command(pattern);
    command.listSubCmds();

    return 0;
}
