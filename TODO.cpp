#include <iostream>
#include <thread>
#include <vector>
#include <future>
#include <chrono>

// 假设 APUSYS_Command 提供的 API
namespace APUSYS_Command {
    void createSession() {
        // 创建会话的实现
        std::cout << "Session created.\n";
    }

    void bindCommand(const Command& command) {
        // 绑定命令的实现
        std::cout << "Command bound.\n";
    }

    void setParameters() {
        // 设置参数的实现
        std::cout << "Parameters set.\n";
    }

    void runCommand() {
        // 运行命令的实现
        std::cout << "Command running...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2)); // 模拟运行时间
        std::cout << "Command completed.\n";
    }
}

void allocateDeviceAddressesThread(Pattern& pattern) {
    pattern.allocateDeviceAddresses();
}

void runCommandThread(const Command& command) {
    APUSYS_Command::createSession();
    APUSYS_Command::bindCommand(command);
    APUSYS_Command::setParameters();
    APUSYS_Command::runCommand();
}

void postProcessingThread(Pattern& pattern) {
    pattern.getGoldenBuffersFromOutputs();
}

int main() {
    // 1. Create class Pattern
    Pattern pattern;

    // 2. Parsing 0.hex to fill code_buffers, data_buffers, and bindings
    parseFile("0.hex", pattern);

    // 3. Parsing cmodel_output.hex to fill golden_buffers
    parseGoldenFile("cmodel_output.hex", pattern);

    // 4. Use class Pattern to generate class Command
    Command command(pattern);

    // 5. Create thread to allocate device addresses in the pattern
    std::thread allocationThread(allocateDeviceAddressesThread, std::ref(pattern));
    allocationThread.join(); // Ensure allocation is done before proceeding

    // 6. In the thread, use APUSYS_Command API to create session, bind command, and set parameters
    std::thread commandThread(runCommandThread, std::cref(command));
    commandThread.join(); // Ensure command execution is done before proceeding

    // 7. Create post-processing thread to compare output data with golden data asynchronously
    std::future<void> postProcessingFuture = std::async(std::launch::async, postProcessingThread, std::ref(pattern));

    // 8. Wait for post-processing to complete
    postProcessingFuture.get();

    // All threads are joined and completed
    std::cout << "All threads completed.\n";

    return 0;
}
