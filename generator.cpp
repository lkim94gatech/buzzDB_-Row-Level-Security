#include <fstream>
#include <iostream>
#include <random>

int main() {
    std::ofstream outFile("output.txt");
    if (!outFile.is_open()) {
        std::cout << "Cannot open output.txt\n";
        return 1;
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1, 10);
    
    for(int i = 0; i < 1000; i++) {
        outFile << dis(gen) << " " << (dis(gen) * 100) << "\n";
    }
    
    outFile.close();
    std::cout << "Generated test data successfully\n";
    return 0;
}